"""Run the unchanged p2 native controls; publish only encrypted detailed evidence."""
from pathlib import Path, PurePosixPath
import os, json, base64, hashlib, platform, subprocess, tarfile, time, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path.cwd()
OUT = Path('/tmp/halite-p2-public-evidence')
OUT.mkdir()
assert platform.machine() == 'aarch64'
key = base64.b64decode(os.environ['HALITE_P2_ARM_KEY_20261015T115319Z'], validate=True)
cipher = (ROOT / 'halite-p2-input.enc').read_bytes()
assert hashlib.sha256(cipher).hexdigest() == 'e391466327cddda257c99c9a7cf0b4e2d4201675458dab07eb0b1f0edefeadc0'
plain = AESGCM(key).decrypt(cipher[:12], cipher[12:], b'halite-p2-arm-input-v1')
assert hashlib.sha256(plain).hexdigest() == 'bf4028881e0449ab98a931b26183a5b4918434386d84c71a524da036552edd14'
private = ROOT / 'halite-private-run'
private.mkdir(mode=0o700)
archive = private / 'input.tar.gz'
archive.write_bytes(plain)
with tarfile.open(archive) as tf:
    members = tf.getmembers()
    assert sum(m.size for m in members) < 512 * 1024**2
    for m in members:
        p = PurePosixPath(m.name)
        assert not p.is_absolute() and '..' not in p.parts and (m.isfile() or m.isdir())
        assert p.parts[0] in ('input', 'native-controls.py')
    tf.extractall(private, filter='data')
control = private / 'native-controls.py'
assert hashlib.sha256(control.read_bytes()).hexdigest() == '2a4befd1e8afe3be1feebf68abc0a0bb6e43beaa6db8ec2fca64612700362957'
docker_arch = subprocess.check_output(['docker', 'info', '--format', '{{.Architecture}}'], text=True).strip()
assert docker_arch in ('aarch64', 'arm64')
started = time.monotonic()
with (private / 'controls-console.log').open('wb') as log:
    p = subprocess.Popen([sys.executable, '-B', str(control)], cwd=private, stdout=log, stderr=subprocess.STDOUT)
    while p.poll() is None:
        print(json.dumps({'stage': 'unchanged_native_controls_running', 'elapsed_sec': round(time.monotonic() - started, 1)}), flush=True)
        time.sleep(20)
report_path = private / 'native-evidence/report.json'
report = json.loads(report_path.read_text()) if report_path.exists() else {}
success = p.returncode == 0 and report.get('passed') and report.get('complete')
if success:
    assert report['native_machine'] == 'aarch64'
    assert report['native_rebuild']['rebuilt_machine'] == 183
    assert report['native_rebuild']['original_machine'] == 62
    for role in ('work', 'judge'):
        image = json.loads((private / f'native-evidence/{role}-image.json').read_text())
        assert len(image) == 1 and image[0]['Architecture'] == 'arm64'
    assert len(report['rows']) == 5 and all(r['passed'] for r in report['rows'])
    assert {r['name'] for r in report['rows']} == {'nop', 'reference', 'trace-1', 'trace-2', 'trace-3'}
details = private / 'detailed-evidence.tar.gz'
with tarfile.open(details, 'w:gz') as tf:
    evidence = private / 'native-evidence'
    if evidence.exists():
        tf.add(evidence, arcname='native-evidence')
    tf.add(private / 'controls-console.log', arcname='controls-console.log')
nonce = os.urandom(12)
encrypted = nonce + AESGCM(key).encrypt(nonce, details.read_bytes(), b'halite-p2-arm-evidence-v1')
(OUT / 'details.enc').write_bytes(encrypted)
summary = {
    'passed': bool(success), 'control_exit_code': p.returncode,
    'host_architecture': platform.machine(), 'docker_server_architecture': docker_arch,
    'scoring_revision': 'halite3-resource-odds-p2-w0.5-v1',
    'input_archive_sha256': hashlib.sha256(plain).hexdigest(),
    'control_sha256': hashlib.sha256(control.read_bytes()).hexdigest(),
    'original_strategy_source_modified': False, 'new_model_runs': 0,
    'rows': [{k: r[k] for k in ('name', 'score', 'raw_score', 'passed', 'same_score_as_original', 'score_delta_from_expected_normalized_x86')} for r in report.get('rows', [])],
    'encrypted_details_sha256': hashlib.sha256(encrypted).hexdigest(),
}
(OUT / 'summary.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary), flush=True)
raise SystemExit(0 if success else 1)
