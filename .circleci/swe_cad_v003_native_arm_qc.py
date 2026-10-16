"""Native ARM reference study. Hidden requests and detailed results stay encrypted."""
from pathlib import Path
import datetime,hashlib,json,os,platform,shutil,subprocess,tarfile,urllib.request
assert platform.machine()=='aarch64'
root=Path('/tmp/swe-cad-integral-probe-private-r1');root.mkdir(mode=0o700)
public=Path('/tmp/swe-cad-integral-probe-public-r1');public.mkdir()
key=root/'transport-key';key.write_text(os.environ['SWE_CAD_V3_QC_KEY_R1']);key.chmod(0o600)
def run(argv,log,timeout=1800):
    with (root/log).open('wb') as f:p=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
    assert p.returncode==0,'Inspect encrypted diagnostics for '+log
report={'scope':'Trusted reference integral convergence only; not frozen task grading',
        'passed':False,'model_calls':0,'full_delivery_pass':False,
        'actual_native_host_machine':platform.machine(),'actual_native_host_CPUs':os.cpu_count(),
        'job_url':os.environ.get('CIRCLE_BUILD_URL'),'revision':os.environ.get('CIRCLE_SHA1'),
        'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
try:
    encrypted=root/'payload.enc'
    with urllib.request.urlopen(os.environ['SWE_CAD_V3_QC_PAYLOAD_URL_R1'],timeout=120) as src,encrypted.open('wb') as dst:shutil.copyfileobj(src,dst)
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest()==os.environ['SWE_CAD_V3_QC_PAYLOAD_SHA256_R1']
    run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-md','sha256','-in',str(encrypted),'-out',str(root/'payload.tar.gz'),'-pass','file:'+str(key)],'decrypt.log',120)
    with tarfile.open(root/'payload.tar.gz') as t:t.extractall(root/'payload',filter='data')
    payload=root/'payload';task=payload/'task'
    manifest=json.loads((payload/'manifest.json').read_text())
    original={str(p.relative_to(task)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(task.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
    assert original==manifest['task_hashes'];report['original_payload_hashes_verified']=True
    # An explicitly separate scratch context contains the changed trusted observer.
    context=root/'probe-context';shutil.copytree(task/'verifier',context)
    probe=Path('.circleci/cad_integral_probe.cpp')
    destination=context/'tests/reference-source/adapter/reference.cpp'
    destination.write_bytes(probe.read_bytes())
    report['probe_source_sha256']=hashlib.sha256(probe.read_bytes()).hexdigest()
    report['frozen_task_reference_changed']=False
    report['separate_probe_context_reference_changed']=True
    image='swe-cad-integral-native-arm-probe:20261016-r1'
    run(['docker','build','--platform','linux/arm64','--network=none','-t',image,str(context)],'probe-source-build.log',2400)
    info=json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
    assert info['Architecture']=='arm64'
    report['actual_probe_image_architecture']=info['Architecture'];report['actual_probe_image_id']=info['Id']
    logs=root/'integral-convergence';logs.mkdir(mode=0o700)
    driver=Path('.circleci/cad_integral_probe.py').resolve()
    run(['docker','run','--rm','--platform','linux/arm64','--network','none','--cpus','4','--memory','16g','--memory-swap','16g','--read-only','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=4g',
        '-v',str(driver)+':/trusted-integral-probe.py:ro','-v',str(logs)+':/logs/verifier:rw',
        '--entrypoint','/usr/bin/python3',image,'/trusted-integral-probe.py'],'actual-integral-probe.log',1800)
    actual=json.loads((logs/'report.json').read_text())
    assert actual['passed'] and actual['all_case_count']==32
    report.update(passed=True,actual_case_count=actual['all_case_count'],full_frozen_task_grade_claimed=False)
finally:
    report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    (root/'public-report.json').write_text(json.dumps(report,indent=2));(public/'report.json').write_text(json.dumps(report,indent=2))
    archive=root/'results.tar.gz'
    with tarfile.open(archive,'w:gz') as t:
        for p in root.iterdir():
            if p.name not in ['transport-key','payload.enc','payload.tar.gz','results.tar.gz','payload','probe-context']:t.add(p,arcname=p.name)
    run(['openssl','enc','-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-in',str(archive),'-out',str(public/'details.enc'),'-pass','file:'+str(key)],'encrypt-results.log',120)
    key.unlink(missing_ok=True)
    print(json.dumps({'passed':report['passed'],'scope':report['scope'],'job_url':report['job_url']}))
assert report['passed']
