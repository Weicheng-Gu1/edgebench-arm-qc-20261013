"""Public transport only. No task data, credentials, or result private key."""
import argparse, base64, hashlib, io, json, os, tarfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

AAD = b'edgebench-sealed-control-v1'

def extract_verified(blob, key, out):
    assert blob[:8] == b'EBPAY001'
    plain = AESGCM(key).decrypt(blob[8:20], blob[20:], AAD)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz') as tf:
        members = tf.getmembers()
        for m in members:
            p = Path(m.name)
            assert not p.is_absolute() and '..' not in p.parts and m.isfile()
        tf.extractall(out, members=members)
    manifest = json.loads((out/'payload-manifest.json').read_text())
    actual = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in out.rglob('*') if p.is_file() and p.name != 'payload-manifest.json'}
    assert actual == manifest['files']
    assert set(manifest['file_modes']) == set(actual)
    assert all(type(mode) is int and 0 <= mode <= 0o777 and (out/name).stat().st_mode & 0o7777 == mode for name,mode in manifest['file_modes'].items())
    directories = manifest.get('directories', {})
    assert isinstance(directories, dict)
    for name, meta in sorted(directories.items(), key=lambda item: (len(Path(item[0]).parts), item[0])):
        rel = Path(name)
        assert isinstance(name, str) and name and not rel.is_absolute() and '..' not in rel.parts and rel.as_posix() == name and name != '.'
        assert isinstance(meta, dict) and type(meta['mode']) is int and 0 <= meta['mode'] <= 0o777 and type(meta['empty']) is bool
        target = out/rel
        assert not target.is_symlink()
        target.mkdir(parents=True, exist_ok=True)
        assert target.is_dir()
        target.chmod(meta['mode'])
    assert {p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_dir()} == set(directories)
    assert all((not any((out/name).iterdir())) == meta['empty'] for name,meta in directories.items())
    return manifest

def seal_results(root, recipient, output):
    # Recipient PRIVATE key remains on the developer host, never in CircleCI.
    key, nonce = AESGCM.generate_key(256), os.urandom(12)
    public = serialization.load_pem_public_key(recipient.read_bytes())
    assert public.key_size >= 3072
    wrapped = public.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                              algorithm=hashes.SHA256(), label=AAD))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for p in sorted(root.rglob('*')):
            if p.is_symlink(): raise ValueError('result symlinks forbidden')
            if p.is_file(): tf.add(p, arcname=str(p.relative_to(root)), recursive=False)
    body = AESGCM(key).encrypt(nonce, buf.getvalue(), AAD)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix('.tmp')
    tmp.write_bytes(b'EBRES001' + len(wrapped).to_bytes(4,'big') + wrapped + nonce + body)
    tmp.replace(output)

def main():
    ap=argparse.ArgumentParser(); sp=ap.add_subparsers(dest='op',required=True)
    a=sp.add_parser('open'); a.add_argument('blob',type=Path); a.add_argument('out',type=Path)
    a=sp.add_parser('seal'); a.add_argument('root',type=Path); a.add_argument('recipient',type=Path); a.add_argument('output',type=Path)
    args=ap.parse_args()
    if args.op=='open':
        key=base64.b64decode(os.environ.pop('EB_PAYLOAD_KEY_B64'),validate=True)
        assert len(key)==32
        extract_verified(args.blob.read_bytes(),key,args.out)
    else: seal_results(args.root,args.recipient,args.output)

if __name__=='__main__': main()
