"""Authenticated encryption for task fixtures and native validation evidence."""
import argparse, hashlib, io, os, tarfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['encrypt','decrypt']);p.add_argument('source',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()
    key=bytes.fromhex(os.environ.pop('EDGEBENCH_TRANSPORT_KEY'))
    if a.mode=='encrypt':
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz',dereference=True) as t:t.add(a.source,arcname='payload')
        nonce=os.urandom(12);a.destination.write_bytes(nonce+AESGCM(key).encrypt(nonce,buf.getvalue(),b'edgebench-native-arm-v1'))
    else:
        data=a.source.read_bytes()
        with tarfile.open(fileobj=io.BytesIO(AESGCM(key).decrypt(data[:12],data[12:],b'edgebench-native-arm-v1')),mode='r:gz') as t:
            members=t.getmembers()
            for m in members:
                if Path(m.name).is_absolute() or '..' in Path(m.name).parts or m.issym() or m.islnk() or not(m.isdir() or m.isfile()):raise ValueError('unsafe archive member')
            a.destination.mkdir(parents=True,exist_ok=False);t.extractall(a.destination,members=members,filter='data')
    print('transport_complete',hashlib.sha256(a.source.read_bytes()).hexdigest() if a.source.is_file() else 'directory')

if __name__=='__main__':main()
