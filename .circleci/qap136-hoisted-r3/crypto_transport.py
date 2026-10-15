"""AES-256-GCM task transport, derived from the prior native ARM transport helper."""
import hashlib,io,json,os,stat,tarfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def seal(source,destination,key,aad):
    source=Path(source);destination=Path(destination);assert len(key)==32 and not destination.exists()
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w:gz')as t:
        for p in sorted(source.rglob('*')):
            assert not p.is_symlink() and not(p.stat().st_mode&0o6000)
            if p.is_file():t.add(p,arcname='payload/'+str(p.relative_to(source)),recursive=False)
    nonce=os.urandom(12);destination.write_bytes(nonce+AESGCM(key).encrypt(nonce,buf.getvalue(),aad))
    return {'SHA256':hashlib.sha256(destination.read_bytes()).hexdigest(),'bytes':destination.stat().st_size}

def open_safe(source,destination,key,aad,max_bytes=256*1024**2):
    data=Path(source).read_bytes();assert len(key)==32 and len(data)>28
    plain=AESGCM(key).decrypt(data[:12],data[12:],aad);assert len(plain)<=max_bytes
    dest=Path(destination);assert not dest.exists()
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz')as t:
        members=t.getmembers();names=set();total=0
        for m in members:
            p=Path(m.name);assert not p.is_absolute()and'..'not in p.parts and p.parts[0]=='payload'
            assert m.name not in names and m.isfile()and not(m.mode&0o6000);names.add(m.name);total+=m.size
        assert total<=max_bytes and len(members)<=20000
        dest.mkdir(mode=0o700,parents=True)
        t.extractall(dest,members=members,filter='data')
    return {'files':len(members),'uncompressed_regular_bytes':total}
