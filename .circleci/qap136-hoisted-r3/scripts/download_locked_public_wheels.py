"""Stdlib-only wheel bootstrap; no install, credentials, package resolution or fallback."""
import argparse, concurrent.futures, hashlib, json, urllib.parse, urllib.request
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--lock',type=Path,required=True)
    p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert not a.output.exists();lock=json.loads(a.lock.read_text())
    assert lock['count']==len(lock['files'])==95;a.cache.mkdir(parents=True,exist_ok=True)
    def get(row):
        assert Path(row['wheel']).name==row['wheel']
        assert urllib.parse.urlparse(row['url']).hostname=='files.pythonhosted.org'
        dest=a.cache/row['wheel']
        if not dest.exists():
            with urllib.request.urlopen(row['url'],timeout=90)as response:data=response.read(row['size']+1)
            assert len(data)==row['size'] and hashlib.sha256(data).hexdigest()==row['sha256']
            dest.write_bytes(data)
        assert dest.stat().st_size==row['size'] and hashlib.sha256(dest.read_bytes()).hexdigest()==row['sha256']
        return {'wheel':row['wheel'],'bytes':row['size'],'SHA256':row['sha256']}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:rows=list(pool.map(get,lock['files']))
    a.output.write_text(json.dumps({'passed':True,'scope':'Exact public wheel body hashes only; no ARM install/import claim','lock_SHA256':hashlib.sha256(a.lock.read_bytes()).hexdigest(),'files':rows,'bytes':sum(r['bytes']for r in rows),'model_CI_grade_requests':0},indent=2)+'\n')
    print(json.dumps({'actual_wheels':len(rows),'no_install':True}))
if __name__=='__main__':main()
