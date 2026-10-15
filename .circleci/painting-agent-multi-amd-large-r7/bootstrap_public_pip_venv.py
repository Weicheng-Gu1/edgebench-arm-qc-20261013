"""Explicit host deployment only: stdlib venv without ensurepip + one exact public pip wheel."""
import argparse,base64,csv,hashlib,io,json,os,subprocess,sys,urllib.parse,urllib.request,zipfile
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--python312',type=Path,required=True);p.add_argument('--venv',type=Path,required=True)
    p.add_argument('--lock',type=Path,required=True);p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert not a.venv.exists()and not a.output.exists();lock=json.loads(a.lock.read_text());assert lock['kind']=='edgebench-public-host-pip-bootstrap-v1'and lock['package']=='pip'and lock['version']=='24.0'
    assert lock['wheel']=='pip-24.0-py3-none-any.whl'and urllib.parse.urlparse(lock['url']).hostname=='files.pythonhosted.org'
    a.cache.mkdir(parents=True,exist_ok=True);wheel=a.cache/lock['wheel']
    if not wheel.exists():
        with urllib.request.urlopen(lock['url'],timeout=90)as response:data=response.read(lock['bytes']+1)
        assert len(data)==lock['bytes']and hashlib.sha256(data).hexdigest()==lock['SHA256'];wheel.write_bytes(data)
    assert wheel.stat().st_size==lock['bytes']and hashlib.sha256(wheel.read_bytes()).hexdigest()==lock['SHA256']
    # Explicitly no ensurepip, apt, global installation, package resolution or upgrade.
    commands=[]
    def run(argv):
        r=subprocess.run([str(x)for x in argv],capture_output=True,text=True,timeout=180);commands.append({'argv':[str(x)for x in argv],'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0;return r.stdout
    version=run([a.python312,'-I','-c','import sys,ssl,venv,json;assert sys.version_info[:2]==(3,12);print(json.dumps({"version":list(sys.version_info[:3]),"executable":sys.executable,"OpenSSL":ssl.OPENSSL_VERSION}))'])
    run([a.python312,'-I','-c','import sys,venv;venv.create(sys.argv[1],with_pip=False)',a.venv])
    python=a.venv/'bin/python';pure=Path(run([python,'-I','-c','import sysconfig;print(sysconfig.get_path("purelib"))']).strip());assert pure.resolve().is_relative_to(a.venv.resolve())
    assert not(pure/'pip').exists();pure.mkdir(parents=True,exist_ok=True);files={}
    with zipfile.ZipFile(wheel)as z:
        names=z.namelist();assert len(names)==len(set(names));record='pip-24.0.dist-info/RECORD';records={r[0]:r[1:]for r in csv.reader(io.StringIO(z.read(record).decode()))}
        for info in z.infolist():
            n=Path(info.filename);assert not n.is_absolute()and'..'not in n.parts and n.parts[0]in ['pip','pip-24.0.dist-info']and(info.external_attr>>16)&0o170000!=0o120000
            if info.is_dir():continue
            data=z.read(info.filename);digest,size=records[info.filename]
            if info.filename!=record:assert digest=='sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')and int(size)==len(data)
            target=pure/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);target.chmod(0o644);files[str(n)]={'SHA256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    pipversion=run([python,'-I','-m','pip','--version']);assert 'pip 24.0 'in pipversion;run([python,'-I','-m','pip','check'])
    a.output.write_text(json.dumps({'passed':True,'kind':'actual_public_pip_clean_venv_bootstrap_no_ensurepip','interpreter':json.loads(version),'pip_version_output':pipversion.strip(),'exact_public_lock_SHA256':hashlib.sha256(a.lock.read_bytes()).hexdigest(),'wheel_SHA256':lock['SHA256'],'wheel_bytes':lock['bytes'],'stdlib_venv_with_pip':False,'all_wheel_RECORD_member_hashes_checked':True,'actual_pip_member_count':len(files),'actual_pip_file_manifest':files,'commands':commands,'global_python_modified':False,'original95SDK_lock_modified':False,'full95_SDK_install_or_ARM_or_grading_claimed':False,'models':0},indent=2)+'\n');print(json.dumps({'actual_clean_venv_public_pip':True,'version':'24.0','ensurepip_used':False}))
if __name__=='__main__':main()
