"""Public generic CI bootstrap. Encrypted task bytes and role controls stay private."""
from pathlib import Path
import json,hashlib,os,subprocess,tarfile,traceback,shutil,concurrent.futures,urllib.request,time,signal
ROOT=Path('/ci');ROOT.mkdir(exist_ok=True);O=ROOT/'artifact';O.mkdir(exist_ok=True);H=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();M=json.loads(Path('ci/transport.json').read_text());status=1;os.umask(0o022)
def terminate_owned_check(signum,frame):
 raise SystemExit(128+signum)
signal.signal(signal.SIGTERM,terminate_owned_check)
def safe_tar(z):
 names=set()
 for m in z.getmembers():
  p=Path(m.name);assert m.isfile()and not p.is_absolute()and'..'not in p.parts and'\\'not in m.name and m.name not in names;names.add(m.name)
 return z
try:
 cipher=ROOT/'payload.enc'
 with cipher.open('wb')as out:
  for r in M['chunks']:
   p=Path('ci')/r['name'];assert H(p)==r['sha256']and p.stat().st_size==r['bytes'];out.write(p.read_bytes())
 assert H(cipher)==M['encrypted_sha256'];plain=ROOT/'payload.tar.gz';subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(cipher),'-out',str(plain)],check=True,capture_output=True);assert H(plain)==M['plaintext_sha256']
 with tarfile.open(plain)as z:safe_tar(z).extractall(ROOT,filter='data')
 I=json.loads((ROOT/'source/inputs.json').read_text());assert H(ROOT/'source/inputs.json')==M['source_inputs_SHA256'];assert I['actual_physical_files']==859
 private=ROOT/'source/private-task-content.tar.gz';assert H(private)==I['private_content_archive_SHA256']
 with tarfile.open(private)as z:safe_tar(z).extractall(ROOT,filter='data')
 C=ROOT/'content';receipts=[]
 def fetch(row):
  digest,r=row;p=C/digest;assert not p.exists();last=None
  for attempt in range(3):
   try:
    with urllib.request.urlopen(r['url'],timeout=180)as source,p.open('wb')as out:shutil.copyfileobj(source,out,1024**2)
    assert H(p)==digest,'EXACT_DEPENDENCY_SHA_MISMATCH';return {'SHA256':digest,'filename':r['filename'],'official_URL':r['url'],'bytes':p.stat().st_size,'actual_downloaded_now':True}
   except Exception as e:last=type(e).__name__
  raise RuntimeError('Fixed public asset download incomplete: '+r['filename']+' '+str(last))
 with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:receipts=list(pool.map(fetch,I['fetched_public_assets'].items()))
 (O/'actual-public-dependency-acquisition.json').write_text(json.dumps({'passed':True,'network_fetched_exact_assets':len(receipts),'rows':receipts,'no_version_or_url_substitutions':True},indent=2));T=ROOT/'frozen-task';T.mkdir();modes={}
 for name,r in I['files'].items():
  p=Path(name);assert not p.is_absolute()and'..'not in p.parts and'\\'not in name;src=C/r['SHA256'];assert H(src)==r['SHA256']and src.stat().st_size==r['bytes'];dst=T/p;dst.parent.mkdir(parents=True,exist_ok=True);key=(r['SHA256'],r['mode'])
  if key not in modes:variant=ROOT/('materialized-'+r['SHA256']+'-'+str(r['mode']));shutil.copyfile(src,variant);variant.chmod(r['mode']);modes[key]=variant
  os.link(modes[key],dst)
 assert len([p for p in T.rglob('*')if p.is_file()])==859
 assert all(H(T/n)==r['SHA256']and (T/n).stat().st_mode&511==r['mode']for n,r in I['files'].items());binding={'passed':True,'files':859,'actual_task_hashes':{n:H(T/n)for n in I['files']},'expected_task_hashes':I['task_hashes'],'POSIX_modes_verified':True,'restoration_no_source_edits':True};assert binding['actual_task_hashes']==binding['expected_task_hashes'];(O/'actual-restored859-source-binding.json').write_text(json.dumps(binding,indent=2));assert os.uname().machine=='aarch64'
 subprocess.run(['docker','pull','--platform','linux/arm64','ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'],stdout=(O/'actual-base-pull.stdout').open('w'),stderr=(O/'actual-base-pull.stderr').open('w'),check=True,timeout=300)
 with(O/'actual-driver.stdout').open('w')as out,(O/'actual-driver.stderr').open('w')as err:q=subprocess.run(['python3','-B',str(ROOT/'source/native-controls.py'),'--task',str(T),'--output',str(O/'controls'),'--arch','arm64'],stdout=out,stderr=err,stdin=subprocess.DEVNULL,timeout=9000)
 status=q.returncode
except BaseException:(O/'bootstrap-traceback.txt').write_text(traceback.format_exc())
finally:
 if status:
  job=os.environ.get('CIRCLE_BUILD_NUM','IMPOSSIBLE');prefix='ytli-luxs3-v10-arm64-'+job+'-';q=subprocess.run(['docker','ps','-a','--filter','label=edgebench.owner=ytli','--filter','label=edgebench.native_arm_run='+job,'--format','{{.Names}}'],capture_output=True,text=True,timeout=30);actions=[]
  for name in q.stdout.splitlines():
   if name.startswith(prefix):r=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=60);actions.append({'name':name,'actual_exit':r.returncode})
  (O/'failure-only-owned-native-prefix-cleanup.json').write_text(json.dumps(actions,indent=2))
 raw=ROOT/'details.tar.gz'
 with tarfile.open(raw,'w:gz')as z:z.add(O,arcname='artifact')
 A=Path('circle-artifact');A.mkdir(exist_ok=True);out=A/'details.tar.gz.enc';subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(raw),'-out',str(out)],check=True,capture_output=True);report={'passed':status==0,'actual_control_exit':status,'host_architecture':os.uname().machine,'task_files':859,'models_started':0,'encrypted_details_SHA256':H(out),'scope':'Native ARM Docker role source builds, actual eight original games and legal reference/failure controls. Not GPT growth or final task delivery.'};(A/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
raise SystemExit(status)
