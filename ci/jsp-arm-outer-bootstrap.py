"""Authenticated fixture-free transport. Preparation does not publish or start CI."""
from pathlib import Path,PurePosixPath
import os,json,hashlib,hmac,subprocess,tarfile,tempfile,traceback,platform,signal,time,re,shutil
ENVKEY='JSP_ARM_QC_20261017_C3';AAD=b'edgebench-jsp-native-arm-20261017-c3';OWNER='jsp-native-arm-20261017-c3'
PUBLIC=Path('circle-artifact');PUBLIC.mkdir(exist_ok=False);P=Path(tempfile.mkdtemp(prefix='jsp-private-'));P.chmod(0o700)
password=os.environ.pop(ENVKEY,None);M={};status=1;failure=None;clean={'owner':OWNER,'new_API_requests':0}
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def key(purpose):return hashlib.pbkdf2_hmac('sha256',password.encode(),AAD+b'/'+purpose,200000,32)
def crypt(src,dst,decrypt=False):
 env={'PATH':'/usr/bin:/bin','PRIVATE_TRANSPORT_PASSWORD':password};args=['openssl','enc']+(['-d']if decrypt else[])+['-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-pass','env:PRIVATE_TRANSPORT_PASSWORD','-in',str(src),'-out',str(dst)]
 subprocess.run(args,env=env,capture_output=True,check=True,timeout=60);dst.chmod(0o600)
try:
 assert isinstance(password,str)and len(password)>=40,'key unavailable'
 M=json.loads(Path('ci/jsp-arm-transport.json').read_text())
 assert M['schema']=='jsp-native-arm-encrypted-v1'and M['source_tree_sha256']=='2b7677457099042827579cda86551882c0ce3b3e30925c4a170a5cf385d4d5ea'
 assert platform.machine()=='aarch64'and os.uname().sysname=='Linux'
 cipher=Path('ci/jsp-arm-payload.enc');assert H(cipher)==M['cipher_sha256']
 assert hmac.compare_digest(hmac.new(key(b'payload'),cipher.read_bytes(),hashlib.sha256).hexdigest(),M['cipher_hmac_sha256'])
 plain=P/'payload.tar.gz';crypt(cipher,plain,True);assert H(plain)==M['plaintext_sha256']
 with tarfile.open(plain)as z:
  members=z.getmembers();assert len(members)<=1000 and sum(m.size for m in members)<128*1024**2;seen=set()
  for m in members:
   q=PurePosixPath(m.name);assert m.isfile()and not q.is_absolute()and'..'not in q.parts and'\\'not in m.name and':'not in m.name and m.size<32*1024**2 and str(q)not in seen
   seen.add(str(q));target=P.joinpath(*q.parts);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.extractfile(m).read());target.chmod(m.mode&0o777)
 manifest=json.loads((P/'payload-files.json').read_text())
 actual={p.relative_to(P).as_posix():{'bytes':p.stat().st_size,'sha256':H(p)}for p in P.rglob('*')if p.is_file()and p.name not in ['payload.tar.gz']and p!=P/'payload-files.json'}
 assert actual==manifest and H(P/'payload-files.json')==M['payload_files_manifest_sha256']
 assert H(P/'stage-bundle.tar.gz')==M['stage_bundle_sha256']
 with tarfile.open(P/'stage-bundle.tar.gz')as z:
  seen=set();total=0
  for m in z:
   q=PurePosixPath(m.name);assert not q.is_absolute()and'..'not in q.parts and'\\'not in m.name and':'not in m.name and q.parts[0]=='stage'and(m.isdir()or m.isfile());target=P.joinpath(*q.parts)
   assert m.name not in seen;seen.add(m.name);total+=m.size;assert m.size<32*1024**2 and total<128*1024**2
   if m.isdir():target.mkdir(parents=True,exist_ok=True)
   else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.extractfile(m).read());target.chmod(m.mode&0o777)
 assert H(P/'stage/manifest.json')==M['stage_manifest_sha256']and H(P/'stage/runner.py')==M['runner_sha256']and H(P/'stage/bootstrap.sh')==M['source_bootstrap_sha256']
 stage_manifest=json.loads((P/'stage/manifest.json').read_bytes());assert stage_manifest['source_tree']==M['source_tree_sha256']
 stage_actual={p.relative_to(P/'stage').as_posix():{'bytes':p.stat().st_size,'sha256':H(p)}for p in(P/'stage').rglob('*')if p.is_file()and p!=P/'stage/manifest.json'};assert stage_actual==stage_manifest['files']
 assert(P/'stage/static-fixture-preflight/NOP/submission').is_dir()and not list((P/'stage/static-fixture-preflight/NOP/submission').iterdir())
 env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':str(P),'LANG':'C.UTF-8'}
 with(P/'runner.stdout').open('wb')as out,(P/'runner.stderr').open('wb')as err:
  q=subprocess.Popen(['/usr/bin/timeout','6500','/bin/bash',str(P/'stage/bootstrap.sh'),str(P/'source-output')],env=env,stdout=out,stderr=err,start_new_session=True)
  try:status=q.wait(timeout=7000)
  except subprocess.TimeoutExpired:
   try:os.killpg(q.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   try:status=q.wait(timeout=5)
   except subprocess.TimeoutExpired:
    try:os.killpg(q.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    status=q.wait()
   status=1;(P/'runner-timeout.txt').write_text('Trusted control envelope exceeded; own process group stopped; own containers cleaned by outer finally.')
except BaseException as e:
 failure=type(e).__name__;status=1;(P/'bootstrap-error.txt').write_text(traceback.format_exc())
finally:
 try:
  env={'PATH':'/usr/bin:/bin','HOME':str(P),'LANG':'C.UTF-8'}
  # Atomic original runner report is written before any Docker call, and
  # retains PID/owner through timeout. Query exactly that owner label, not the
  # possibly incomplete commands array and never an unfiltered container list.
  rp=P/'source-output/report.json';removed=[];surviving=[]
  if rp.exists():
   identity=json.loads(rp.read_bytes());pid=identity['runner_PID'];assert type(pid)is int and pid>0;owner=identity['owner'];label=identity['owner_label_key'];assert label=='edgebench.jsp-arm.owner'and owner=='b-jsp-native-arm-runner-'+str(pid)
   q=subprocess.run(['docker','ps','-aq','--filter','label='+label+'='+owner],env=env,capture_output=True,text=True,check=True,timeout=30)
   for cid in q.stdout.split():
    item=json.loads(subprocess.check_output(['docker','inspect',cid],env=env,timeout=20))[0];assert(item['Config'].get('Labels')or{}).get(label)==owner
    assert re.fullmatch(r'/b-jsp-arm-'+str(pid)+r'-[a-zA-Z0-9_-]+',item['Name'])and re.fullmatch(r'b-jsp-arm-(work|judge):'+str(pid),item['Config']['Image'])
    subprocess.run(['docker','rm','-f',cid],env=env,capture_output=True,check=True,timeout=30);removed.append(cid)
   q=subprocess.run(['docker','ps','-aq','--filter','label='+label+'='+owner],env=env,capture_output=True,text=True,check=True,timeout=30);surviving=q.stdout.split();assert not surviving;clean.update(actual_runner_PID=pid,actual_runner_owner=owner,owner_label_key=label)
  else:clean.update(original_atomic_runner_report_absent=True,scope='Verified runner writes atomic identity before its first Docker call; no successful runner result is inferred from absence')
  clean.update(removed_only_exact_source_owner=removed,surviving=surviving,unfiltered_container_listing=False)
 except BaseException:clean['error_type']='owned_cleanup_failed';status=1
 e=P/'outer-evidence';e.mkdir(exist_ok=True);(e/'bootstrap-own-container-cleanup.json').write_text(json.dumps(clean,indent=2))
 if status==0:
  try:
   original=json.loads((P/'source-output/report.json').read_bytes());assert original['passed']is True and original['architecture']=='aarch64'and original['source_tree']==M['source_tree_sha256']and original['own_containers_all_absent']is True
  except BaseException:status=1;failure='source_bootstrap_report_not_successful'
 summary={'passed':status==0,'exit_code':status,'architecture':platform.machine(),'source_tree_sha256':M.get('source_tree_sha256'),'new_models':0,'new_SDK':0,'scope':'Native ARM exact JSP source, 42numeric+6infra host and8baked static-plan controls; public ORTools construct-only, no solve/model/SDK/Harbor trial/growth. Host Harbor venv is built externally, runtime excluded from details.'}
 if failure:summary['exception_type']=failure
 if isinstance(password,str)and len(password)>=40:
  try:
   tooling=P/'tooling-evidence';tooling.mkdir(exist_ok=True)
   for name in ['harbor-install.log','harbor-installed-freeze.txt','safe-failure.json','venv-system-dependency-install.log','actual-venv-system-packages.txt']:
    f=P/'source-output-bootstrap'/name
    if f.exists():shutil.copyfile(f,tooling/name)
   details=P/'private-details.tar.gz'
   with tarfile.open(details,'w:gz')as z:
    for name in ['source-output','tooling-evidence','outer-evidence','runner.stdout','runner.stderr','bootstrap-error.txt','runner-timeout.txt']:
     p=P/name
     if p.exists():z.add(p,arcname=name,recursive=True)
   dst=PUBLIC/'jsp-native-arm-private-details.tar.gz.enc';crypt(details,dst)
   summary.update(encrypted_details_sha256=H(dst),encrypted_details_hmac_sha256=hmac.new(key(b'details'),dst.read_bytes(),hashlib.sha256).hexdigest())
  except BaseException as e:summary.update(passed=False,exit_code=1,evidence_encryption_exception_type=type(e).__name__);status=1
 (PUBLIC/'report.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
raise SystemExit(status)
