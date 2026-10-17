"""Authenticated fixture-free transport. Preparation does not publish or start CI."""
from pathlib import Path,PurePosixPath
import os,json,hashlib,hmac,subprocess,tarfile,tempfile,traceback,platform,signal,time
ENVKEY='SLIDESHOW_ARM_QC_20261017_C1';AAD=b'edgebench-slideshow-native-arm-20261017-c1';OWNER='slideshow-native-arm-source-A-v1'
PUBLIC=Path('circle-artifact');PUBLIC.mkdir(exist_ok=False);P=Path(tempfile.mkdtemp(prefix='slideshow-private-'));P.chmod(0o700)
password=os.environ.pop(ENVKEY,None);M={};status=1;failure=None;clean={'owner':OWNER,'new_API_requests':0}
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def key(purpose):return hashlib.pbkdf2_hmac('sha256',password.encode(),AAD+b'/'+purpose,200000,32)
def crypt(src,dst,decrypt=False):
 env={'PATH':'/usr/bin:/bin','PRIVATE_TRANSPORT_PASSWORD':password};args=['openssl','enc']+(['-d']if decrypt else[])+['-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-pass','env:PRIVATE_TRANSPORT_PASSWORD','-in',str(src),'-out',str(dst)]
 subprocess.run(args,env=env,capture_output=True,check=True,timeout=60);dst.chmod(0o600)
try:
 assert isinstance(password,str)and len(password)>=40,'key unavailable'
 M=json.loads(Path('ci/slideshow-arm-transport.json').read_text())
 assert M['schema']=='slideshow-native-arm-encrypted-v1'and M['source_tree_sha256']=='a54e0ecb03e2f27ad1c5f9760fe822b54cd969244fbb5a376cdb11180913d095'
 assert platform.machine()=='aarch64'and os.uname().sysname=='Linux'
 cipher=Path('ci/slideshow-arm-payload.enc');assert H(cipher)==M['cipher_sha256']
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
 assert H(P/'preparation/PREPARATION-FILES.json')==M['preparation_manifest_sha256']
 assert H(P/'preparation/slideshow-arm-bootstrap.py')==M['source_bootstrap_sha256']
 assert H(P/'preparation/run-native-ARM-controls.py')==M['runner_sha256']
 env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':os.environ['HOME'],'LANG':'C.UTF-8'}
 with(P/'runner.stdout').open('wb')as out,(P/'runner.stderr').open('wb')as err:
  q=subprocess.Popen(['/usr/bin/python3','-I','-B',str(P/'preparation/slideshow-arm-bootstrap.py'),'--payload-root',str(P/'preparation'),'--output',str(P/'source-output'),'--execute'],env=env,stdout=out,stderr=err,start_new_session=True)
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
  q=subprocess.run(['docker','ps','-aq','--filter','label=edgebench.owner='+OWNER],env=env,capture_output=True,text=True,check=True,timeout=30);removed=[]
  for cid in q.stdout.split():
   x=json.loads(subprocess.check_output(['docker','inspect',cid],env=env,timeout=20))[0];assert(x['Config'].get('Labels')or{}).get('edgebench.owner')==OWNER
   subprocess.run(['docker','rm','-f',cid],env=env,capture_output=True,check=True,timeout=30);removed.append(cid)
  q=subprocess.run(['docker','ps','-aq','--filter','label=edgebench.owner='+OWNER],env=env,capture_output=True,text=True,check=True,timeout=30);clean.update(removed_only_exact_owner=removed,surviving=q.stdout.split());assert not clean['surviving']
 except BaseException:clean['error_type']='owned_cleanup_failed';status=1
 e=P/'outer-evidence';e.mkdir(exist_ok=True);(e/'bootstrap-own-container-cleanup.json').write_text(json.dumps(clean,indent=2))
 if status==0:
  try:
   original=json.loads((P/'source-output/bootstrap-report.json').read_bytes());assert original['passed']is True and original['architecture']=='aarch64'and original['source_tree_sha256']==M['source_tree_sha256']and original['own_cleanup']['surviving_own_ids']==[]
  except BaseException:status=1;failure='source_bootstrap_report_not_successful'
 summary={'passed':status==0,'exit_code':status,'architecture':platform.machine(),'source_tree_sha256':M.get('source_tree_sha256'),'new_models':0,'new_SDK':0,'scope':'Native ARM exact frozen Slideshow two-role source build/static plan controls only; source bootstrap retains original NOT_IMPLEMENTED transport historical scope, authenticated outer layer is separate. Not model/SDK/Harbor/growth.'}
 if failure:summary['exception_type']=failure
 if isinstance(password,str)and len(password)>=40:
  try:
   details=P/'private-details.tar.gz'
   with tarfile.open(details,'w:gz')as z:
    for name in ['source-output','outer-evidence','runner.stdout','runner.stderr','bootstrap-error.txt','runner-timeout.txt']:
     p=P/name
     if p.exists():z.add(p,arcname=name,recursive=True)
   dst=PUBLIC/'slideshow-native-arm-private-details.tar.gz.enc';crypt(details,dst)
   summary.update(encrypted_details_sha256=H(dst),encrypted_details_hmac_sha256=hmac.new(key(b'details'),dst.read_bytes(),hashlib.sha256).hexdigest())
  except BaseException as e:summary.update(passed=False,exit_code=1,evidence_encryption_exception_type=type(e).__name__);status=1
 (PUBLIC/'report.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
raise SystemExit(status)
