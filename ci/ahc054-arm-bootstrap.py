"""Fixture-free authenticated transport; parent invokes publication only after review."""
from pathlib import Path,PurePosixPath
import os,json,hashlib,hmac,subprocess,tarfile,tempfile,traceback,platform
ENVKEY='AHC054_FORMAL_ARM_QC_20261016_C1';AAD=b'edgebench-ahc054-formal-native-arm-20261016-c1';OWNER='ahc054-formal-native-arm-20261016-c1'
M=json.loads(Path('ci/ahc054-arm-transport.json').read_text());password=os.environ.pop(ENVKEY);assert len(password)>=40
PUBLIC=Path('circle-artifact');PUBLIC.mkdir(exist_ok=False);P=Path(tempfile.mkdtemp(prefix='ahc054-formal-arm-private-'));P.chmod(0o700);H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def key(purpose):return hashlib.pbkdf2_hmac('sha256',password.encode(),AAD+b'/'+purpose,200000,32)
def crypt(src,dst,decrypt=False):
 env={'PATH':'/usr/bin:/bin','PRIVATE_TRANSPORT_PASSWORD':password};argv=['openssl','enc']+(['-d']if decrypt else[])+['-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-pass','env:PRIVATE_TRANSPORT_PASSWORD','-in',str(src),'-out',str(dst)];subprocess.run(argv,env=env,capture_output=True,check=True,timeout=60);dst.chmod(0o600)
status=1;clean={'owner':OWNER,'new_API_requests':0}
try:
 assert M['schema']=='ahc054-formal-native-arm-encrypted-v1'and M['source_tree_sha256']=='f209d3dfd6c8ceca1c834a41a06904c873867e4ca6ad1fdc1b75ccb21e73fecb';assert platform.machine()=='aarch64'and os.uname().sysname=='Linux'
 cipher=Path('ci/ahc054-arm-payload.enc');assert H(cipher)==M['cipher_sha256'];assert hmac.compare_digest(hmac.new(key(b'payload'),cipher.read_bytes(),hashlib.sha256).hexdigest(),M['cipher_hmac_sha256']);plain=P/'payload.tar.gz';crypt(cipher,plain,True);assert H(plain)==M['plaintext_sha256']
 with tarfile.open(plain)as z:
  members=z.getmembers();assert len(members)<=1500 and sum(x.size for x in members)<64*1024**2;seen=set()
  for x in members:
   p=PurePosixPath(x.name);assert x.isfile()and not p.is_absolute()and'..'not in p.parts and'\\'not in x.name and':'not in x.name and x.size<16*1024**2 and str(p)not in seen;seen.add(str(p));d=P.joinpath(*p.parts);d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(z.extractfile(x).read());d.chmod(x.mode&0o777)
 assert H(P/'run-native-ARM-controls.py')==M['runner_sha256'];env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':os.environ['HOME'],'LANG':'C.UTF-8'}
 with(P/'runner.stdout').open('wb')as out,(P/'runner.stderr').open('wb')as err:q=subprocess.run(['/usr/bin/python3','-I','-B',str(P/'run-native-ARM-controls.py'),'--root',str(P)],env=env,stdout=out,stderr=err,timeout=5400)
 status=q.returncode
except BaseException:(P/'bootstrap-error.txt').write_text(traceback.format_exc())
finally:
 # Only this owner's exact labels may be cleaned, including outer deadline failures.
 try:
  env={'PATH':'/usr/bin:/bin','HOME':str(P),'LANG':'C.UTF-8'};q=subprocess.run(['docker','ps','-aq','--filter','label=edgebench.owner='+OWNER],env=env,capture_output=True,text=True,check=True,timeout=30);rows=[]
  for cid in q.stdout.split():
   x=json.loads(subprocess.check_output(['docker','inspect',cid],env=env,timeout=30))[0];assert(x['Config'].get('Labels')or{}).get('edgebench.owner')==OWNER;subprocess.run(['docker','rm','-f',cid],env=env,capture_output=True,check=True,timeout=30);rows.append(cid)
  q=subprocess.run(['docker','ps','-aq','--filter','label=edgebench.owner='+OWNER],env=env,capture_output=True,text=True,check=True,timeout=30);clean.update(removed_only_exact_owner=rows,surviving=q.stdout.split());assert not clean['surviving']
 except BaseException:clean.update(error_type='owned_cleanup_failed');status=1
 e=P/'evidence';e.mkdir(exist_ok=True);(e/'bootstrap-own-container-cleanup.json').write_text(json.dumps(clean,indent=2))
 details=P/'private-details.tar.gz'
 with tarfile.open(details,'w:gz')as z:
  for name in ['evidence','runner.stdout','runner.stderr','bootstrap-error.txt']:
   p=P/name
   if p.exists():z.add(p,arcname=name,recursive=True)
 dst=PUBLIC/'ahc054-formal-native-arm-private-details.tar.gz.enc';crypt(details,dst);summary={'passed':status==0,'exit_code':status,'architecture':platform.machine(),'source_tree_sha256':M['source_tree_sha256'],'encrypted_details_sha256':H(dst),'encrypted_details_hmac_sha256':hmac.new(key(b'details'),dst.read_bytes(),hashlib.sha256).hexdigest(),'new_models':0,'new_SDK':0,'scope':'Native ARM Docker source rebuild, native reward CLI plus periodic report CLI and C++ guard controls. Not provider CloudScorer SDK/native Harbor/framework/model growth acceptance.'};(PUBLIC/'report.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
raise SystemExit(status)
