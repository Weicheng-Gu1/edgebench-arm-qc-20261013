"""Public fixture-free encrypted ARM transport. No auth tokens in child environments."""
from pathlib import Path,PurePosixPath
import os,json,hashlib,hmac,subprocess,tarfile,tempfile,traceback,platform
ENVKEY='BRAINWALL_ARM_QC_20261016_ROOT_V1';AAD=b'edgebench-brainwall-native-arm-20261016-root-v1'
M=json.loads(Path('ci/brainwall-arm-transport.json').read_text());password=os.environ.pop(ENVKEY);assert len(password)>=40
PUBLIC=Path('circle-artifact');PUBLIC.mkdir(exist_ok=False);P=Path(tempfile.mkdtemp(prefix='brainwall-arm-private-'));P.chmod(0o700)
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def key(purpose):return hashlib.pbkdf2_hmac('sha256',password.encode(),AAD+b'/'+purpose,200000,32)
def openssl(src,dst,decrypt=False):
 env={'PATH':'/usr/bin:/bin','BRAINWALL_PRIVATE_TRANSPORT_PASSWORD':password}
 argv=['openssl','enc']+(['-d']if decrypt else[])+['-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-pass','env:BRAINWALL_PRIVATE_TRANSPORT_PASSWORD','-in',str(src),'-out',str(dst)]
 subprocess.run(argv,env=env,capture_output=True,check=True,timeout=60);dst.chmod(0o600)
status=1
try:
 assert M['schema']=='brainwall-native-arm-encrypted-v2' and M['source_tree_sha256']=='a997aaa16e0ca21e9c8ad75bc65ea7bb63d1357eb8728f3f2b18c7d63642793f'
 assert platform.machine()=='aarch64' and os.uname().sysname=='Linux'
 cipher=Path('ci/brainwall-arm-payload.enc');assert H(cipher)==M['cipher_sha256'];assert hmac.compare_digest(hmac.new(key(b'payload'),cipher.read_bytes(),hashlib.sha256).hexdigest(),M['cipher_hmac_sha256'])
 plain=P/'payload.tar.gz';openssl(cipher,plain,True);assert H(plain)==M['plaintext_sha256']
 with tarfile.open(plain)as z:
  members=z.getmembers();assert len(members)<2000 and sum(x.size for x in members)<64*1024**2;seen=set()
  for x in members:
   p=PurePosixPath(x.name);assert x.isfile()and not p.is_absolute()and'..'not in p.parts and x.size<16*1024**2 and str(p)not in seen;seen.add(str(p))
   d=P.joinpath(*p.parts);d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(z.extractfile(x).read());d.chmod(x.mode&0o777)
 assert H(P/'run-native-ARM-controls.py')==M['runner_sha256']
 env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':os.environ['HOME'],'LANG':'C.UTF-8'}
 with(P/'runner.stdout').open('wb')as out,(P/'runner.stderr').open('wb')as err:q=subprocess.run(['/usr/bin/python3','-I','-B',str(P/'run-native-ARM-controls.py'),'--root',str(P)],env=env,stdout=out,stderr=err,timeout=3300)
 status=q.returncode
except BaseException:
 (P/'bootstrap-error.txt').write_text(traceback.format_exc())
finally:
 details=P/'private-details.tar.gz'
 with tarfile.open(details,'w:gz')as z:
  for name in ['evidence','runner.stdout','runner.stderr','bootstrap-error.txt']:
   p=P/name
   if p.exists():z.add(p,arcname=name,recursive=True)
 dst=PUBLIC/'brainwall-native-arm-private-details.tar.gz.enc';openssl(details,dst)
 summary={'passed':status==0,'exit_code':status,'architecture':platform.machine(),'source_tree_sha256':M['source_tree_sha256'],'encrypted_details_sha256':H(dst),'encrypted_details_hmac_sha256':hmac.new(key(b'details'),dst.read_bytes(),hashlib.sha256).hexdigest(),'new_models':0,'new_SDK':0,'scope':'Native ARM Docker rebuild/direct controls only; no native Harbor/cloud/model-growth admission'}
 (PUBLIC/'report.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
raise SystemExit(status)


