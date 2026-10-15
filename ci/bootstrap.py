from pathlib import Path
import hashlib,json,os,subprocess,tarfile,traceback,signal
os.umask(0o022)
ROOT=Path('/ci');ROOT.mkdir(exist_ok=True);O=ROOT/'artifact';O.mkdir(exist_ok=True)
M=json.loads(Path('ci/transport.json').read_text());H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();status=1
def run_owned(command,filename,timeout):
 p=subprocess.Popen(command,stdout=(O/(filename+'.stdout')).open('w'),stderr=(O/(filename+'.stderr')).open('w'),start_new_session=True)
 try:return p.wait(timeout=timeout)
 except subprocess.TimeoutExpired:
  os.killpg(p.pid,signal.SIGKILL);p.wait();raise
try:
 c=ROOT/'payload.enc'
 with c.open('wb')as f:
  for row in M['chunks']:
   p=Path('ci')/row['name'];assert H(p)==row['sha256'];f.write(p.read_bytes())
 assert H(c)==M['encrypted_sha256'];plain=ROOT/'payload.tar.gz'
 subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(c),'-out',str(plain)],check=True,capture_output=True)
 assert H(plain)==M['plaintext_sha256']
 with tarfile.open(plain)as z:
  for m in z.getmembers():assert m.isfile()and not Path(m.name).is_absolute()and'..'not in Path(m.name).parts
  z.extractall(ROOT,filter='data')
 assert os.uname().machine=='aarch64';os.environ.update(EXPECTED_ARCH='arm64',DMC_OWN_CI_ROOT='/ci',GITHUB_RUN_ID=os.environ['CIRCLE_BUILD_NUM'])
 assert run_owned(['python3','/ci/source/get-dependencies.py'],'dependencies',900)==0
 assert run_owned(['python3','/ci/source/assemble-task-v2.py'],'restoration',180)==0
 subprocess.run(['docker','pull','--platform','linux/arm64','ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'],stdout=(O/'base-pull.stdout').open('w'),stderr=(O/'base-pull.stderr').open('w'),check=True,timeout=240)
 status=run_owned(['python3','/ci/source/run-controlled-ARM.py'],'driver',2100)
except BaseException:
 (O/'bootstrap-traceback.txt').write_text(traceback.format_exc())
finally:
 # On failure remove only this job's exact original control prefix, never another job's resources.
 if status:
  prefix='dmc-source-v6-arm-'+os.environ.get('CIRCLE_BUILD_NUM','IMPOSSIBLE')+'-';cleanup=[]
  for kind,args in [('container',['docker','ps','-a','--format','{{.Names}}']),('image',['docker','image','ls','--format','{{.Repository}}:{{.Tag}}'])]:
   p=subprocess.run(args,capture_output=True,text=True,timeout=20)
   for name in p.stdout.splitlines():
    if name.startswith(prefix):
     q=subprocess.run(['docker',kind,'rm','-f',name],capture_output=True,text=True,timeout=30);cleanup.append({'kind':kind,'name':name,'returncode':q.returncode})
  (O/'failure-owned-prefix-cleanup.json').write_text(json.dumps(cleanup))
 artifact=Path('circle-artifact');artifact.mkdir(exist_ok=True);raw=ROOT/'details.tar.gz'
 with tarfile.open(raw,'w:gz')as z:z.add(O,arcname='artifact')
 subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(raw),'-out',str(artifact/'details.tar.gz.enc')],check=True,capture_output=True)
 report={'passed':status==0,'exit_code':status,'host_architecture':os.uname().machine,'task_files':904,'models_started':0,'task_version':'source-build-descriptor-v6','encrypted_details_sha256':H(artifact/'details.tar.gz.enc'),'scope':'Current original DMC task native ARM Docker source builds and full32 controls only; no model growth/final delivery claim'}
 (artifact/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
raise SystemExit(status)
