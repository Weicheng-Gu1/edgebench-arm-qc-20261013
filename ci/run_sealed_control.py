"""Prepared only: one CI builds exact two roles, probes architecture/resources, no math grading."""
from pathlib import Path
import base64,hashlib,json,os,platform,re,signal,subprocess,tempfile,threading,time,shutil
from sealed_transport import extract_verified,seal_results
ROOT=Path(__file__).resolve().parents[1];PRIVATE=Path(tempfile.mkdtemp(prefix='eb-private-two-role-build-'));PRIVATE.chmod(0o700)
PUBLIC=ROOT/'sealed-artifacts';UUID=os.environ.get('CIRCLE_WORKFLOW_JOB_ID','missing');assert re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',UUID)
HOST=Path('/tmp/edgebench-hard-proper-build-'+UUID+'.json');assert not HOST.exists()
names={role:'eb-sealed-'+UUID+'-'+role for role in ['work','judge']};tags={role:names[role].lower()+':local'for role in names}
state={'stage':'admission','status':'unknown','mathematical_score_not_computed':True};started=time.monotonic();stop=threading.Event();checkpoint_thread=None;created=[]
identity={'pid':os.getpid(),'start_ticks':Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19],'runner_source_SHA256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'runner_status':'running'}
def owned_absence(name,rmrc,rc,out,err):
 if name not in names.values()or rmrc!=0 or rc!=1:return False
 try:
  if json.loads(out)!=[]:return False
 except (ValueError,TypeError):return False
 return re.fullmatch(r'(?:error:\s*|error response from daemon:\s*)?no such (?:object|container):\s*'+re.escape(name.casefold()),err.strip().casefold())is not None
class InfrastructurePreemption(Exception):pass
def preempt(signum,frame):raise InfrastructurePreemption()
signal.signal(signal.SIGTERM,preempt)
def save():
 (PRIVATE/'control-state.json').write_text(json.dumps(state,indent=2)+'\n');tmp=HOST.with_suffix('.tmp');tmp.write_text(json.dumps(dict(identity,stage=state['stage'],status=state['status']),indent=2)+'\n');tmp.chmod(0o600);tmp.replace(HOST)
def run(cmd,name,timeout):
 with(PRIVATE/(name+'.stdout')).open('wb')as out,(PRIVATE/(name+'.stderr')).open('wb')as err:return subprocess.run(cmd,stdout=out,stderr=err,timeout=timeout,check=True,env={k:v for k,v in os.environ.items()if not k.startswith('EB_')})
def checkpoint():
 while not stop.wait(300):
  print(json.dumps({'stage':state['stage'],'elapsed_seconds':round(time.monotonic()-started)}),flush=True)
  try:save();seal_results(PRIVATE,ROOT/'ci/result-recipient.pem',PUBLIC/'checkpoint.enc')
  except Exception:pass
PROBE="""import os,platform,json,subprocess,pathlib,hashlib
r={'architecture':platform.machine(),'affinity_cpus':len(os.sched_getaffinity(0)),'cpu_max':pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'memory_max':pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip(),'memory_swap_max':pathlib.Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'tests_present':pathlib.Path('/tests/test.sh').is_file(),'image_owned_checker_present':pathlib.Path('/opt/grader-source/tests/test.sh').is_file(),'image_owned_native_components':json.loads(pathlib.Path('/opt/grader-source/tests/native-components.json').read_text())if pathlib.Path('/opt/grader-source/tests/native-components.json').is_file()else None,'toolchain_identity':json.loads(pathlib.Path('/toolchain-identity.json').read_text()),'lean_version':subprocess.check_output(['/opt/lean/bin/lean','--version'],text=True).strip(),'protected_tests_source_SHA256_map':{p.relative_to(pathlib.Path('/tests')).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()for p in pathlib.Path('/tests').rglob('*')if p.is_file()and p.suffix not in ['.native','.olean','.ilean']and p.name!='native-components.json'}if pathlib.Path('/tests').exists()else {}}
print(json.dumps(r))
"""
def main():
 global checkpoint_thread
 save();cfg=json.loads((ROOT/'ci/sealed-public-plan.json').read_text());assert cfg['ready_for_execution']is True and cfg['purpose']=='two-proper-role-native-ARM-build-only-no-grade'
 assert os.environ['CIRCLE_PROJECT_USERNAME']=='Weicheng-Gu1'and os.environ['CIRCLE_PROJECT_REPONAME']=='edgebench-arm-qc-20261013'
 assert os.environ['CIRCLE_BRANCH']==cfg['approved_branch']and os.environ['CIRCLE_SHA1']==os.environ['EB_APPROVED_REVISION']and os.environ['EB_ONE_USE_NONCE']==cfg['one_use_nonce']
 assert int(os.environ['EB_AUTHORIZED_ATTEMPT_WINDOW_SECONDS'])==cfg['attempt_window_seconds']==3600
 assert platform.machine()=='aarch64'and len(os.sched_getaffinity(0))==4
 run(['docker','info','--format','{{json .}}'],'docker-info',30);info=json.loads((PRIVATE/'docker-info.stdout').read_text());assert info['Architecture']=='aarch64'and info['OSType']=='linux'and info['NCPU']==4
 active={p.name:p.read_text()for p in Path('/proc/sys/fs/binfmt_misc').glob('*')if p.is_file()and'qemu'in p.name};assert not any('enabled'in v for v in active.values())
 state.update(host={'architecture':platform.machine(),'meminfo':Path('/proc/meminfo').read_text(),'affinity_cpus':4},docker_daemon=info,qemu_binfmt=active)
 blob=(ROOT/'sealed-payload.bin').read_bytes();assert hashlib.sha256(blob).hexdigest()==cfg['ciphertext_sha256'];key=base64.b64decode(os.environ.pop('EB_PAYLOAD_KEY_B64'),validate=True);assert len(key)==32
 state['payload_manifest']=extract_verified(blob,key,PRIVATE/'payload');del key
 for k in ['EB_ONE_USE_NONCE','EB_APPROVED_REVISION','EB_AUTHORIZED_ATTEMPT_WINDOW_SECONDS']:os.environ.pop(k,None)
 assert not any(k.startswith(('CIRCLE_TOKEN','GITHUB_TOKEN','GH_TOKEN'))for k in os.environ)
 checkpoint_thread=threading.Thread(target=checkpoint,daemon=True);checkpoint_thread.start();state['roles']=[]
 for role,context in [('work','environment'),('judge','tests')]:
  state['stage']=role+'-native-image-build';save();remaining=int(3300-(time.monotonic()-started));assert remaining>60
  run(['docker','build','--platform','linux/arm64','--progress','plain','-t',tags[role],str(PRIVATE/'payload'/context)],role+'-native-build',remaining)
  run(['docker','image','inspect',tags[role]],role+'-image-inspect',30);image=json.loads((PRIVATE/(role+'-image-inspect.stdout')).read_text())[0];assert image['Architecture']=='arm64'and image['Os']=='linux'and not image['Config'].get('Entrypoint')and image['Config']['Cmd']==['sleep','infinity']
  state['stage']=role+'-native-role-resource-probe';save()
  # Main role resource shape; no candidate/checker/Oracle is invoked.
  run(['docker','create','--name',names[role],'--network','none','--cpus','4','--memory','16384m','--memory-swap','16384m','--user','root',tags[role]],role+'-container-create',30);created.append(names[role])
  run(['docker','start',names[role]],role+'-container-start',30)
  run(['docker','exec',names[role],'/usr/bin/python3','-c',PROBE],role+'-architecture-probe',60);probe=json.loads((PRIVATE/(role+'-architecture-probe.stdout')).read_text());assert probe['architecture']=='aarch64'and probe['cpu_max']=='400000 100000'and probe['memory_max']=='17179869184'and probe['memory_swap_max']=='0'and probe['interfaces']==['lo']
  assert probe['toolchain_identity']['architecture']=='aarch64'and probe['toolchain_identity']['official_release_sha256']=='fdb974c2cdb4627e090d5d4007b913e09d13c4868720fb5594e22808b3de9e37'
  assert probe['tests_present']==(role=='judge') # Image bootstrap owns /tests before separate Harbor verification.
  assert probe['image_owned_checker_present']==(role=='judge')
  if role=='judge':
   assert probe['image_owned_native_components']['architecture']=='aarch64'
   expected={p.removeprefix('tests/tests/'):h for p,h in state['payload_manifest']['files'].items()if p.startswith('tests/tests/')and Path(p).name!='native-components.json'}
   assert probe['protected_tests_source_SHA256_map']==expected
  run(['docker','inspect',names[role]],role+'-container-inspect',30);inspected=json.loads((PRIVATE/(role+'-container-inspect.stdout')).read_text())[0];q=inspected['HostConfig'];assert q['NanoCpus']==4000000000 and q['Memory']==q['MemorySwap']==17179869184 and q['NetworkMode']=='none'
  state['roles'].append({'role':role,'image_Id':image['Id'],'image_architecture':image['Architecture'],'probe':probe,'actual_container_quota':q,'mathematical_score_not_computed':True})
 state.update(stage='complete',status='passed',both_current_proper_role_builds_and_native_probes_passed=True);save()
if __name__=='__main__':
 code=1
 try:main();code=0
 except BaseException as e:
  state.update(status='unknown',error_type=type(e).__name__,mathematical_score_not_computed=True)
  import traceback
  (PRIVATE/'private-exception.txt').write_text(traceback.format_exc())
 finally:
  stop.set()
  if checkpoint_thread is not None:checkpoint_thread.join()
  try:
   cleanup=[]
   for name in created:
    assert name in names.values();rm=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=60);q=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=30);absent=owned_absence(name,rm.returncode,q.returncode,q.stdout,q.stderr);cleanup.append({'name':name,'rm_returncode':rm.returncode,'inspect_returncode':q.returncode,'fresh_absence_confirmed':absent})
    if not absent:code=1;state['status']='cleanup_unknown'
   state['owned_container_cleanup']=cleanup;state['elapsed_seconds']=time.monotonic()-started;save();seal_results(PRIVATE,ROOT/'ci/result-recipient.pem',PUBLIC/'final.enc');identity['final_ciphertext_SHA256']=hashlib.sha256((PUBLIC/'final.enc').read_bytes()).hexdigest()
  except BaseException:code=1
  identity['runner_status']='finished';identity['process_exit_code']=code;save();print(json.dumps({'status':'passed'if code==0 else'unknown','sealed_only':True,'math_grade_not_run':True}),flush=True);shutil.rmtree(PRIVATE,ignore_errors=True)
 raise SystemExit(code)
