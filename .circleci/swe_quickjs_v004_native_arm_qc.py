"""CI host runner. Payload and detailed results encrypted; no task data in logs."""
from pathlib import Path
import datetime,hashlib,json,os,platform,shutil,subprocess,tarfile,tempfile,time,urllib.request
assert platform.machine()=='aarch64','This job requires native ARM64 hardware'
root=Path('/tmp/swe-quickjs-v004-native-arm-qc-r2');root.mkdir(mode=0o700);public=Path('/tmp/swe-quickjs-v004-native-arm-public-r2');public.mkdir();key=root/'transport-key';key.write_text(os.environ['SWE_QUICKJS_V4_QC_KEY_R1']);key.chmod(0o600)
def run(argv,log,**kw):
 with(root/log).open('wb')as f:p=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=kw.pop('timeout',1800),**kw)
 assert p.returncode==0,'Command failed; details are in encrypted artifacts: '+log
 return p
report={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':False,'actual_native_host_machine':platform.machine(),'actual_native_host_CPUs':os.cpu_count(),'job_url':os.environ.get('CIRCLE_BUILD_URL'),'revision':os.environ.get('CIRCLE_SHA1'),'scope':'Actual frozen QuickJS task grader Docker source build, full teacher conformance, private-path isolation and native partial grading','model_calls':0}
try:
 encrypted=root/'payload.enc'
 with urllib.request.urlopen(os.environ['SWE_QUICKJS_V4_QC_PAYLOAD_URL_R1'],timeout=120)as src,encrypted.open('wb')as dst:shutil.copyfileobj(src,dst)
 assert hashlib.sha256(encrypted.read_bytes()).hexdigest()==os.environ['SWE_QUICKJS_V4_QC_PAYLOAD_SHA256_R1']
 run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-md','sha256','-in',str(encrypted),'-out',str(root/'payload.tar.gz'),'-pass','file:'+str(key)],'decrypt.log',timeout=120)
 with tarfile.open(root/'payload.tar.gz')as t:t.extractall(root/'payload',filter='data')
 payload=root/'payload';task=payload/'task';manifest=json.loads((payload/'manifest.json').read_text());actual={str(p.relative_to(task)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(task.rglob('*'))if p.is_file()and'__pycache__'not in p.parts};assert actual==manifest['task_hashes'];report['frozen_task_hashes_verified']=True
 image='swe-quickjs-v004-native-arm-qc:20261015-r1';run(['docker','build','--platform','linux/arm64','--network=none','-t',image,str(task/'verifier')],'actual-grader-build.log',timeout=2400)
 info=json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0];assert info['Architecture']=='arm64';report['actual_grader_image_architecture']=info['Architecture'];report['actual_grader_image_id']=info['Id']
 check="import os,json;assert os.geteuid()==65534;print(json.dumps({p:os.access(p,os.R_OK)for p in ['/opt/swe-reference-source/adapter/main.cpp','/opt/swe-reference/reference','/tests/private/corpus.json']}))"
 privacy=json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--read-only','--user','65534:65534','--entrypoint','/usr/bin/python3',image,'-c',check],text=True));assert not any(privacy.values());report['actual_nonroot_private_paths_readable']=privacy
 common=['docker','run','--rm','--platform','linux/arm64','--network','none','--cpus','4','--memory','16g','--memory-swap','16g','--read-only','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=4g']
 # Trusted-reference preflight covers every frozen functional and throughput row,
 # using the same isolation and per-process limits as the actual grader.
 compat=root/'teacher-conformance.py';compat.write_text('''import sys,json,tempfile,pathlib,hashlib
sys.path.insert(0,'/tests')
from operation_grader import assess
from sandbox import execute
corpus=json.load(open('/tests/private/corpus.json'));count=0;rows=0
with tempfile.TemporaryDirectory(prefix='trusted-preflight-',dir='/tmp')as td:
 root=pathlib.Path(td);root.chmod(0o755)
 for row in corpus['correctness']+corpus['performance']:
  raw,m=execute(pathlib.Path('/tests/private/reference'),json.dumps(row['request'],separators=(',',':')).encode(),root,25)
  fraction,ok=assess(raw,row,'quickjs')
  assert m['status']=='completed'and ok,'Frozen teacher conformance failure'
  count+=len(row['request']['cases']);rows+=1
pathlib.Path('/logs/verifier/conformance.json').write_text(json.dumps({'passed':True,'functional_operations':sum(len(r['request']['cases'])for r in corpus['correctness']),'all_functional_and_performance_operations':count,'all_requests':rows}))
''')
 logs=root/'teacher-conformance';logs.mkdir(mode=0o700)
 run(common+['-v',str(compat)+':/trusted-conformance.py:ro','-v',str(logs)+':/logs/verifier:rw','--entrypoint','/usr/bin/python3',image,'/trusted-conformance.py'],'teacher-conformance.log',timeout=1800);report['actual_teacher_conformance']=json.loads((logs/'conformance.json').read_text())
 grades={}
 for name in ['partial-a','partial-b','empty']:
  folder=root/name;folder.mkdir(mode=0o700);source=payload/name;source.mkdir(exist_ok=True)
  run(common+['-v',str(source)+':/home/workspace/swe-quickjs-engine/submission:ro','-v',str(folder)+':/logs/verifier:rw','--entrypoint','/bin/sh',image,'/tests/test.sh'],name+'.log',timeout=1800)
  score=json.loads((folder/'score.json').read_text());assert score['valid']is True
  if name=='empty':assert score['score']==0 and score['submission_sha256']=={}
  else:assert 0<score['score']<1 and 0<score['pass_rate']<1 and score['build']['status']=='compiled'
  native=float((folder/'reward.txt').read_text());assert native==score['score'];grades[name]={'score':native,'correctness':score['metrics']['correctness'],'performance':score['metrics']['performance'],'submission_sha256':score['submission_sha256'],'native_reward_parity':True}
 report.update(passed=True,actual_grades=grades)
finally:
 report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();(root/'public-report.json').write_text(json.dumps(report,indent=2));(public/'report.json').write_text(json.dumps(report,indent=2))
 # Exclude transport key and downloads from archived details. Task source and
 # grading reports may contain hidden fixtures; encrypt all detailed artifacts.
 archive=root/'results.tar.gz'
 with tarfile.open(archive,'w:gz')as t:
  for p in root.iterdir():
   if p.name not in ['transport-key','payload.enc','payload.tar.gz','results.tar.gz','payload']:t.add(p,arcname=p.name)
 run(['openssl','enc','-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-in',str(archive),'-out',str(public/'details.enc'),'-pass','file:'+str(key)],'encrypt-results.log',timeout=120)
 key.unlink(missing_ok=True)
 print(json.dumps({'passed':report['passed'],'host_machine':report['actual_native_host_machine'],'job_url':report['job_url']}))
