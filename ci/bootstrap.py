from pathlib import Path
import hashlib,json,os,subprocess,tarfile,traceback
os.umask(0o022)
ROOT=Path('/ci'); ROOT.mkdir(exist_ok=True); O=ROOT/'artifact';O.mkdir(exist_ok=True)
M=json.loads(Path('ci/transport.json').read_text()); H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
status=1
try:
 c=ROOT/'payload.enc'
 with c.open('wb')as f:
  for row in M['chunks']:
   p=Path('ci')/row['name'];assert H(p)==row['sha256'];f.write(p.read_bytes())
 assert H(c)==M['encrypted_sha256']
 plain=ROOT/'payload.tar.gz'
 subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(c),'-out',str(plain)],check=True,capture_output=True)
 assert H(plain)==M['plaintext_sha256']
 with tarfile.open(plain)as z:
  for m in z.getmembers():assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
  z.extractall(ROOT,filter='data')
 I=json.loads((ROOT/'source/inputs.json').read_text());T=ROOT/'frozen-task';T.mkdir()
 for n,v in I['task_hashes'].items():
  assert not Path(n).is_absolute() and '..'not in Path(n).parts
  src=ROOT/'content'/v;assert H(src)==v
  p=T/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(src.read_bytes());p.chmod(int(I['file_modes'][n],8))
 assert len([p for p in T.rglob('*')if p.is_file()])==86
 (O/'actual-restored-source-binding.json').write_text(json.dumps({'passed':True,'physical_files':86,'task_hashes':I['task_hashes'],'file_modes_verified':all((T/n).stat().st_mode&511==int(v,8)for n,v in I['file_modes'].items()),'transport':'SHA-bound encrypted content-addressed bundle; no task edits'}))
 patch=Path('ci/native-control-v2.enc');assert H(patch)=='ab7ac8390dfb7e59c6275c0e537662577647d5dc4b45beeacb0d6324ecfd7998'
 control=ROOT/'source/run-controlled-native-ARM.py';assert H(control)=='0ecd1c244f3741dabb758252ccc9bb56e83ac2cd590d7de0025cd34e8db520ba'
 subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(patch),'-out',str(control)],check=True,capture_output=True)
 assert H(control)=='1e3cd21c49d3477d4ad6a86f26f979e4fed4683737f20d7a429b73506e9ae38a'
 (O/'actual-CI-control-only-invocation-fix.json').write_text(json.dumps({'task_files_unchanged':86,'old_driver_sha256':'0ecd1c244f3741dabb758252ccc9bb56e83ac2cd590d7de0025cd34e8db520ba','new_driver_sha256':'1e3cd21c49d3477d4ad6a86f26f979e4fed4683737f20d7a429b73506e9ae38a','fix':'Use declared Bash for both entry points; trusted launcher clears shell startup hooks before interpreter; frozen task/scorer unchanged'}))
 assert os.uname().machine=='aarch64'
 subprocess.run(['docker','pull','--platform','linux/arm64','ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'],stdout=(O/'base-pull.stdout').open('w'),stderr=(O/'base-pull.stderr').open('w'),check=True,timeout=300)
 os.environ.update(EXPECTED_ARCH='arm64',RAILWAY_OWN_CI_ROOT='/ci',GITHUB_RUN_ID=os.environ.get('CIRCLE_BUILD_NUM','circle'))
 q=subprocess.run(['python3','/ci/source/run-controlled-native-ARM.py'],stdout=(O/'driver.stdout').open('w'),stderr=(O/'driver.stderr').open('w'),timeout=2000)
 status=q.returncode
except BaseException:
 (O/'bootstrap-traceback.txt').write_text(traceback.format_exc())
finally:
 cleanup=[]
 try:
  terminal=O/'actual-current-native-role-controls-terminal.json'
  if terminal.exists():
   evidence=json.loads(terminal.read_text())
   for v in evidence.get('images_retained_for_explicit_followup',{}).values():
    tag=v['tag'];assert tag.startswith('edgebench-cityplan-v7-')
    q=subprocess.run(['docker','image','rm','-f',tag],capture_output=True,text=True,timeout=60)
    r=subprocess.run(['docker','image','inspect',tag],capture_output=True,text=True,timeout=30)
    cleanup.append({'tag':tag,'original_id':v['Id'],'remove_exit':q.returncode,'actual_tag_absent':r.returncode==1})
   (O/'actual-owned-images-cleanup.json').write_text(json.dumps(cleanup,indent=2))
 except BaseException:
  (O/'cleanup-traceback.txt').write_text(traceback.format_exc());status=1
 artifact=Path('circle-artifact');artifact.mkdir(exist_ok=True)
 raw=ROOT/'details.tar.gz'
 with tarfile.open(raw,'w:gz')as z:z.add(O,arcname='artifact')
 subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(raw),'-out',str(artifact/'details.tar.gz.enc')],check=True,capture_output=True)
 report={'passed':status==0,'exit_code':status,'host_architecture':os.uname().machine,'task_files':86,'models_started':0,'task_version':'native-cloud-v7','encrypted_details_sha256':H(artifact/'details.tar.gz.enc'),'scope':'Actual CityPlan2018 original86 native ARM Docker controls; no model growth or final delivery acceptance implied'}
 (artifact/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
raise SystemExit(status)
