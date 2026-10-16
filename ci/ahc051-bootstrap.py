from pathlib import Path
import json,hashlib,subprocess,os,tarfile,traceback
ROOT=Path('/ci');ROOT.mkdir(exist_ok=True);O=ROOT/'artifact';O.mkdir(exist_ok=True)
M=json.loads(Path('ci/ahc051-transport.json').read_text());H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();status=1
try:
 assert os.uname().machine=='aarch64'
 enc=ROOT/'base-cache.enc'
 with enc.open('wb')as f:
  for row in M['base']['chunks']:
   p=Path('ci')/row['name'];assert H(p)==row['sha256'];f.write(p.read_bytes())
 assert H(enc)==M['base']['encrypted_sha256']
 base=ROOT/'base-cache.tar.gz';subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(enc),'-out',str(base)],check=True,capture_output=True)
 assert H(base)==M['base']['plaintext_sha256'];B=ROOT/'reused-base-cache';B.mkdir()
 with tarfile.open(base)as z:
  for m in z.getmembers():assert m.isfile()and not Path(m.name).is_absolute()and '..'not in Path(m.name).parts
  z.extractall(B,filter='data')
 p=Path('ci/ahc051-new-source.enc');assert H(p)==M['new_cipher_SHA256'];small=ROOT/'new-source.tar.gz';subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(p),'-out',str(small)],check=True,capture_output=True);assert H(small)==M['new_plain_SHA256']
 with tarfile.open(small)as z:
  for m in z.getmembers():assert m.isfile()and not Path(m.name).is_absolute()and '..'not in Path(m.name).parts
  z.extractall(ROOT,filter='data')
 I=json.loads((ROOT/'source/inputs.json').read_text());T=ROOT/'frozen-task';T.mkdir();cache_used=[]
 assert I['task_files']==len(I['task_hashes'])==143
 for n,v in I['task_hashes'].items():
  assert not Path(n).is_absolute()and '..'not in Path(n).parts
  p=ROOT/'content'/v
  if not p.exists():assert v in I['reused_OS_cache_content_SHA256'];p=B/'content'/v;cache_used.append(v)
  assert H(p)==v;q=T/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes());q.chmod(int(I['file_modes'][n],8))
 assert len([p for p in T.rglob('*')if p.is_file()])==143
 assert all(H(T/n)==v and (T/n).stat().st_mode&511==int(I['file_modes'][n],8)for n,v in I['task_hashes'].items())
 (O/'actual-exact143-restored-source-binding.json').write_text(json.dumps({'passed':True,'files':143,'task_hashes':I['task_hashes'],'task_tree_SHA256':I['tree_SHA256'],'all_modes_verified':True,'reused_unchanged_OS_caches':sorted(set(cache_used))},indent=2))
 subprocess.run(['docker','pull','--platform','linux/arm64','ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'],stdout=(O/'base-pull.stdout').open('w'),stderr=(O/'base-pull.stderr').open('w'),check=True,timeout=300)
 q=subprocess.run(['python3','-B','/ci/source/run-native-ARM-controls.py'],stdout=(O/'driver.stdout').open('w'),stderr=(O/'driver.stderr').open('w'),timeout=2000);status=q.returncode
 if status==0:
  report=json.loads((O/'native-controls/report.json').read_text());assert report['passed']and report['reference_five_exact']and report['original_task_unchanged'];assert all(x['architecture']=='arm64'for x in report['images'].values())
except BaseException:
 status=1;(O/'bootstrap-traceback.txt').write_text(traceback.format_exc())
finally:
 destination=Path('circle-artifact');destination.mkdir(exist_ok=True);raw=ROOT/'details.tar.gz'
 with tarfile.open(raw,'w:gz')as z:z.add(O,arcname='artifact')
 subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','env:'+M['key_env'],'-in',str(raw),'-out',str(destination/'details.tar.gz.enc')],check=True,capture_output=True)
 report={'passed':status==0,'exit_code':status,'host_architecture':os.uname().machine,'task_files':143,'task_version':'independent-fixed-layout-v1','models_started':0,'encrypted_details_SHA256':H(destination/'details.tar.gz.enc'),'scope':'Actual native ARM64 offline Docker/static-layout controls; not model growth or final delivery acceptance'};(destination/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
raise SystemExit(status)
