"""Prepare new ARM-only source revision after actual own role builds; never edit AMD D/F/T."""
from pathlib import Path
import argparse,ast,hashlib,json,os,re,shutil,subprocess,difflib
p=argparse.ArgumentParser();p.add_argument('--source-bridge',type=Path,required=True);p.add_argument('--images',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();src=a.source_bridge.resolve(strict=True);out=a.output.resolve();assert not out.exists();assert os.geteuid()==0 and set(range(4))<=os.sched_getaffinity(0)
HERE=Path(__file__).resolve().parent;H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();meta=json.loads((HERE/'ACTUAL-SOURCE-SET-SHA256-r1.json').read_text());wanted=meta['bridge-framework']['files'];assert len(wanted)==533
omit={n:v for n,v in wanted.items()if n.startswith('public-native-audit/bin/')or n.startswith('public-native-audit/lib/')or(n.startswith('public-CA-dependencies/')and n.endswith('.deb'))};assert len(omit)==0
actual={str(q.relative_to(src/'framework'))for q in(src/'framework').rglob('*')if q.is_file()};assert actual in [set(wanted),set(wanted)-set(omit)]
assert not any(q.is_symlink()for q in(src/'framework').rglob('*'))
for n in actual:
 q=src/'framework'/n;v=wanted[n];assert H(q)==v['SHA256']and q.stat().st_size==v['bytes']and(q.stat().st_mode&0o7777)==v['mode']
images=json.loads(a.images.read_text());assert set(images)=={'agent','verifier'};ids={}
for role,v in images.items():
 image=v['image_id'];assert re.fullmatch(r'sha256:[0-9a-f]{64}',image);r=subprocess.run(['docker','image','inspect',image],capture_output=True,text=True,check=True,timeout=30);i=json.loads(r.stdout)[0];assert i['Id']==image and i['Architecture']=='arm64'and i['Os']=='linux';ids[role]=image
assert len(set(ids.values()))==2
# Actual F533 already contains source/license/hash metadata only; no optional binary bodies are present.
omit={n:v for n,v in wanted.items()if n.startswith('public-native-audit/bin/')or n.startswith('public-native-audit/lib/')or(n.startswith('public-CA-dependencies/')and n.endswith('.deb'))};assert len(omit)==0
out.mkdir();fw=out/'framework';fw.mkdir()
for n,v in wanted.items():
 if n in omit:continue
 d=fw/n;d.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src/'framework'/n,d)
for n in ['package_eval.py','score_snapshot.py','setup_public.py','check_legal_namespace.py','original-task-source-SHA256.json']:
 shutil.copy2(src/n,out/n)
shutil.copytree(src/'dependencies',out/'dependencies');lock=HERE/'arm64-public-host-wheel-metadata-r1';shutil.copy2(lock/'public-wheel-lock-arm64.json',out/'dependencies/public-wheel-lock-arm64.json');shutil.copy2(lock/'requirements-arm64-hashed.txt',out/'dependencies/requirements-arm64-hashed.txt')
changes={}
def edit(rel,transform):
 q=out/rel;old=q.read_text();new=transform(old);assert old!=new;ast.parse(new);q.write_text(new);changes[rel]={'before_SHA256':hashlib.sha256(old.encode()).hexdigest(),'after_SHA256':H(q),'diff':''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=rel+'-AMD',tofile=rel+'-ARM'))}
def policy(s):
 for key,role in [('AGENT','agent'),('VERIFIER','verifier')]:s,count=re.subn(r"^"+key+r"='sha256:[0-9a-f]{64}'$",key+'='+repr(ids[role]),s,flags=re.M);assert count==1
 return s
def cpu(s):
 old="args+=['--cpuset-cpus','12-15']";assert s.count(old)==1;return s.replace(old,"args+=['--cpuset-cpus','0-3']")
def setup(s):
 assert s.count('public-wheel-lock-amd64.json')==1 and s.count('requirements-amd64-hashed.txt')==1;return s.replace('public-wheel-lock-amd64.json','public-wheel-lock-arm64.json').replace('requirements-amd64-hashed.txt','requirements-arm64-hashed.txt')
edit('framework/qap_programless_policy.py',policy);edit('framework/edgebench_harbor/docker_runtime.py',cpu);edit('setup_public.py',setup)
assert H(fw/'harbor/agents/installed/codex.py')=='ee0ca8ec43617f3909d2195afe8f9e7cbd7313a8b3b558b01fde388f65b7c39c'
manifest={str(q.relative_to(out)):{'SHA256':H(q),'bytes':q.stat().st_size,'mode':q.stat().st_mode&0o7777}for q in sorted(out.rglob('*'))if q.is_file()};(out/'CURRENT-ARM-DEPLOYMENT-AMENDMENT.json').write_text(json.dumps({'status':'new_independent_ARM_deployment_source_only_not_scored_or_admitted','actual_ARM_image_ids':ids,'AMD_F533_and_T272_original_bytes_untouched':True,'only_functional_changes':changes,'optional_payload_omissions_with_hashes':omit,'original_scoring_B_F_inputs_candidate_resource_and_namespace_policy_unchanged':True,'licenses_and_hash_metadata_retained':True,'actual_ARM_footprint_original_shape_report_and_BIND_still_required':True,'manifest':manifest},indent=2)+'\n');print(json.dumps({'prepared':str(out),'actual_ARM_image_ids':ids,'changed_code':list(changes),'omitted_optional_payloads':len(omit),'not_scored_or_bound':True}))
