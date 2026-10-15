"""One source-bound native ARM public rebuild and fixed R + final three plan checks; no models."""
from pathlib import Path
import argparse,datetime,hashlib,json,os,platform,subprocess,sys,time,uuid,shutil
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
J=lambda p:json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--payload',type=Path,required=True);p.add_argument('--python312',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 assert a.execute and os.geteuid()==0 and platform.machine()=='aarch64'
 os.umask(0o022)
 payload=a.payload.resolve(strict=True);release=payload/'release';out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 wanted=J(payload/'SOURCE-PAYLOAD-MANIFEST.json')['files'];actual={f.relative_to(payload).as_posix():{'SHA256':H(f),'bytes':f.stat().st_size,'mode':f.stat().st_mode&0o777} for f in payload.rglob('*') if f.is_file() and f.name!='SOURCE-PAYLOAD-MANIFEST.json'}
 assert wanted==actual and not any(f.is_symlink() for f in payload.rglob('*'))
 save(out/'actual-source-identity.json',{'all_payload_SHA_size_mode_equal':True,'members':len(actual),'manifest_SHA256':H(payload/'SOURCE-PAYLOAD-MANIFEST.json')})
 selection=J(payload/'selection.json');assert selection['status']=='ROOT_APPROVED_FINAL_BUDGET_BESTS'
 assert {x['lineage'] for x in selection['rows']}=={'first','replica2','replica3'} and len(selection['rows'])==3
 for r in selection['rows']:assert r['budget_eligible'] and 0<=r['elapsed_capture_sec']<=21600
 builder='esa-current-best-arm-'+uuid.uuid4().hex[:12];builder_container='buildx_buildkit_'+builder+'0';created=False
 cleanenv={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','HARBOR_TELEMETRY':'0','PYTHONDONTWRITEBYTECODE':'1'}
 record={'status':'running','actual_native_arch':platform.machine(),'new_models':0,'new_multiplatform_builds':0,'builds_are_native_ARM_only':True,'original_score_physics_tolerance_unchanged':True,'commands':[]}
 def run(cmd,label,timeout=600):
  start=time.monotonic()
  with (out/(label+'.stdout')).open('wb') as so,(out/(label+'.stderr')).open('wb') as se:r=subprocess.run([str(x) for x in cmd],cwd='/tmp',env=cleanenv,stdout=so,stderr=se,timeout=timeout)
  row={'argv':[str(x) for x in cmd],'cwd':'/tmp','exit':r.returncode,'wall_sec':time.monotonic()-start,'stdout_SHA256':H(out/(label+'.stdout')),'stderr_SHA256':H(out/(label+'.stderr'))};save(out/(label+'.command.json'),row);record['commands'].append(row);assert r.returncode==0,(label,r.returncode)
 try:
  controller=out/'controller';receiver=release/'public-runtime/receiver';run([a.python312,'-I','-B',receiver/'setup_controller_r2.py','--python312',a.python312,'--output',controller],'actual-clean38-controller-setup',600);vpython=controller/'venv/bin/python'
  hostproof=out/'clean-host-setup';hostproof.mkdir()
  for name in ['SETUP-RECEIPT.json','pip-bootstrap.json','install-0.stdout','install-0.stderr','install-1.stdout','install-1.stderr']:
   shutil.copy2(controller/name,hostproof/name)
  cfg=out/'buildkitd.toml';cfg.write_text('[worker.oci]\n  max-parallelism = 4\n');assert subprocess.run(['docker','buildx','inspect',builder],capture_output=True).returncode!=0
  created=True
  run(['docker','buildx','create','--name',builder,'--driver','docker-container','--driver-opt','image=moby/buildkit@sha256:a38cf64aa6415899097fac5bfcf6c07c95d5a68c67a21e3d254ba398a3c9187f','--driver-opt','memory=16g','--driver-opt','memory-swap=16g','--driver-opt','cpu-period=100000','--driver-opt','cpu-quota=400000','--driver-opt','network=host','--buildkitd-flags','--allow-insecure-entitlement network.host','--buildkitd-config',cfg,'--bootstrap'],'create-owned-builder',240)
  inspect=json.loads(subprocess.check_output(['docker','inspect',builder_container]))[0];save(out/'actual-owned-builder-inspect.json',inspect);hc=inspect['HostConfig'];assert hc['Memory']==hc['MemorySwap']==16*2**30 and hc['CpuQuota']==400000 and hc['CpuPeriod']==100000
  images={}
  for role,dirname in [('agent','environment'),('verifier','tests')]:
   context=release/'task'/dirname;tag='edgebench-esa-current-best-arm:'+role+'-'+builder[-12:]
   run(['docker','buildx','build','--builder',builder,'--platform','linux/arm64','--pull','--no-cache','--network','host','--allow','network.host','--progress','plain','--load','--metadata-file',out/(role+'-buildx-metadata.json'),'-t',tag,context],'build-'+role,2400)
   image=json.loads(subprocess.check_output(['docker','image','inspect',tag]))[0];assert image['Architecture']=='arm64';save(out/(role+'-image-inspect.json'),image);images[role]={'image_id':image['Id'],'image_tag':tag,'Dockerfile_SHA256':H(context/'Dockerfile'),'actual_build_exit':0}
  save(out/'PUBLIC-IMAGES.json',images)
  run(['docker','buildx','rm',builder],'remove-owned-builder-before-grading',180);created=False
  absent=[]
  for command in [['docker','inspect',builder_container],['docker','volume','inspect',builder_container+'_state'],['docker','buildx','inspect',builder]]:
   r=subprocess.run(command,capture_output=True,text=True,timeout=30);assert r.returncode!=0 and ('no such' in r.stderr.lower() or 'no builder' in r.stderr.lower());absent.append({'argv':command,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
  save(out/'actual-owned-builder-absence.json',{'all_absent':True,'raw':absent})
  run([vpython,'-I','-B',release/'public-runtime/scripts/measure_public_role_footprints.py','--images',out/'PUBLIC-IMAGES.json','--output',out/'actual-readonly-footprints'],'measure-RO',600)
  helper=receiver/'package_eval.py';deployment=out/'deployment'
  run([vpython,'-I','-B',helper,'prepare','--task',release/'task','--output',deployment],'relative-prepare',180)
  run([vpython,'-I','-B',helper,'bind','--deployment',deployment,'--images',out/'PUBLIC-IMAGES.json','--footprints',out/'actual-readonly-footprints/manifest.json'],'relative-bind',120)
  run([vpython,'-I','-B',receiver/'check_controller_imports_r2.py','--deployment',deployment],'realcwd-full-agent-native-Scorer-imports',90)
  reference=release/'task/solution/plans.json';assert H(reference)=='0cba559a76439be6ef2c19d8d072eaadaa75d256cfa1d19028424d4aee6297f1'
  controls=[{'label':'reference','path':reference,'expected_report':payload/'expected/reference.json'}]+[{'label':r['lineage'],'path':payload/'snapshots'/r['lineage']/'plans.json','expected_report':payload/'expected'/(r['lineage']+'.json')} for r in selection['rows']]
  rows=[]
  for item in controls:
   assert os.statvfs(out).f_bavail*os.statvfs(out).f_frsize>=64*2**30
   snapshot=out/'snapshots'/item['label'];dest=snapshot/'home/workspace/esa-keplerian-tour/submission/plans.json';dest.parent.mkdir(parents=True);dest.write_bytes(item['path'].read_bytes())
   target=out/'controls'/item['label'];target.parent.mkdir(exist_ok=True)
   run([vpython,'-I','-B',helper,'score','--deployment',deployment,'--entry','native','--snapshot',snapshot,'--output',target,'--execute'],'native-'+item['label'],600)
   raw=J(target/'actual-whole-report.json');expected=J(item['expected_report']);assert raw['valid'] is True
   def strip(x):
    if isinstance(x,dict):return {k:strip(v) for k,v in x.items() if k not in ['seconds','delta_v_m_per_s']}
    if isinstance(x,list):return [strip(v) for v in x]
    return x
   rows.append({'label':item['label'],'score':raw['score'],'expected_AMD_score':expected['score'],'source_plans_SHA256':H(item['path']),'raw_SHA256':H(target/'actual-whole-report.json'),'valid':raw['valid'],'pass_rate':raw['pass_rate'],'score_equal':raw['score']==expected['score'],'all_discrete_physics_and_completion_equal_except_float_dv':strip(raw)==strip(expected)})
   save(out/'controls-progress.json',{'actual':rows,'complete':False})
  record.update(status='completed',rows=rows,all_four_score_and_discrete_physics_equal=all(r['score_equal'] and r['all_discrete_physics_and_completion_equal_except_float_dv'] for r in rows),resource={'grading_CPUs':4,'memory_cap_bytes':16*2**30,'original_ESA_declared_storage_bytes':15*2**30,'network':'none','candidate_code_executed':False})
  save(out/'CONTROLS-SUMMARY.json',record);assert record['all_four_score_and_discrete_physics_equal'],'ARM_current_best_physics_or_score_difference_no_tolerance_change'
 except BaseException as exc:
  record.update(status='failed',exception_class=type(exc).__name__,score_on_infrastructure_failure=None)
  raise
 finally:
  if created:
   r=subprocess.run(['docker','buildx','rm',builder],capture_output=True,text=True,timeout=180);checks=[]
   for command in [['docker','inspect',builder_container],['docker','volume','inspect',builder_container+'_state']]:
    v=subprocess.run(command,capture_output=True,text=True,timeout=30);checks.append({'command':command,'exit':v.returncode,'stdout':v.stdout,'stderr':v.stderr})
   record['failure_owned_builder_cleanup']={'remove_exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'checks':checks}
  record['finished_UTC']=datetime.datetime.now(datetime.timezone.utc).isoformat();save(out/'LANE-REPORT.json',record)
if __name__=='__main__':main()
