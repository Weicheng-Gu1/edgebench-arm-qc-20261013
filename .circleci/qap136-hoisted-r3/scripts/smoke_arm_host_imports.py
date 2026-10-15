"""Prepared read-only root/cwd host closure proof for new ARM bridge; no resource launch."""
from pathlib import Path
import argparse,hashlib,importlib.metadata as meta,inspect,json,os,sys
p=argparse.ArgumentParser();p.add_argument('--bridge',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();ROOT=a.bridge.resolve(strict=True);os.environ['EDGEBENCH_DEPLOYMENT_CONFIG']=str(ROOT/'work/binding.json');os.environ['HARBOR_TELEMETRY']='0';sys.dont_write_bytecode=True;sys.path[:0]=[str(ROOT/'framework'),str(ROOT/'framework/sdk')]
from edgebench_harbor.docker_runtime import EdgeBenchDockerEnvironment,DockerScorer
from edgebench_harbor.docker_verifier import DockerNativeVerifier
from edgebench_harbor.docker_storage import verified_readonly_footprint
from harbor.verifier.verifier import Verifier
from harbor.agents.installed.codex import Codex
from harbor.models.task.task import Task
from qap_programless_policy import validate,IMAGES,VERIFIER,TOTAL,SHM,DEV,CONTROL
H=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();assert H(inspect.getsourcefile(Codex))=='ee0ca8ec43617f3909d2195afe8f9e7cbd7313a8b3b558b01fde388f65b7c39c';assert H(inspect.getsourcefile(Verifier))=='6d3d9ed8882c5e07bae4aa6449732b096166fb9bbabc685b39c0e25f57b20aa9';task=Task(ROOT/'work/task');cfg=task.config.verifier.environment;assert validate(VERIFIER,'no-network',cfg)['namespace_SYS_ADMIN'];rows=[]
for role in ['agent','verifier']:
 image=json.loads((ROOT/'evidence/readonly'/role/'image-inspect.json').read_text())[0];r=verified_readonly_footprint(ROOT/'framework',image,image['Id']);w=TOTAL-r['readonly_budget_bound_bytes']-SHM-CONTROL-DEV;assert w>0 and w%4096==0;rows.append({'role':role,'readonly_bound':r['readonly_budget_bound_bytes'],'writable_ext4_bytes':w,'protected_control':CONTROL,'shm':SHM,'dev':DEV,'total':TOTAL,'guest_allocation_not_yet_executed':True})
rejects=0
for image,mode,c in [('sha256:'+'0'*64,'no-network',cfg),(VERIFIER,'allowlist',cfg),(VERIFIER,'no-network',cfg.model_copy(update={'storage_mb':15360}))]:
 try:validate(image,mode,c)
 except ValueError:rejects+=1
 else:raise AssertionError('Policy negative accepted')
assert rejects==3;a.output.write_text(json.dumps({'passed':True,'actual_cwd':str(Path.cwd()),'actual_python':sys.executable,'actual_Harbor_distribution':meta.version('harbor'),'official_Codex_SHA256':H(inspect.getsourcefile(Codex)),'official_Verifier_SHA256':H(inspect.getsourcefile(Verifier)),'DockerScorer_source':inspect.getsourcefile(DockerScorer),'DockerNativeVerifier_source':inspect.getsourcefile(DockerNativeVerifier),'policy_negative_rejections':rejects,'budget_plans':rows,'new_containers_grades_models':0},indent=2)+'\n');print(json.dumps({'passed':True,'output':str(a.output)}))
