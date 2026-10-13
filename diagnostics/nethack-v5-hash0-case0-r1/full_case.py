"""Owner-only onecase diagnostic; original engine/policy and explicit candidate hashseed0."""
import sys,os,json,hashlib,shutil,platform
from pathlib import Path
sys.path.insert(0,'/tests')
import episode
from nethack_protocol import ObservationDecoder
OUT=Path('/logs/verifier');OUT.mkdir(parents=True,exist_ok=True);work=Path('/tmp/hash0-case0-reference');shutil.copytree('/opt/reference',work)
for p in [work,*work.rglob('*')]:os.chown(p,2000,2000);p.chmod(0o700 if p.is_dir()else 0o600)
source=Path('/tests/sandbox_launcher.py').read_text();modified=source.replace("os.write(ready,b'READY\\n');os.close(ready)","env['PYTHONHASHSEED']='0'\nos.write(ready,b'READY\\n');os.close(ready)")
if modified==source:raise RuntimeError('trusted diagnostic launcher patch not applied')
launcher=Path('/tmp/hash0-launcher.py');launcher.write_text(modified);launcher.chmod(0o755)
seeds=[];original_reset=episode.NetHackScore.reset

def reset(env,*a,**kw):
 result=original_reset(env,*a,**kw);seeds.append({'after_reset_native_seeds':list(env.get_seeds()),'all15_obs_initial':{k:{'sha256':hashlib.sha256(v.tobytes()).hexdigest(),'shape':list(v.shape),'dtype':v.dtype.str}for k,v in result[0].items()}});return result

episode.NetHackScore.reset=reset
orig_send=episode.Channel.send;orig_receive=episode.Channel.receive;decoder=ObservationDecoder();pending=None;log=(OUT/'actual-policy-requests.jsonl').open('w');sequence=hashlib.sha256();count=0

def send(channel,frame,deadline):
 global pending
 if frame.get('done')is not True:
  obs=decoder.decode(frame['observation']);fields={k:{'sha256':hashlib.sha256(v.tobytes()).hexdigest(),'shape':list(v.shape),'dtype':v.dtype.str}for k,v in sorted(obs.items())}
  pending={'request_id':frame['request_id'],'observation_sha256':hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'fields':fields}
 return orig_send(channel,frame,deadline)

def receive(channel,deadline):
 global count
 reply=orig_receive(channel,deadline);row={**pending,'reply':reply};log.write(json.dumps(row,separators=(',',':'))+'\n');count+=1;sequence.update(json.dumps(reply,separators=(',',':')).encode()+b'\n');return reply

episode.Channel.send=send;episode.Channel.receive=receive
case=json.loads(Path('/tests/schedule.json').read_text())['episodes'][0]
try:result=episode.run_episode(work,case,OUT/'game','/opt/nethack-env/bin/python',launcher=launcher,wall_sec=600)
finally:log.close()
report={'scope':'one originalcase0 fullnaturalterminal reference with diagnostic candidate PYTHONHASHSEED0; not full8 control or newexpectedreward','machine':platform.machine(),'python':sys.version,'case':case,'hashseed':'0','source_original_launcher_sha256':hashlib.sha256(Path('/tests/sandbox_launcher.py').read_bytes()).hexdigest(),'diagnostic_launcher_sha256':hashlib.sha256(launcher.read_bytes()).hexdigest(),'reference_source_sha256':{str(p.relative_to('/opt/reference')):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(Path('/opt/reference').rglob('*'))if p.is_file()},'after_reset_seeds_and_observation':seeds,'actual_policy_request_count':count,'policy_actions_sha256':sequence.hexdigest(),'policy_request_log_sha256':hashlib.sha256((OUT/'actual-policy-requests.jsonl').read_bytes()).hexdigest(),'result':result,'model_requests':0,'credentials_injected':False};(OUT/'full-case-diagnostic.json').write_text(json.dumps(report,indent=2));assert result['candidate_valid']and result['natural_or_action_limit_terminal'];print('onecasehash0 diagnostic naturalterminal',platform.machine(),result['points'])
