"""Owner-only bounded same-observation first-action/hash experiment; no game scores."""
import sys,os,json,subprocess,time,signal,shutil,select,hashlib,platform
from pathlib import Path
sys.path.insert(0,'/tests')
from episode import Channel,OBS,descriptor
from nethack_protocol import ObservationEncoder
from nle.env.tasks import NetHackScore
from nle import nethack
OUT=Path('/logs/verifier');OUT.mkdir(parents=True,exist_ok=True)
fixture=Path('/opt/same-observations.json')
if fixture.exists():frames=json.loads(fixture.read_text());origin='identical recorded AMD64 frames'
else:
 frames=[];schedule=json.loads(Path('/tests/schedule.json').read_text())['episodes']
 for i in (0,1):
  case=schedule[i];env=NetHackScore(savedir=f'/tmp/first-world-{i}',save_ttyrec_every=1,max_episode_steps=100000,character=case['character'],actions=nethack.ACTIONS,observation_keys=OBS,fix_moon_phase=True,allow_all_yn_questions=True,allow_all_modes=True)
  try:
   env.seed(core=case['core'],disp=case['disp'],lgen=case['lgen'],reseed=False);obs,_=env.reset(seed=case['core'])
   frame={'schema':'nethack-jsonl-v1','kind':'init','episode_id':case['episode_id'],'character':case['character'],'policy_seed':0,'action_keys':[int(a) for a in nethack.ACTIONS],'request_id':0,'reward':0,'done':False,'info':{'end_status':0,'is_ascended':False},'observation':ObservationEncoder().encode(obs,True)}
   frames.append({'case':case,'seeds_after_reset':list(env.get_seeds()),'frame':frame})
  finally:env.close()
 origin='recorded native AMD64 initial observations (no engine action)'
(OUT/'same-observations.json').write_text(json.dumps(frames,separators=(',',':'))+'\n')
# Independent diagnostic copy: only added explicit hashseed to the trusted launcher env.
launcher=Path('/tmp/policy-diagnostic-launcher.py');src=Path('/tests/sandbox_launcher.py').read_text()
src=src.replace("if len(sys.argv)!=6:raise SystemExit(119)","if len(sys.argv)!=7:raise SystemExit(119)")
src=src.replace("python,code,work,kind,ready=sys.argv[1:];ready=int(ready)","python,code,work,kind,ready,hashseed=sys.argv[1:];ready=int(ready)")
src=src.replace("os.write(ready,b'READY\\n');os.close(ready)","if hashseed!='unset':env['PYTHONHASHSEED']=hashseed\nos.write(ready,b'READY\\n');os.close(ready)")
launcher.write_text(src);launcher.chmod(0o755)
rows=[]
for item in frames:
 for hashseed in ('unset','0','1'):
  for repeat in range(2):
   name=f"{item['case']['episode_id']}-{hashseed}-{repeat}";out=OUT/name;out.mkdir()
   work=Path('/tmp')/('policy-'+name);shutil.copytree('/opt/reference',work)
   # Keep original policy/source unchanged; small wrapper records process hash state before imports.
   wrapper=work/'diag_entry.py';wrapper.write_text("import os,sys,json,runpy\nfrom pathlib import Path\nPath('hashstate.json').write_text(json.dumps({'hashseed':os.environ.get('PYTHONHASHSEED'),'hash_nethack':hash('nethack'),'string_set_order':list({'wand','potion','scroll','ring','weapon','armor'})}))\nrunpy.run_path('agent.py',run_name='__main__')\n")
   for p in [work,*work.rglob('*')]:
    os.chown(p,2000,2000);p.chmod(0o700 if p.is_dir() else 0o600)
   r,w=os.pipe();err=(out/'candidate.stderr').open('wb');begin=time.monotonic();proc=None;reply=None;failure=None
   try:
    proc=subprocess.Popen(['/usr/bin/python3','-B','-I',str(launcher),'/opt/nethack-env/bin/python',str(wrapper),str(work),'python',str(w),hashseed],cwd=work,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,start_new_session=True,pass_fds=(w,));os.close(w);w=None
    if not select.select([r],[],[],30)[0] or os.read(r,4096)!=b'READY\n':raise RuntimeError('diagnostic trusted launcher failed')
    ch=Channel(proc);deadline=time.monotonic()+60;ch.send(item['frame'],deadline);reply=ch.receive(deadline)
    if not isinstance(reply,dict) or reply.get('request_id')!=0 or type(reply.get('action_key'))is not int:raise RuntimeError('unexpected first reply')
   except Exception as e:failure=type(e).__name__+': '+str(e)
   finally:
    if proc:
     try:os.killpg(proc.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     proc.wait(timeout=10)
    os.close(r)
    if w is not None:os.close(w)
    err.close()
   state=json.loads((work/'hashstate.json').read_text()) if(work/'hashstate.json').exists()else None
   row={'case':item['case'],'hashseed_mode':hashseed,'repeat':repeat,'first_reply':reply,'failure':failure,'hash_state':state,'seconds':time.monotonic()-begin,'candidate_exit':proc.returncode if proc else None,'frame_sha256':hashlib.sha256(json.dumps(item['frame'],separators=(',',':')).encode()).hexdigest()};rows.append(row)
   (OUT/'progress.json').write_text(json.dumps(rows,indent=2));shutil.rmtree(work)
report={'scope':'only first policy response to exactly same initial observations, no native game step/no points/no full reference rerun','machine':platform.machine(),'python':sys.version,'fixture_origin':origin,'fixture_sha256':hashlib.sha256((OUT/'same-observations.json').read_bytes()).hexdigest(),'launcher_original_sha256':hashlib.sha256(Path('/tests/sandbox_launcher.py').read_bytes()).hexdigest(),'launcher_diagnostic_sha256':hashlib.sha256(launcher.read_bytes()).hexdigest(),'reference_source_sha256':{str(p.relative_to('/opt/reference')):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path('/opt/reference').rglob('*'))if p.is_file()},'rows':rows,'model_requests':0,'credentials_injected':False};(OUT/'policy-diagnostic.json').write_text(json.dumps(report,indent=2));assert all(r['failure']is None for r in rows)
print('same-observation first action/hashseed complete',platform.machine())
