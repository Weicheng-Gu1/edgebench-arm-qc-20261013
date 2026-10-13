import hashlib,json,sys,importlib.metadata,platform
from pathlib import Path
from nle import nethack
from nle.env.tasks import NetHackScore
case=json.loads(Path('/tests/schedule.json').read_text())['episodes'][0];records=[];env=NetHackScore(savedir='/tmp/diag-native',save_ttyrec_every=1,max_episode_steps=100000,character=case['character'],actions=nethack.ACTIONS,observation_keys=('glyphs','chars','colors','specials','blstats','message','inv_glyphs','inv_strs','inv_letters','inv_oclasses','screen_descriptions','tty_chars','tty_colors','tty_cursor','misc'),fix_moon_phase=True,allow_all_yn_questions=True,allow_all_modes=True)
try:
 returned=env.seed(core=case['core'],disp=case['disp'],lgen=case['lgen'],reseed=False);obs,info=env.reset(seed=case['core']);wait=list(nethack.ACTIONS).index(nethack.Command.WAIT)
 for step in range(101):
  if step in (0,1,5,100):records.append({'step':step,'fields':{k:{'sha256':hashlib.sha256(a.tobytes()).hexdigest(),'shape':list(a.shape),'dtype':str(a.dtype)}for k,a in obs.items()},'blstats':obs['blstats'].tolist(),'message_bytes':bytes(obs['message']).split(b'\0')[0].decode(errors='replace')})
  if step<100:
   obs,reward,terminated,truncated,info=env.step(wait)
   if terminated or truncated:raise RuntimeError('Diagnostic terminated early '+str(step))
 output={'scope':'native fixed wait-action world only; no reference policy/paid model','machine':platform.machine(),'python':sys.version,'versions':{p:importlib.metadata.version(p)for p in [line.split('==')[0]for line in Path('/tests/requirements.txt').read_text().splitlines()]},'case':case,'native_seeds_returned':list(returned),'action':int(nethack.Command.WAIT),'records':records};Path('/logs/verifier/fixed-world.json').write_text(json.dumps(output,indent=2));print('fixed0/1/5/100 complete')
finally:env.close()
