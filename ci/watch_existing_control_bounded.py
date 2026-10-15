"""One finite existing-process observation; no start/retry, secrets or raw stdout."""
from pathlib import Path
import argparse,hashlib,json,os,signal,stat,time
ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser();ap.add_argument('--seconds',type=int,default=480);ap.add_argument('--final-preservation-step',action='store_true');a=ap.parse_args();assert 1<=a.seconds<=480
host=Path('/tmp/edgebench-matrix-sealed-'+os.environ['CIRCLE_WORKFLOW_JOB_ID']+'.json');deadline=time.monotonic()+a.seconds

def read():
 if not host.exists():return None
 st=host.stat();assert stat.S_ISREG(st.st_mode)and st.st_uid==os.geteuid()and not st.st_mode&0o077
 r=json.loads(host.read_text());assert r['runner_source_SHA256']==hashlib.sha256((ROOT/'ci/run_sealed_control.py').read_bytes()).hexdigest();return r

def same_alive(r):
 p=Path('/proc',str(r['pid']),'stat')
 return p.exists()and p.read_text().rsplit(')',1)[1].split()[19]==r['start_ticks']
while time.monotonic()<deadline:
 r=read()
 if r is not None and(r['runner_status']=='finished'or not same_alive(r)):break
 time.sleep(min(2,max(0,deadline-time.monotonic())))
r=read()
if r is None:
 print(json.dumps({'status':'unknown','reason':'original control identity not yet observed','no_restart':True}));raise SystemExit(0)
if a.final_preservation_step and r['runner_status']!='finished'and same_alive(r):
 # Explicit outer infrastructure cancellation reserves time for sealing/upload.
 # It never changes the original10800s checker argument or assigns a math reward.
 os.kill(r['pid'],signal.SIGTERM);end=time.monotonic()+120
 while time.monotonic()<end:
  r=read()
  if r['runner_status']=='finished'or not same_alive(r):break
  time.sleep(1)
print(json.dumps({'status':r.get('status','unknown'),'original_runner_status':r['runner_status'],'same_original_PID_alive':same_alive(r),'finite_observation_only':True,'no_restart_or_new_control':True}))
