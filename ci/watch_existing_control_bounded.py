"""Bounded same-job observer; no trigger, SDK, build, grade or process restart."""
from pathlib import Path
import argparse, hashlib, json, os, time
ROOT = Path(__file__).resolve().parents[1]
def same_process(row):
    try:
        fields=(Path('/proc')/str(row['pid'])/'stat').read_text().rsplit(')',1)[1].split()
        return fields[19]==row['start_ticks'] and fields[0]!='Z'
    except (FileNotFoundError, ProcessLookupError): return False
def observe(max_seconds):
    end=time.monotonic()+max_seconds; row=None
    while time.monotonic()<end:
        p=ROOT/'.sealed-control-status.json'
        if p.exists():
            row=json.loads(p.read_text())
            assert row['run_id']==os.environ['GITHUB_RUN_ID'] and row['run_attempt']==os.environ['GITHUB_RUN_ATTEMPT']
            if row.get('runner_status')=='finished' or not same_process(row): break
        time.sleep(1)
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in(ROOT/'sealed-artifacts').glob('*.enc')}
    stamp=ROOT/'.last-checkpoint-upload-map.json'; prior=json.loads(stamp.read_text())if stamp.exists()else{}
    upload=bool(files and files!=prior)
    if upload:stamp.write_text(json.dumps(files)+'\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a')as f:f.write('upload='+str(upload).lower()+'\n')
    print(json.dumps({'bounded_original_control_read':True,'runner_status':None if row is None else row.get('runner_status'),
        'stage':None if row is None else row.get('stage'),'new_encrypted_checkpoint':upload,'grade_or_trigger_calls':0}),flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--max-seconds',type=int,required=True);a=p.parse_args()
    assert 0<=a.max_seconds<=1800;observe(a.max_seconds)
