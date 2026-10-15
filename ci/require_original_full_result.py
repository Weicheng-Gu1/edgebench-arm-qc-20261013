"""Bounded original-job final gate. Unknown is a CI failure, never score zero."""
from pathlib import Path
import hashlib,json,os,time
ROOT=Path(__file__).resolve().parents[1]
def main():
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        p=ROOT/'.sealed-control-status.json'
        if p.exists():
            row=json.loads(p.read_text())
            assert row['run_id']==os.environ['GITHUB_RUN_ID']and row['run_attempt']==os.environ['GITHUB_RUN_ATTEMPT']
            if row.get('runner_status')=='finished':break
        time.sleep(1)
    else:raise RuntimeError('original controller final status unknown; no restart or mathematical zero')
    final=ROOT/'sealed-artifacts/final.enc'
    assert final.is_file()and hashlib.sha256(final.read_bytes()).hexdigest()==row['final_ciphertext_SHA256']
    assert row['mathematical_status']=='complete_four_original_posthoc_inputs', 'not completed within infrastructure window; unknown, not zero'
    assert row['infrastructure_status']=='passed'and row['process_exit_code']==0
    print(json.dumps({'one_original_control_completed':True,'sealed_final_present':True,'must_authenticate_cipher_and_original_raw_before_claiming_score':True}))
if __name__=='__main__':main()
