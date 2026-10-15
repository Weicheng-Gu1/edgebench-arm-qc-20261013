"""Final job status cannot substitute for decrypted raw mathematical verification."""
from pathlib import Path
import hashlib,json,os
ROOT=Path(__file__).resolve().parents[1]
host=Path('/tmp/edgebench-matrix-proper-build-'+os.environ['CIRCLE_WORKFLOW_JOB_ID']+'.json')
r=json.loads(host.read_text());assert r['runner_source_SHA256']==hashlib.sha256((ROOT/'ci/run_sealed_control.py').read_bytes()).hexdigest()
assert r['runner_status']=='finished'and r['status']=='passed'and r['process_exit_code']==0,'Unknown or failed control; no reward assigned'
p=ROOT/'sealed-artifacts/final.enc';assert p.is_file()and hashlib.sha256(p.read_bytes()).hexdigest()==r['final_ciphertext_SHA256'];print(json.dumps({'status':'both_roles_and_one_full_Oracle_finished_and_encrypted','decrypted_full_Oracle_source_input_resources_and_kernel_review_still_required':True}))
