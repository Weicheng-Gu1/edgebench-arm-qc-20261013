"""Run an explicitly modified trusted reference, never claim frozen-task QC."""
from pathlib import Path
import copy,hashlib,json,platform,sys,tempfile
sys.path.insert(0,'/tests')
from sandbox import execute
out=Path('/logs/verifier');out.mkdir(parents=True,exist_ok=True)
corpus=json.loads(Path('/tests/private/corpus.json').read_text())
rows=[]
with tempfile.TemporaryDirectory(prefix='trusted-integral-probe-') as folder:
    root=Path(folder);root.chmod(0o755)
    for index,case in enumerate(corpus['cases']):
        request=copy.deepcopy(case['request'])
        for job in request['cases']:
            for observation in job['observe']:
                observation['mesh']=False;observation['classify']=[]
        raw,measurement=execute(Path('/tests/private/reference'),json.dumps(request).encode(),root,30)
        (out/f'case-{index}-raw.json').write_bytes(raw)
        row={'index':index,'case_id':case['id'],'measurement':measurement,
             'raw_sha256':hashlib.sha256(raw).hexdigest()}
        try:
            result=json.loads(raw)
            row['measurements']=result
            row['passed']=measurement['status']=='completed' and all(x['ok'] for x in result['results'])
        except (ValueError,KeyError,TypeError):row['passed']=False
        rows.append(row)
        (out/'progress.json').write_text(json.dumps({'completed':len(rows),'rows':rows},indent=2))
report={'kind':'trusted_reference_integral_convergence_study',
        'actual_host_machine':platform.machine(),'all_case_count':len(rows),
        'passed':all(x['passed'] for x in rows),'rows':rows,
        'full_frozen_task_grade_claimed':False,'model_calls':0,'full_delivery_pass':False}
(out/'report.json').write_text(json.dumps(report,indent=2))
assert report['passed'],'Inspect original per-case numerical probe failure'
