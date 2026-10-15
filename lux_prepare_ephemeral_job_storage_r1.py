"""Only a fresh dedicated GitHub-hosted job; never called on development host."""
from pathlib import Path
import json,os,shutil,subprocess,sys
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
assert os.geteuid()==0
out=Path(sys.argv[1]);out.parent.mkdir(parents=True,exist_ok=True)
record={'scope':'dedicated ephemeral GitHub-hosted job only; unused preinstalled Android/.NET/Haskell tools',
        'developer_or_other_job_resources_touched':False,'before_df':subprocess.check_output(['df','-B1','.'],text=True),'removed':[]}
for name in ['/usr/local/lib/android','/usr/share/dotnet','/opt/ghc']:
    p=Path(name)
    if p.exists():
        assert p.is_dir() and not p.is_symlink() and str(p.resolve())==name
        size=subprocess.check_output(['du','-s','-B1',str(p)],text=True).split()[0]
        shutil.rmtree(p)
        record['removed'].append({'path':name,'allocated_before_bytes':int(size),'actual_absent':not p.exists()})
record['after_df']=subprocess.check_output(['df','-B1','.'],text=True)
out.write_text(json.dumps(record,indent=2)+'\n')
