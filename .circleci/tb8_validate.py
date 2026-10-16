"""CI driver; encrypted payload and evidence, no credentials passed to Docker."""
import base64,hashlib,json,os,platform,subprocess,sys,tarfile,tempfile,time,traceback
from pathlib import Path,PurePosixPath
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

task_id=sys.argv[1];architecture=sys.argv[2]
key=base64.b64decode(os.environ.pop('TB21_SAMPLE_AES_KEY'))
blob=b''.join(p.read_bytes() for p in sorted(Path('.circleci').glob('tb8-sample.enc.*')))
clear=AESGCM(key).decrypt(blob[:12],blob[12:],b'tb21-public-sample-v1')
expected=Path('.circleci/tb8-sample.sha256').read_text().strip()
assert hashlib.sha256(clear).hexdigest()==expected,'transport digest mismatch'
root=Path('/tmp/tb8-ci');root.mkdir(exist_ok=True)
archive=root/'sample.tar.gz';archive.write_bytes(clear);del clear
with tarfile.open(archive) as tar:
    for item in tar.getmembers():
        path=PurePosixPath(item.name)
        assert not path.is_absolute() and '..' not in path.parts
        assert item.isfile() or item.isdir()
    tar.extractall(root,filter='data')
package=root/'tb8-public-sample-v1';evidence=root/'evidence';evidence.mkdir()
public=Path('/tmp/tb8-ci-public');public.mkdir(exist_ok=True)
summary={'task':task_id,'platform':architecture,'host_architecture':platform.machine(),'package_sha256':expected,'commit':os.environ.get('CIRCLE_SHA1'),'job':os.environ.get('CIRCLE_BUILD_URL'),'stages':[],'started':time.time()}
def run(label,cmd,timeout):
    begin=time.time()
    with (evidence/(label+'.log')).open('w') as log:
        p=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
    row={'stage':label,'exit_code':p.returncode,'seconds':round(time.time()-begin,2)}
    summary['stages'].append(row);print(json.dumps(row),flush=True);return p.returncode
try:
    required='aarch64' if architecture=='arm64' else 'x86_64'
    assert platform.machine()==required,'native runner architecture mismatch'
    daemon=subprocess.check_output(['docker','info','--format','{{.Architecture}}'],text=True).strip()
    summary['docker_architecture']=daemon
    assert daemon in (required,architecture),'Docker daemon architecture mismatch'
    for line in (package/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1)
        path=PurePosixPath(name);assert not path.is_absolute() and '..' not in path.parts
        assert hashlib.sha256((package/name).read_bytes()).hexdigest()==digest,name
    script=str(package/'evaluation/run.py');python=sys.executable
    rc=run('build',[python,script,'build','--task',task_id,'--platform','linux/'+architecture],5400)
    assert rc==0,'public clean build failed'
    inspect=json.loads(subprocess.check_output(['docker','image','inspect','tb8-public:'+task_id]))[0]
    summary['image']={'id':inspect['Id'],'architecture':inspect['Architecture'],'os':inspect['Os']}
    assert inspect['Architecture']==architecture
    summary['container_architecture']=subprocess.check_output(['docker','run','--rm','--entrypoint','uname','tb8-public:'+task_id,'-m'],text=True).strip()
    assert summary['container_architecture']==required
    manifest=json.loads((package/'manifest.json').read_text());task=next(t for t in manifest['tasks'] if t['id']==task_id)
    cases=[('oracle',None,1),('nop',None,0)]+[('replay',r['id'],r['expected_reward']) for r in task['runs']]
    for action,runid,wanted in cases:
        label=runid or action;out=evidence/label
        cmd=[python,script,action,'--task',task_id,'--output',str(out)]
        if runid:cmd+=['--run',runid]
        rc=run(label,cmd,1500)
        data=json.loads((out/'run.json').read_text()) if (out/'run.json').exists() else {}
        summary['stages'][-1].update(reward=data.get('reward'),expected_reward=wanted,status=data.get('status'))
    expected_stages=8
    if task['docker_target'] in ('c04','c05'):
        package_name='torch_pruning' if task['docker_target']=='c04' else 'sqlmesh'
        for mode in ['xml','reward']:
            label='attack-'+mode;submission=evidence/(label+'.tar.gz');out=evidence/label
            subprocess.run([python,str(package/'evaluation/regressions/forge_submission.py'),'--package',package_name,'--mode',mode,'--output',str(submission)],check=True)
            run(label,[python,script,'verify','--task',task_id,'--submission',str(submission),'--output',str(out)],1500)
            data=json.loads((out/'run.json').read_text()) if (out/'run.json').exists() else {}
            summary['stages'][-1].update(reward=data.get('reward'),expected_reward=0,status=data.get('status'))
            expected_stages+=1
    summary['passed']=all(x['exit_code']==0 and (x['stage']=='build' or x.get('status')=='graded' and x.get('reward')==x.get('expected_reward')) for x in summary['stages']) and len(summary['stages'])==expected_stages
except Exception as error:
    (evidence/'driver-error.txt').write_text(traceback.format_exc());summary['passed']=False;summary['error_type']=type(error).__name__
finally:
    summary['finished']=time.time()
    (evidence/'summary.json').write_text(json.dumps(summary,indent=2))
    (public/'summary.json').write_text(json.dumps(summary,indent=2))
    archive=root/'evidence.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:tar.add(evidence,arcname='evidence')
    nonce=os.urandom(12);(public/'evidence.enc').write_bytes(nonce+AESGCM(key).encrypt(nonce,archive.read_bytes(),b'tb21-ci-evidence-v1'))
    print(json.dumps({'passed':summary['passed'],'task':task_id,'platform':architecture}),flush=True)
raise SystemExit(0 if summary['passed'] else 1)
