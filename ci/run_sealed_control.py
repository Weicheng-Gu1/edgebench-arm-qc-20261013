"""One native ARM control; all private output goes only to encrypted artifacts."""
import base64, hashlib, json, os, platform, signal, shutil, subprocess, sys, tempfile, threading, time
from decimal import Decimal
from pathlib import Path
from sealed_transport import extract_verified, seal_results

ROOT=Path(__file__).resolve().parents[1]
PUBLIC=ROOT/'sealed-artifacts'; PRIVATE=Path(tempfile.mkdtemp(prefix='eb-private-'))
PRIVATE.chmod(0o700)
container='eb-sealed-'+os.environ.get('CIRCLE_WORKFLOW_JOB_ID','missing')
tag=container.lower()+':local'
checkpoint_thread=None
started=time.monotonic(); stop=threading.Event(); state={'stage':'admission','status':'unknown'}
HOST=Path('/tmp/edgebench-matrix-sealed-'+os.environ.get('CIRCLE_WORKFLOW_JOB_ID','missing')+'.json')
assert not HOST.exists(), 'This exact job control already claimed; no automatic retry'
runner_identity={'pid':os.getpid(),'start_ticks':Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19],'runner_source_SHA256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'private_directory':str(PRIVATE),'runner_status':'running'}
class InfrastructurePlatformPreemption(Exception):pass
def preempt(signum,frame):raise InfrastructurePlatformPreemption('provider one-hour preservation preemption; original inner10800s unchanged')
signal.signal(signal.SIGTERM,preempt)

def save():
    (PRIVATE/'control-state.json').write_text(json.dumps(state,indent=2)+'\n')
    tmp=HOST.with_suffix('.tmp');tmp.write_text(json.dumps(dict(runner_identity,stage=state['stage'],status=state['status']),indent=2)+'\n');tmp.chmod(0o600);tmp.replace(HOST)

def run(cmd,name,timeout):
    with (PRIVATE/(name+'.stdout')).open('wb') as out, (PRIVATE/(name+'.stderr')).open('wb') as err:
        return subprocess.run(cmd,stdout=out,stderr=err,timeout=timeout,check=True,
                              env={k:v for k,v in os.environ.items() if not k.startswith('EB_')})

def checkpoint():
    while not stop.wait(300):
        # Only fixed stage and elapsed are public; raw score, logs and math stay private.
        print(json.dumps({'stage':state['stage'],'elapsed_seconds':round(time.monotonic()-started)}),flush=True)
        try: save(); seal_results(PRIVATE,ROOT/'ci/result-recipient.pem',PUBLIC/'checkpoint.enc')
        except Exception: pass  # final sealing must still succeed or job fails.

def main():
    global checkpoint_thread
    save()
    cfg=json.loads((ROOT/'ci/sealed-public-plan.json').read_text())
    assert cfg['ready_for_execution'] is True
    assert os.environ['CIRCLE_PROJECT_USERNAME']=='Weicheng-Gu1'
    assert os.environ['CIRCLE_PROJECT_REPONAME']=='edgebench-arm-qc-20261013'
    assert os.environ['CIRCLE_BRANCH']==cfg['approved_branch']
    assert os.environ['CIRCLE_SHA1']==os.environ['EB_APPROVED_REVISION']
    assert os.environ['EB_ONE_USE_NONCE']==cfg['one_use_nonce']
    assert int(os.environ['EB_AUTHORIZED_ATTEMPT_WINDOW_SECONDS'])==3600
    assert cfg['attempt_window_seconds']==3600 and cfg['original_inner_verifier_budget_seconds']==10800
    # This approves a one-hour attempt, never asserts an unverified paid plan or completion guarantee.
    assert platform.machine()=='aarch64' and len(os.sched_getaffinity(0))==4
    # Public scope: nominal arm.large16GB; actual physical bytes recorded, not equated to Aliyun16GiB.
    run(['docker','info','--format','{{json .}}'],'docker-info',30)
    info=json.loads((PRIVATE/'docker-info.stdout').read_text())
    assert info['Architecture']=='aarch64' and info['OSType']=='linux' and info['NCPU']==4
    state['host']={'uname':platform.uname()._asdict(),'affinity_cpus':4,'meminfo':Path('/proc/meminfo').read_text()}
    state['docker_daemon']=info
    active={p.name:p.read_text() for p in Path('/proc/sys/fs/binfmt_misc').glob('*') if p.is_file() and 'qemu' in p.name}
    assert not any('enabled' in v for v in active.values())
    state['qemu_binfmt']=active
    blob=(ROOT/'sealed-payload.bin').read_bytes()
    assert hashlib.sha256(blob).hexdigest()==cfg['ciphertext_sha256']
    key=base64.b64decode(os.environ.pop('EB_PAYLOAD_KEY_B64'),validate=True); assert len(key)==32
    state['payload_manifest']=extract_verified(blob,key,PRIVATE/'payload'); del key
    # Secret route is not inherited by Docker, subprocesses or public artifacts.
    os.environ.pop('EB_ONE_USE_NONCE',None)
    os.environ.pop('EB_APPROVED_REVISION',None)
    os.environ.pop('EB_AUTHORIZED_ATTEMPT_WINDOW_SECONDS',None)
    for k in list(os.environ):
        if k.startswith('CIRCLE_TOKEN') or k.startswith('GITHUB_TOKEN') or k.startswith('GH_TOKEN'):
            raise RuntimeError('unexpected credential environment')
    state['stage']='native-image-build'; save()
    checkpoint_thread=threading.Thread(target=checkpoint,daemon=True); checkpoint_thread.start()
    run(['docker','build','--platform','linux/arm64','--progress','plain','-t',tag,
         str(PRIVATE/'payload/verifier')],'native-build',3600)
    run(['docker','image','inspect',tag],'image-inspect',30)
    image=json.loads((PRIVATE/'image-inspect.stdout').read_text())[0]
    assert image['Architecture']=='arm64' and image['Os']=='linux'
    state['stage']='full-Oracle-original-budget'; save()
    export=PRIVATE/'export'; export.mkdir()
    # This changes only former CI2CPU/6GiB quota, not mathematical source/runtime.
    run(['docker','run','--name',container,'--network','none','--cpus','4',
         '--memory','16384m','--memory-swap','16384m',
         '-v',str(export)+':/export',tag,'--fixture','oracle'], 'native-oracle',11400)
    run(['docker','inspect',container],'container-inspect',30)
    inspected=json.loads((PRIVATE/'container-inspect.stdout').read_text())[0]
    quota=inspected['HostConfig']
    assert quota['NanoCpus']==4000000000 and quota['Memory']==17179869184
    assert quota['MemorySwap']==17179869184 and quota['NetworkMode']=='none'
    state['actual_container_quota']=quota
    receipt=json.loads((export/'receipt.json').read_text())
    score=json.loads((export/'verifier/score.json').read_text())
    reward_raw=(export/'verifier/reward.txt').read_bytes()
    reward=str(Decimal(reward_raw.decode().strip()))
    assert Decimal(reward)==1
    state['raw_score_sha256']=hashlib.sha256((export/'verifier/score.json').read_bytes()).hexdigest()
    state['raw_reward_sha256']=hashlib.sha256(reward_raw).hexdigest()
    assert receipt['success'] and receipt['architecture']=='aarch64'
    assert score['valid'] and score['score']==1 and score['certified']==4809 and score['targets_total']==4809 and score['full_solution_validated']
    assert score['checks']['kernel_exit_code']==0 and score['checks']['kernel_modules']==504
    assert score['source_manifest']=={'proofs.json':state['payload_manifest']['oracle_sha256']}
    state.update(stage='complete',status='passed',score=score,reward=reward)

if __name__=='__main__':
    code=1
    try: main(); code=0
    except BaseException as e:
        # No exception text/traceback on public stdout (may contain private paths/source).
        state.update(status='unknown',error_type=type(e).__name__,mathematical_score_not_assigned_from_exception=True)
        import traceback
        (PRIVATE/'private-exception.txt').write_text(traceback.format_exc())
    finally:
        stop.set()
        if checkpoint_thread is not None: checkpoint_thread.join()
        try:
            with (PRIVATE/'cleanup.stdout').open('wb') as out,(PRIVATE/'cleanup.stderr').open('wb') as err:
                removed=subprocess.run(['docker','rm','-f',container],stdout=out,stderr=err,timeout=60)
            with (PRIVATE/'post-cleanup-inspect.stdout').open('wb') as out,(PRIVATE/'post-cleanup-inspect.stderr').open('wb') as err:
                inspected=subprocess.run(['docker','inspect',container],stdout=out,stderr=err,timeout=30)
            error=(PRIVATE/'post-cleanup-inspect.stderr').read_text(errors='replace')
            absent=inspected.returncode==1 and ('No such object' in error or 'No such container' in error)
            state['owned_container_cleanup']={'rm_returncode':removed.returncode,'inspect_returncode':inspected.returncode,'fresh_absence_confirmed':absent}
            if not absent: code=1;state['status']='cleanup_unknown'
            state['elapsed_seconds']=time.monotonic()-started; save()
            seal_results(PRIVATE,ROOT/'ci/result-recipient.pem',PUBLIC/'final.enc')
            runner_identity['final_ciphertext_SHA256']=hashlib.sha256((PUBLIC/'final.enc').read_bytes()).hexdigest()
        except BaseException:
            code=1
        runner_identity['runner_status']='finished';runner_identity['process_exit_code']=code;save()
        print(json.dumps({'status':'passed' if code==0 else 'unknown','sealed_only':True}),flush=True)
        shutil.rmtree(PRIVATE,ignore_errors=True)
    sys.exit(code)
