"""GitHub native ARM proper two roles and at most three original first-trajectory terminal inputs.

Only source hashes, phase and infrastructure identity may reach public stdout.
Task sources, proof values, logs and results remain in authenticated ciphertext.
"""
from pathlib import Path
import argparse, base64, hashlib, json, os, platform, re, shutil, signal
import subprocess, sys, tempfile, threading, time, uuid
from sealed_transport import extract_verified, seal_results
ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT/'ci/sealed-public-plan.json'
REPO = 'Weicheng-Gu1/edgebench-arm-qc-20261013'
WORKFLOW = '.github/workflows/edgebench-esa-public-native-controller-path-r3.yml'
HOST = ROOT/'.sealed-control-status.json'
PUBLIC = ROOT/'sealed-artifacts'
BLOCKED_ENV_PREFIXES = ('EB_', 'GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')
class InfrastructureWindowEnd(Exception): pass
def H(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def safe_env(): return {k: v for k, v in os.environ.items() if not k.startswith(BLOCKED_ENV_PREFIXES)}
def write(p, value):
    tmp = p.with_suffix('.tmp'); tmp.write_text(json.dumps(value, indent=2)+'\n'); tmp.chmod(0o600); tmp.replace(p)
def own_absence(name, expected_names, removed, inspected):
    if name not in expected_names or removed.returncode != 0 or inspected.returncode != 1: return False
    try:
        if json.loads(inspected.stdout) != []: return False
    except (ValueError, TypeError): return False
    return re.fullmatch(r'(?:error:\s*|error response from daemon:\s*)?no such (?:object|container):\s*'+re.escape(name.casefold()), inspected.stderr.strip().casefold()) is not None
def signal_preempt(signum, frame): raise InfrastructureWindowEnd('provider/owner infrastructure interruption; not mathematical zero')
def validate_posthoc_score(score, reward, manifest, before):
    import math
    assert score['schema'] == 'openai-math-proof-score-v1' and score['valid'] is True
    assert score['targets_total'] == manifest['targets_total'] == 3775
    certified = score['certified']; assert type(certified) is int and 0 <= certified <= 3775
    assert math.isfinite(reward) and 0 <= reward <= 1 and score['score'] == reward
    assert abs(reward-certified/3775) < 1e-14
    assert score['checks']['audit_exit_code'] == score['checks']['kernel_exit_code'] == 0
    assert score['checks']['fixed_mathematical_interfaces']['changed_modules'] == []
    assert score['source_manifest'] == {k:v['SHA256'] for k,v in before['files'].items()}
    return score['checks']['kernel_modules']
PROBE = "import os,platform,json,subprocess,pathlib,hashlib\nr={'architecture':platform.machine(),'affinity_cpus':len(os.sched_getaffinity(0)),'cpu_max':pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'memory_max':pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip(),'memory_swap_max':pathlib.Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'tests_present':pathlib.Path('/tests/test.sh').is_file(),'image_owned_checker_present':pathlib.Path('/opt/grader-source/tests/test.sh').is_file(),'image_owned_native_components':json.loads(pathlib.Path('/opt/grader-source/tests/native-components.json').read_text())if pathlib.Path('/opt/grader-source/tests/native-components.json').is_file()else None,'toolchain_identity':json.loads(pathlib.Path('/toolchain-identity.json').read_text()),'lean_version':subprocess.check_output(['/opt/lean/bin/lean','--version'],text=True).strip(),'protected_tests_source_SHA256_map':{p.relative_to(pathlib.Path('/tests')).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()for p in pathlib.Path('/tests').rglob('*')if p.is_file()and p.suffix not in ['.native','.olean','.ilean','.pyc']and'__pycache__'not in p.parts and p.name!='native-components.json'}if pathlib.Path('/tests').exists()else {}}\nprint(json.dumps(r))\n"
INPUT_PROBE = r'''from pathlib import Path
import hashlib,json,stat,sys
r=Path(sys.argv[1]);f={};d={'.':stat.S_IMODE(r.stat().st_mode)}
for p in sorted(r.rglob('*')):
 assert not p.is_symlink();rel=p.relative_to(r).as_posix()
 if p.is_dir():d[rel]=stat.S_IMODE(p.stat().st_mode)
 else:assert p.is_file();f[rel]={'SHA256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size,'mode':stat.S_IMODE(p.stat().st_mode)}
print(json.dumps({'files':f,'directories':d}))
'''
def controller(private, cfg):
    started = time.monotonic(); stop = threading.Event(); lock = threading.Lock()
    private = Path(private); manifest = json.loads((private/'payload/payload-manifest.json').read_text())
    run_key = os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    names = {r: 'eb-gh-sealed-'+run_key+'-'+r for r in ['work', 'judge']}
    tags = {r: names[r]+':local' for r in names}; created = []; child = None
    state = {'stage': 'admission', 'infrastructure_status': 'running', 'mathematical_status': 'not_computed',
             'posthoc_input_attempts': [], 'posthoc_results': [], 'payload_manifest': manifest, 'roles': []}
    identity = {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                'runner_source_SHA256': H(__file__), 'run_id': os.environ['GITHUB_RUN_ID'],
                'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'runner_status': 'running', 'payload_loaded': True}
    def save():
        with lock:
            write(private/'control-state.json', state)
            write(HOST, dict(identity, stage=state['stage'], infrastructure_status=state['infrastructure_status'],
                             mathematical_status=state['mathematical_status'], elapsed_seconds=time.monotonic()-started))
    def command(args, name, timeout):
        nonlocal child
        with (private/(name+'.stdout')).open('wb') as out, (private/(name+'.stderr')).open('wb') as err:
            child = subprocess.Popen(args, stdout=out, stderr=err, env=safe_env(), start_new_session=True)
            began = time.monotonic()
            try:
                while child.poll() is None:
                    if time.monotonic()-started >= cfg['attempt_window_seconds']: raise InfrastructureWindowEnd('outer hosted-runner safety window')
                    if time.monotonic()-began > timeout: raise subprocess.TimeoutExpired(args, timeout)
                    try: child.wait(timeout=1)
                    except subprocess.TimeoutExpired: pass
                if child.returncode: raise subprocess.CalledProcessError(child.returncode, args)
            except BaseException:
                if child.poll() is None:
                    try: os.killpg(child.pid, signal.SIGTERM); child.wait(timeout=5)
                    except subprocess.TimeoutExpired: os.killpg(child.pid, signal.SIGKILL); child.wait()
                    except ProcessLookupError: pass
                raise
            finally: child = None
    def capture(label, include_live=True):
        with lock:
            # Progress is forensic only; copies may span writes. A valid final
            # mathematical result still requires the full after-input checks.
            if include_live and names['judge'] in created:
                dst = private/'inflight-verifier'; dst.mkdir(exist_ok=True)
                try:
                    p = subprocess.run(['docker','cp',names['judge']+':/logs/verifier/.',str(dst)], capture_output=True, timeout=90, env=safe_env())
                    state['last_inflight_copy'] = {'label': label, 'exit': p.returncode, 'point_in_time_atomicity_not_claimed': True}
                except Exception as exc: state['last_inflight_copy'] = {'label': label, 'error_type': type(exc).__name__}
            write(private/'control-state.json', state)
            seal_results(private, ROOT/'ci/result-recipient.pem', PUBLIC/(label+'.enc'))
    def checkpoint():
        while not stop.wait(300):
            try: save(); capture('checkpoint')
            except Exception as exc:
                state['checkpoint_error_type'] = type(exc).__name__; save()
    signal.signal(signal.SIGTERM, signal_preempt)
    watcher = threading.Thread(target=checkpoint, daemon=True); watcher.start(); code = 1
    try:
        save(); state['host'] = {'architecture': platform.machine(), 'affinity_cpus': len(os.sched_getaffinity(0)),
            'meminfo': Path('/proc/meminfo').read_text(), 'disk_available_bytes': shutil.disk_usage(private).free}
        assert platform.machine() == 'aarch64' and len(os.sched_getaffinity(0)) == 4
        command(['docker','info','--format','{{json .}}'], 'docker-info', 60)
        info = json.loads((private/'docker-info.stdout').read_text()); assert info['Architecture'] == 'aarch64' and info['NCPU'] == 4
        state['docker_daemon'] = info
        docker_root = Path(info['DockerRootDir']); assert docker_root.is_dir()
        actual_disk = shutil.disk_usage(docker_root)
        state['disk_admission'] = {'DockerRootDir':str(docker_root),'actual_available_bytes':actual_disk.free,
            'required_available_bytes':cfg['minimum_free_disk_bytes'],
            'basis':'12GiB explicit infrastructure floor; prior proper Hard AMD images about4GB each with shared base, ARM actual usage measured; not a guarantee of fit',
            'passed':actual_disk.free >= cfg['minimum_free_disk_bytes']}; save()
        if not state['disk_admission']['passed']: raise InfrastructureWindowEnd('actual native-builder disk below explicit infrastructure floor; no build or mathematical attempt')
        binfmt = {p.name:p.read_text() for p in Path('/proc/sys/fs/binfmt_misc').glob('*') if p.is_file() and 'qemu' in p.name}
        assert not any('enabled' in v for v in binfmt.values()); state['qemu_binfmt'] = binfmt
        for role, context in [('work','environment'),('judge','tests')]:
            state['stage'] = role+'-native-build'; save()
            command(['docker','build','--platform','linux/arm64','--progress','plain','-t',tags[role],str(private/'payload'/context)], role+'-build', manifest['original_verifier_timeout_sec'])
            command(['docker','image','inspect',tags[role]], role+'-image-inspect', 60)
            image = json.loads((private/(role+'-image-inspect.stdout')).read_text())[0]
            assert image['Architecture'] == 'arm64' and image['Os'] == 'linux' and not image['Config'].get('Entrypoint')
            command(['docker','create','--name',names[role],'--label','edgebench.sealed-run='+run_key,'--network','none','--cpus','4','--memory','16384m','--memory-swap','16384m','--user','root',tags[role],'sleep','infinity'], role+'-create', 60)
            created.append(names[role]); command(['docker','start',names[role]], role+'-start', 60)
            state['stage'] = role+'-native-resource-foundation-probe'; save()
            command(['docker','exec',names[role],'/usr/bin/python3','-I','-c',PROBE], role+'-probe', 240)
            p = json.loads((private/(role+'-probe.stdout')).read_text())
            assert p['architecture'] == 'aarch64' and p['cpu_max'] == '400000 100000' and p['memory_max'] == '17179869184' and p['memory_swap_max'] == '0' and p['interfaces'] == ['lo']
            assert p['toolchain_identity']['architecture'] == 'aarch64' and p['toolchain_identity']['official_release_sha256'] == manifest['official_ARM_Lean_release_SHA256']
            assert p['tests_present'] == p['image_owned_checker_present'] == (role == 'judge')
            if role == 'judge':
                assert p['image_owned_native_components']['architecture'] == 'aarch64'
                assert p['protected_tests_source_SHA256_map'] == manifest['expected_judge_protected_tests_SHA256_map']
            command(['docker','inspect',names[role]], role+'-container-inspect', 60)
            ins = json.loads((private/(role+'-container-inspect.stdout')).read_text())[0]; q = ins['HostConfig']
            assert q['Memory'] == q['MemorySwap'] == 17179869184 and q['NanoCpus'] == 4000000000 and q['NetworkMode'] == 'none'
            state['roles'].append({'role':role,'image_Id':image['Id'],'image_RootFS':image['RootFS'],'actual_container_quota':q,'probe':p}); save()
        # Resource routing was probed above. Each candidate now gets a fresh
        # judge container from that exact built image, without previous caches.
        old_judge=names['judge']
        removed=subprocess.run(['docker','rm','-f',old_judge],capture_output=True,text=True,timeout=90,env=safe_env())
        inspected=subprocess.run(['docker','inspect',old_judge],capture_output=True,text=True,timeout=45,env=safe_env())
        assert own_absence(old_judge,set(names.values()),removed,inspected)
        created.remove(old_judge);state['posthoc_case_cleanup']=[]
        judge = names['judge']; artifact = manifest['artifact_absolute_path']
        assert 1 <= len(manifest['posthoc_cases']) <= 3
        for index, case in enumerate(manifest['posthoc_cases'], 1):
            identity_key = case['input_identity']; prefix = 'case-'+str(index)+'-'+identity_key[:12]
            assert identity_key not in state['posthoc_input_attempts']
            state['stage'] = prefix+'-original-input-posthoc'; state['posthoc_input_attempts'].append(identity_key); save()
            command(['docker','create','--name',judge,'--label','edgebench.sealed-run='+run_key,'--network','none','--cpus','4','--memory','16384m','--memory-swap','16384m','--user','root',tags['judge'],'sleep','infinity'],prefix+'-create',60)
            created.append(judge);command(['docker','start',judge],prefix+'-start',60)
            fixture = private/'payload'/case['fixture_relative_path']
            prepare = "from pathlib import Path;import shutil,sys;r=Path(sys.argv[1]);assert r.is_dir()and not r.is_symlink();shutil.rmtree(r);r.mkdir(mode=int(sys.argv[2]))"
            command(['docker','exec',judge,'/usr/bin/python3','-I','-c',prepare,artifact,str(case['complete_input_manifest']['directories']['.'])],prefix+'-input-prepare',60)
            # Remove only this container's previous verifier logs, never host/original evidence.
            command(['docker','exec',judge,'/usr/bin/python3','-I','-c',"from pathlib import Path;import shutil;p=Path('/logs/verifier');shutil.rmtree(p,ignore_errors=True);p.mkdir(parents=True)"],prefix+'-logs-prepare',60)
            command(['docker','cp','-a',str(fixture)+'/.',judge+':'+artifact],prefix+'-input-copy',120)
            command(['docker','exec',judge,'/usr/bin/python3','-I','-c',INPUT_PROBE,artifact],prefix+'-input-before',60)
            before = json.loads((private/(prefix+'-input-before.stdout')).read_text()); assert before == case['complete_input_manifest']
            # Direct unchanged scientific checker posthoc scope, NOT a Harbor
            # lifecycle or model trajectory. Every case retains its original
            # 21600s checker timeout; the 19800s shared infrastructure window
            # may leave a case and later cases unknown, never zero.
            command(['docker','exec','--user','root',judge,'/bin/bash','/tests/test.sh'],prefix+'-grade',manifest['original_verifier_timeout_sec'])
            target=private/prefix;target.mkdir();command(['docker','cp',judge+':/logs/verifier',str(target)],prefix+'-raw-download',120)
            raw=target/'verifier'; score=json.loads((raw/'score.json').read_text());reward=float((raw/'reward.txt').read_text())
            modules=validate_posthoc_score(score,reward,manifest,before)
            evidence=Path(score['private_evidence_directory'])
            assert evidence.is_absolute()and evidence.name=='private'and evidence.parent.name.startswith('peterfalvi-grade-')and evidence.parent.parent==Path('/tmp')
            command(['docker','cp',judge+':'+str(evidence),str(target/'original-private-audit-evidence')],prefix+'-private-audit-download',180)
            command(['docker','exec',judge,'/usr/bin/python3','-I','-c',INPUT_PROBE,artifact],prefix+'-input-after',60)
            after=json.loads((private/(prefix+'-input-after.stdout')).read_text());assert after==before
            command(['docker','exec',judge,'/usr/bin/python3','-I','-c',PROBE],prefix+'-protected-after',240)
            post=json.loads((private/(prefix+'-protected-after.stdout')).read_text());prior=next(x['probe']for x in state['roles']if x['role']=='judge')
            assert post['protected_tests_source_SHA256_map']==prior['protected_tests_source_SHA256_map']
            assert (post['cpu_max'],post['memory_max'],post['memory_swap_max'],post['interfaces'])==('400000 100000','17179869184','0',['lo'])
            state['posthoc_results'].append({'input_identity':identity_key,'original_rounds':case['original_rounds'],'score':reward,'certified':score['certified'],'targets':3775,'kernel_modules':modules,'score_SHA256':H(raw/'score.json'),'reward_SHA256':H(raw/'reward.txt'),'complete_input_before':before,'complete_input_after':after,'posthoc_hardware_scope':'native ARM GitHub hosted4CPU16GiB cgroup; not Aliyun hardware equivalence','original_verifier_timeout_sec':21600,'raw_directory':prefix+'/verifier'})
            removed=subprocess.run(['docker','rm','-f',judge],capture_output=True,text=True,timeout=90,env=safe_env())
            inspected=subprocess.run(['docker','inspect',judge],capture_output=True,text=True,timeout=45,env=safe_env())
            absent=own_absence(judge,set(names.values()),removed,inspected)
            state['posthoc_case_cleanup'].append({'identity':identity_key,'remove_exit':removed.returncode,'inspect_exit':inspected.returncode,'fresh_absent':absent})
            assert absent;created.remove(judge)
            save();capture('checkpoint',include_live=False)
        state['mathematical_status']='complete_valid_posthoc_batch'
        state['stage'] = 'complete'; state['infrastructure_status'] = 'passed'; save(); code = 0
    except BaseException as exc:
        state.update(infrastructure_status='unknown', error_type=type(exc).__name__)
        import traceback
        (private/'private-exception.txt').write_text(traceback.format_exc())
    finally:
        stop.set(); watcher.join(timeout=100)
        try:
            capture('checkpoint')
            cleanup = []
            for name in created:
                assert name in names.values()
                removed = subprocess.run(['docker','rm','-f',name], capture_output=True, text=True, timeout=90, env=safe_env())
                inspected = subprocess.run(['docker','inspect',name], capture_output=True, text=True, timeout=45, env=safe_env())
                gone = own_absence(name, set(names.values()), removed, inspected)
                cleanup.append({'name':name,'remove_exit':removed.returncode,'inspect_exit':inspected.returncode,'fresh_absent':gone})
                if not gone: code = 1; state['infrastructure_status'] = 'cleanup_unknown'
            state['own_container_cleanup'] = cleanup; state['elapsed_seconds'] = time.monotonic()-started
            state['infrastructure_window_seconds'] = cfg['attempt_window_seconds']; save(); capture('final', include_live=False)
        except BaseException as exc:
            code = 1; state['final_capture_error_type'] = type(exc).__name__
        identity.update(runner_status='finished', process_exit_code=code)
        if (PUBLIC/'final.enc').exists(): identity['final_ciphertext_SHA256'] = H(PUBLIC/'final.enc')
        save(); print(json.dumps({'sealed_control_finished':True,'infrastructure_status':state['infrastructure_status'],'mathematical_status':state['mathematical_status']}), flush=True)
        shutil.rmtree(private, ignore_errors=True)
    return code
def launch():
    cfg = json.loads(PLAN.read_text())
    assert cfg['ready_for_execution'] and cfg['purpose'] == 'native-arm-current-Hard-first-three-terminal-original-posthoc-batch'
    assert os.environ['GITHUB_REPOSITORY'] == REPO and os.environ['GITHUB_REF'] == 'refs/heads/'+cfg['approved_branch']
    assert os.environ['GITHUB_SHA'] == os.environ['EB_APPROVED_REVISION']
    assert os.environ['GITHUB_WORKFLOW_REF'] == REPO+'/'+WORKFLOW+'@refs/heads/'+cfg['approved_branch']
    assert os.environ['GITHUB_RUN_ATTEMPT'] == '1' and os.environ['EB_ONE_USE_NONCE'] == cfg['one_use_nonce']
    assert cfg['attempt_window_seconds'] == 19800 and cfg['minimum_free_disk_bytes'] == 12*1024**3 and not HOST.exists()
    blob = (ROOT/'sealed-payload.bin').read_bytes(); assert H(ROOT/'sealed-payload.bin') == cfg['ciphertext_sha256']
    key = base64.b64decode(os.environ.pop('EB_PAYLOAD_KEY_B64'), validate=True); assert len(key) == 32
    private = Path(tempfile.mkdtemp(prefix='eb-gh-private-control-')); private.chmod(0o700)
    manifest = extract_verified(blob, key, private/'payload'); del key
    for rel, mode in sorted(manifest['directories'].items(), key=lambda x:len(Path(x[0]).parts), reverse=False):
        assert rel != '.' and not Path(rel).is_absolute() and '..' not in Path(rel).parts
        p = private/'payload'/rel; p.mkdir(parents=True, exist_ok=True); p.chmod(mode)
    for name in list(os.environ):
        if name.startswith(('EB_','GITHUB_TOKEN','GH_TOKEN','ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN')): os.environ.pop(name)
    log = private/'controller-console.log'
    # GitHub runner owns this child for the life of this one job. It is not
    # detached from runner job cleanup or carried into any other job/runner.
    pid = os.fork()
    if pid == 0:
        os.setsid()
        with log.open('ab', buffering=0) as out:
            os.dup2(out.fileno(),1); os.dup2(out.fileno(),2)
            os._exit(controller(private,cfg))
    end = time.monotonic()+90
    while time.monotonic()<end:
        if HOST.exists():
            s=json.loads(HOST.read_text())
            if s.get('pid')==pid and s.get('payload_loaded'):
                print(json.dumps({'sealed_control_actual_started':True,'pid':pid,'payload_loaded':True,'run_id':os.environ['GITHUB_RUN_ID']}),flush=True);return
        dead,status=os.waitpid(pid,os.WNOHANG)
        if dead:raise RuntimeError('sealed child exited before actual-start receipt')
        time.sleep(.25)
    raise TimeoutError('sealed controller START unknown; do not retrigger')
if __name__ == '__main__': launch()
