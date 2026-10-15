"""Generic GitHub native-AMD64 sealed two-role build and eight original controls.

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
def validate_fixed_score(score, reward, manifest, before):
    # Actual physical-module Borsuk checker schema; the Matrix/MaxCut
    # audit_exit_code/kernel_exit_code/kernel_modules schema does not apply.
    assert score['schema'] == 'physical-module-proof-score-v1'
    assert score['valid'] is True and score['full_solution_validated'] is True
    assert score['certified'] == score['targets_total'] == manifest['targets_total'] and score['score'] == reward == 1
    assert score['scoring_contract'] == 'borsuk-scientific-milestone-contract-v1'
    phases = score['scientific_phases']; assert set(phases) == {'1','2','3','4','5'}
    assert sum(p['score'] for p in phases.values()) / 5 == score['score'] == 1
    assert len(score['scientific_interfaces']) == 21 and all(x['milestone_eligible'] is True for x in score['scientific_interfaces'].values())
    physical = score['checks']['physical_modules']
    assert physical['checked'] == manifest['expected_Kernel_modules']
    assert physical['changed_or_invalid_modules'] == [] and physical['official_Kernel_replay_algorithm_unchanged'] is True
    assert score['source_manifest'] == {k:v['SHA256'] for k,v in before['files'].items()}
    return physical['checked']
PROBE = "from pathlib import Path\nimport json,os,platform,hashlib,subprocess\nroot=Path('/tests');judge=(root/'test.sh').is_file();project=Path('/home/workspace/borsuk-full-proof-chain')\ncontract=root/'contract/foundation.json'if judge else Path('/opt/public-bootstrap/contract/foundation.json')\nassert json.loads(contract.read_text())['foundation_modules']==[]\nbase=Path('/opt/edgebench-public-base/borsuk-full-proof-chain/base-lib')if judge else project/'base-lib'\nassert base.is_dir()and not any(p.is_file()for p in base.rglob('*'))\nfi={'rows':[],'strict_foundation_object_manifest':{},'actual_empty_foundation_contract':True};objects={}\nf=Path('/tmp/sealed-borsuk-public-mathlib-import.lean');f.write_text(chr(10).join(['import Mathlib','example : (1 : Nat) = 1 := by rfl','']));f.chmod(0o444)\nlp=Path('/opt/public-bootstrap/lean-path.txt');leanpath=lp.read_text().strip()if lp.is_file()else json.loads((root/'runtime-config.json').read_text())['lean_path']\nenv=dict(os.environ,LEAN_SYSROOT='/opt/lean',LEAN_PATH=leanpath)\nuid=int(subprocess.check_output(['/usr/sbin/runuser','-u','agent','--','id','-u'],text=True))\nr=subprocess.run(['/usr/sbin/runuser','-u','agent','--','/opt/lean/bin/lean',str(f)],cwd='/tmp',env=env,capture_output=True,timeout=180)\nassert uid==1500 and r.returncode==0\nexcluded={'native-components.json'}\nprotected={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()and p.name not in excluded and not p.name.endswith(('.native','.ilean','.pyc'))and'.olean'not in p.name and'__pycache__'not in p.parts}if root.exists()else{}\nprint(json.dumps({'architecture':platform.machine(),'uid':os.geteuid(),'cpu_max':Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'memory_max':Path('/sys/fs/cgroup/memory.max').read_text().strip(),'memory_swap_max':Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),'interfaces':sorted(os.listdir('/sys/class/net')),'tests_present':(root/'test.sh').is_file(),'image_owned_checker_present':Path('/opt/grader-source/tests/test.sh').is_file(),'native_components':json.loads((root/'native-components.json').read_text())if(root/'native-components.json').exists()else None,'toolchain_identity':json.loads(Path('/toolchain-identity.json').read_text()),'foundation_identity':fi,'foundation_objects':objects,'actual_empty_foundation_path':str(base),'public_foundation_import':{'uid':uid,'returncode':r.returncode,'source_SHA256':hashlib.sha256(f.read_bytes()).hexdigest(),'stdout_SHA256':hashlib.sha256(r.stdout).hexdigest(),'stderr_SHA256':hashlib.sha256(r.stderr).hexdigest()},'protected_tests':protected}))\n"
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
             'one_fixed_control_attempts': 0, 'payload_manifest': manifest, 'roles': []}
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
        assert platform.machine() == 'x86_64' and len(os.sched_getaffinity(0)) == 4
        command(['docker','info','--format','{{json .}}'], 'docker-info', 60)
        info = json.loads((private/'docker-info.stdout').read_text()); assert info['Architecture'] in ['x86_64','amd64'] and info['NCPU'] == 4
        state['docker_daemon'] = info
        docker_root = Path(info['DockerRootDir']); assert docker_root.is_dir()
        actual_disk = shutil.disk_usage(docker_root)
        state['disk_admission'] = {'DockerRootDir':str(docker_root),'actual_available_bytes':actual_disk.free,
            'required_available_bytes':cfg['minimum_free_disk_bytes'],
            'basis':'12GiB frozen-carrier infrastructure admission floor; current Borsuk AMD64 native images and actual disk use measured, no fit guarantee',
            'passed':actual_disk.free >= cfg['minimum_free_disk_bytes']}; save()
        if not state['disk_admission']['passed']: raise InfrastructureWindowEnd('actual native-builder disk below explicit infrastructure floor; no build or mathematical attempt')
        binfmt = {p.name:p.read_text() for p in Path('/proc/sys/fs/binfmt_misc').glob('*') if p.is_file() and 'qemu' in p.name}
        assert not any('enabled' in v for v in binfmt.values()); state['qemu_binfmt'] = binfmt
        for role, context in [('work','environment'),('judge','tests')]:
            state['stage'] = role+'-native-build'; save()
            command(['docker','build','--platform','linux/amd64','--progress','plain','-t',tags[role],str(private/'payload/bundle/task'/context)], role+'-build', manifest['original_verifier_timeout_sec'])
            command(['docker','image','inspect',tags[role]], role+'-image-inspect', 60)
            image = json.loads((private/(role+'-image-inspect.stdout')).read_text())[0]
            assert image['Architecture'] == 'amd64' and image['Os'] == 'linux' and not image['Config'].get('Entrypoint')
            command(['docker','create','--name',names[role],'--label','edgebench.sealed-run='+run_key,'--network','none','--cpus','4','--memory','16384m','--memory-swap','16384m','--user','root',tags[role],'sleep','infinity'], role+'-create', 60)
            created.append(names[role]); command(['docker','start',names[role]], role+'-start', 60)
            state['stage'] = role+'-native-resource-foundation-probe'; save()
            command(['docker','exec',names[role],'/usr/bin/python3','-I','-c',PROBE], role+'-probe', 240)
            p = json.loads((private/(role+'-probe.stdout')).read_text())
            assert p['architecture'] == 'x86_64' and p['cpu_max'] == '400000 100000' and p['memory_max'] == '17179869184' and p['memory_swap_max'] == '0' and p['interfaces'] == ['lo']
            assert p['toolchain_identity']['architecture'] == 'x86_64' and p['toolchain_identity']['official_release_sha256'] == manifest['official_AMD64_Lean_release_SHA256']
            assert len(p['foundation_identity']['rows']) == manifest['foundation_module_count']
            assert p['tests_present'] == p['image_owned_checker_present'] == (role == 'judge')
            if role == 'judge':
                assert p['native_components']['architecture'] == 'x86_64'
                assert p['protected_tests'] == manifest['expected_judge_protected_tests_SHA256_map']
            command(['docker','inspect',names[role]], role+'-container-inspect', 60)
            ins = json.loads((private/(role+'-container-inspect.stdout')).read_text())[0]; q = ins['HostConfig']
            assert q['Memory'] == q['MemorySwap'] == 17179869184 and q['NanoCpus'] == 4000000000 and q['NetworkMode'] == 'none'
            state['roles'].append({'role':role,'image_Id':image['Id'],'image_RootFS':image['RootFS'],'actual_container_quota':q,'probe':p}); save()
        # Probe containers are not grade environments: close both before the
        # real Harbor pair, avoiding a hidden four-container memory requirement.
        barriers=[]
        for name in list(created):
            removed=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=90,env=safe_env())
            inspected=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=45,env=safe_env())
            assert own_absence(name,set(names.values()),removed,inspected)
            barriers.append({'name':name,'fresh_absent':True});created.remove(name)
        state['pre_entry_two_probe_container_absence_barrier']=barriers;save()
        state['stage']='locked-public-Python-dependency-bootstrap';save()
        venv=private/'checker-venv'
        command(['/usr/bin/python3','-m','venv',str(venv)],'python-venv',120)
        python=str(venv/'bin/python')
        command([python,'-m','pip','install','--disable-pip-version-check','--no-deps','--only-binary=:all:','--index-url','https://pypi.org/simple','--report',str(private/'public-package-install-report.json'),'-r',str(private/'payload/bundle/thin-framework/requirements.lock.txt')],'locked-public-dependencies',1200)
        images={x['role']:x['image_Id']for x in state['roles']};write(private/'actual-probed-images.json',images)
        state['stage']='eight-original-Harbor-and-CloudScorer-entries';state['one_fixed_control_attempts']=1;save()
        command([python,'-I','-B',str(private/'payload/run_eight_entries.py'),'--images',str(private/'actual-probed-images.json'),'--python',python],'eight-original-entries',8*27600)
        results=json.loads((private/'payload/ACTUAL-EIGHT-ORIGINAL-ENTRY-RESULTS.json').read_text())
        assert results['passed']is True and len(results['entries'])==8
        state.update(mathematical_status='complete_valid_full_reference',eight_original_entries=results,two_new_independent_full_Oracle_measurements=2,full_control={'score':1,'eight_entries_not_single_direct_test':True,'original_per_entry_verifier_timeout':21600})
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
            # Only exact scopes belonging to this run; never global docker prune.
            for case in ['nop','integral-lift','topology','oracle']:
                for entry in ['native','periodic']:
                    scope='borsuk-ci-'+os.environ['GITHUB_RUN_ID']+'-'+case+'-'+entry
                    found=subprocess.run(['docker','ps','-aq','--filter','label=edgebench.owner_scope='+scope],capture_output=True,text=True,timeout=60,env=safe_env())
                    assert found.returncode==0
                    for cid in found.stdout.split():
                        ins=subprocess.run(['docker','inspect',cid],capture_output=True,text=True,timeout=45,env=safe_env())
                        exact=json.loads(ins.stdout)[0];assert exact['Config']['Labels']['edgebench.owner_scope']==scope
                        removed=subprocess.run(['docker','rm','-f',cid],capture_output=True,text=True,timeout=90,env=safe_env())
                        gone=subprocess.run(['docker','container','inspect',cid],capture_output=True,text=True,timeout=45,env=safe_env())
                        assert removed.returncode==0 and gone.returncode!=0 and 'No such container'in gone.stderr
                        cleanup.append({'scope':scope,'CID':cid,'fresh_absent':True,'own_only':True})
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
    assert cfg['ready_for_execution'] and cfg['purpose'] == 'native-amd64-two-proper-roles-eight-original-controls'
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
