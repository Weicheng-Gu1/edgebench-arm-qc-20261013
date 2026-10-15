"""No API credentials: exact public bootstrap, decrypt task, bounded controls, encrypted raw."""
import argparse,datetime,hashlib,json,os,pwd,shutil,stat,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
SECRET='EDGEBENCH_PAINTING_FULL_RECEIVER_R2_KEY'
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--lane',choices=['native-amd64','native-arm64'],required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--work',type=Path,required=True);a=p.parse_args()
    manifest=None;arch=a.lane.split('-')[1];os.umask(0o022);work=a.work.resolve();out=a.output.resolve()
    assert not work.exists()and not out.exists();work.mkdir(mode=0o700,parents=True);out.mkdir(parents=True)
    keyhex=os.environ.pop(SECRET,None);key=None
    cleanenv={n:v for n,v in os.environ.items()if n in ['PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TZ','TMPDIR','DOCKER_HOST','DOCKER_CONTEXT']}
    cleanenv['HARBOR_TELEMETRY']='0';cleanenv['PYTHONDONTWRITEBYTECODE']='1'
    job_revision=os.environ.get('CIRCLE_SHA1');job_number=os.environ.get('CIRCLE_BUILD_NUM')
    selected=work/'selected';selected.mkdir();status={'lane':a.lane,'status':'bootstrap_not_complete','job_commit':job_revision,'job_number':job_number,'model_calls':0,'API_tokens_sent_to_worker_by_publisher':False,'commands':[]}
    current_python=None;code=1
    def public_status():
        fields=['lane','status','stage','job_commit','job_number','model_calls','exception_class','encrypted_evidence','evidence_encryption_failed','encryption_exception_class','evidence_encryption_process','python_candidates_checked']
        public={n:status.get(n)for n in fields}
        if status['commands']:public['last_completed_command']={n:status['commands'][-1].get(n)for n in ['label','exit','stderr_SHA256','stderr_bytes']}
        (out/'public-status.json').write_text(json.dumps(public,indent=2)+'\n')
    status['stage']='initial_stdlib_evidence';public_status()
    def run(argv,label,cwd=work,timeout=2400):
        t=time.monotonic();public_status()
        with(work/(label+'.stdout')).open('wb')as so,(work/(label+'.stderr')).open('wb')as se:r=subprocess.run([str(s)for s in argv],cwd=cwd,env=cleanenv,stdout=so,stderr=se,timeout=timeout)
        status['commands'].append({'label':label,'argv':[str(s)for s in argv],'cwd':str(cwd),'exit':r.returncode,'wall_seconds':time.monotonic()-t,'stderr_SHA256':H(work/(label+'.stderr')),'stderr_bytes':(work/(label+'.stderr')).stat().st_size});public_status();assert r.returncode==0,label
    try:
        status['stage']='task_key_and_source_hashes';public_status();key=bytes.fromhex(keyhex)if keyhex else None;keyhex=None;assert key is not None and len(key)==32,'task_key_missing_or_invalid'
        manifest=json.loads((HERE/'execution-manifest.json').read_text())
        for n,v in manifest['public_files'].items():assert H(HERE/n)==v['SHA256']and(HERE/n).stat().st_size==v['bytes']and not(HERE/n).is_symlink()
        assert H(HERE/'payload.aesgcm')==manifest['ciphertext']['SHA256']
        status['stage']='verify_preinstalled_CPython312_stdlib_venv_no_pip';status['python_candidates_checked']=[];public_status()
        bases=[]
        try:bases.append(Path(pwd.getpwnam('circleci').pw_dir)/'.pyenv/versions')
        except KeyError:pass
        bases.extend([Path.home()/'.pyenv/versions',Path('/opt/circleci/.pyenv/versions')])
        candidates=[q for base in bases for q in sorted(base.glob('3.12*/bin/python3.12'),reverse=True)]+[shutil.which('python3.12')]
        seen=set()
        check_code='import sys,json,venv,ssl,tempfile,pathlib,subprocess;assert sys.version_info[:2]==(3,12);td=tempfile.TemporaryDirectory(prefix=\'esa-venv-prerequisite-\');v=pathlib.Path(td.name)/\'venv\';venv.create(v,with_pip=False);r=subprocess.run([str(v/\'bin/python\'),\'-I\',\'-c\',\'import sys,importlib.util;assert sys.version_info[:2]==(3,12);assert importlib.util.find_spec("pip")is None;print(sys.executable)\'],capture_output=True,text=True);assert r.returncode==0;print(json.dumps({\'version\':list(sys.version_info[:3]),\'stdlib_clean_venv_without_ensurepip\':True}));td.cleanup()'
        for q in candidates:
            if not q:continue
            q=Path(q).resolve()
            if str(q)in seen:continue
            seen.add(str(q))
            test=subprocess.run([str(q),'-I','-c',check_code],env=cleanenv,capture_output=True,timeout=120)
            index=len(status['python_candidates_checked']);(work/('python-candidate-'+str(index)+'.stdout')).write_bytes(test.stdout);(work/('python-candidate-'+str(index)+'.stderr')).write_bytes(test.stderr)
            status['python_candidates_checked'].append({'path':str(q),'fixed_check':'offline_stdlib_venv_without_ensurepip','exit':test.returncode,'stderr_SHA256':hashlib.sha256(test.stderr).hexdigest(),'stderr_bytes':len(test.stderr)})
            public_status()
            if test.returncode==0:current_python=q;break
        assert current_python is not None,'HOLD_no_verified_preinstalled_CPython312_with_stdlib_venv'
        status['stage']='actual_resource_preflight';run([current_python,HERE/'preflight_circle_machine.py','--platform',arch,'--python312',current_python,'--output',work/'prerequisite.json']+(['--supplier-low-memory-host']if arch=='amd64'else[]),'actual-preflight',timeout=90)
        # Three public wheels are enough for the authenticated decryptor. The exact38 controller SDK
        # remains a separate real offline install/import gate inside the native lane.
        status['stage']='public_locked_crypto_bootstrap';lock=json.loads((HERE/('crypto-wheel-lock-'+arch+'.json')).read_text())
        three=[r for r in lock['files']if r['package'].lower()in ['cryptography','cffi','pycparser']];assert len(three)==3
        import urllib.request,urllib.parse
        cache=work/'crypto-public-wheels';cache.mkdir();requirements=[]
        for row in three:
            assert urllib.parse.urlparse(row['url']).hostname=='files.pythonhosted.org'
            with urllib.request.urlopen(row['url'],timeout=90)as response:data=response.read(row['size']+1)
            assert len(data)==row['size']and hashlib.sha256(data).hexdigest()==row['sha256'];(cache/row['wheel']).write_bytes(data)
            requirements.append(row['package']+'=='+row['version']+' --hash=sha256:'+row['sha256'])
        req=work/'crypto-public-requirements.txt';req.write_text('\n'.join(requirements)+'\n')
        run([current_python,HERE/'bootstrap_public_pip_venv.py','--python312',current_python,'--venv',work/'crypto-venv','--lock',HERE/'public-pip-bootstrap-lock.json','--cache',work/'pip-public-cache','--output',work/'actual-crypto-pip-bootstrap.json'],'locked-public-pip-crypto-venv-bootstrap',timeout=240);crypto_python=work/'crypto-venv/bin/python'
        run([crypto_python,'-m','pip','install','--no-index','--find-links',cache,'--require-hashes','-r',req],'locked-public-crypto-install',timeout=180)
        run([crypto_python,'-m','pip','check'],'crypto-pip-check',timeout=30)
        # stdlib worker imports cryptography only through this isolated exact interpreter.
        status['stage']='authenticated_decrypt';taskenv=dict(cleanenv);taskenv[SECRET]=key.hex()
        command=[str(crypto_python),str(HERE/'crypto_action.py'),'decrypt',str(HERE/'payload.aesgcm'),str(work/'decrypted'),'--aad',manifest['source_AAD']]
        with(work/'decrypt.stdout').open('wb')as so,(work/'decrypt.stderr').open('wb')as se:r=subprocess.run(command,env=taskenv,stdout=so,stderr=se,timeout=120)
        taskenv.clear();assert r.returncode==0,'authenticated_source_decrypt';payload=work/'decrypted/payload'
        status['stage']='source_bound_'+a.lane
        source_manifest=payload/'SOURCE-FILES.json';assert H(source_manifest)==manifest['source_payload_manifest_SHA256']
        cleanenv['PAINTING_SOURCE_MANIFEST_SHA256']=manifest['source_payload_manifest_SHA256'];cleanenv['PAINTING_SOURCE_ARCHIVE_SHA256']=manifest['reviewed_source_archive_SHA256']
        run([current_python,payload/'scripts/run_painting_full_receiver_native.py','--payload',payload,'--python312',current_python,'--output',work/'results','--arch',arch,'--native-R-count',('1'if arch=='amd64'else'4'),'--execute'],'native-'+arch+'-fullScorer-native-periodic-four-fixtures',timeout=10800)
        status['status']='commands_completed_independent_raw_review_required';code=0
    except BaseException as exc:
        status.update(status='STOPPED_FIRST_FAILURE_NO_RETRY',exception_class=type(exc).__name__,failure_summary=str(exc)[:180]);public_status()
    finally:
        public_status()
        # Select ordinary small raw evidence; never include source task/venvs/wheels,
        # live filesystem images, OCI or keys. Preserve failure logs as well as success.
        forbidden={'.venv','crypto-venv','native-venv','public-wheel-cache','crypto-public-wheels','pip-public-cache','decrypted','framework','controller','public-wheel-cache','assembled-public-cache'}
        for f in work.rglob('*'):
            if not f.is_file()or f.is_symlink()or selected in f.parents:continue
            rel=f.relative_to(work)
            if set(rel.parts)&forbidden:continue
            if 'deployment/task'in str(rel)and f.name!='task.toml':continue
            if f.suffix.lower()not in ['.json','.jsonl','.log','.stdout','.stderr','.txt','.tsv','.iid','.toml','.diff']:continue
            if f.stat().st_size>32*1024**2:raise RuntimeError('raw_evidence_member_unexpectedly_large')
            dest=selected/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,dest)
        status['new_task_plaintext_in_public_artifacts']=False
        (selected/'worker-status.json').write_text(json.dumps(status,indent=2)+'\n')
        files={str(f.relative_to(selected)):{'SHA256':H(f),'bytes':f.stat().st_size,'mode':stat.S_IMODE(f.stat().st_mode)}for f in sorted(selected.rglob('*'))if f.is_file()}
        (selected/'EVIDENCE-MANIFEST.json').write_text(json.dumps({'files':files,'job_commit':job_revision,'lane':a.lane},indent=2)+'\n')
        if key is not None and current_python is not None and(work/'crypto-venv/bin/python').exists():
            e=dict(cleanenv);e[SECRET]=key.hex();aad=manifest['result_AAD_prefix']+'/'+a.lane+'/'+str(job_revision)
            try:
                r=subprocess.run([str(work/'crypto-venv/bin/python'),str(HERE/'crypto_action.py'),'encrypt',str(selected),str(out/'result.aesgcm'),'--aad',aad],env=e,capture_output=True,timeout=120)
                status['evidence_encryption_process']={'exit':r.returncode,'stdout_SHA256':hashlib.sha256(r.stdout).hexdigest(),'stderr_SHA256':hashlib.sha256(r.stderr).hexdigest(),'stdout_bytes':len(r.stdout),'stderr_bytes':len(r.stderr)}
                if r.returncode==0:
                    status['encrypted_evidence']={'SHA256':H(out/'result.aesgcm'),'bytes':(out/'result.aesgcm').stat().st_size,'AAD':aad}
                else:
                    status['encrypted_evidence']=None;status['evidence_encryption_failed']=True;code=1
            except BaseException as enc:
                status['encrypted_evidence']=None;status['evidence_encryption_failed']=True;status['encryption_exception_class']=type(enc).__name__;code=1
            finally:e.clear()
        else:
            status['encrypted_evidence']=None
        # Always preserve non-sensitive primary evidence, even when cryptography failed.
        if(work/'prerequisite.json').exists():shutil.copy2(work/'prerequisite.json',out/'prerequisite.json')
        public_status();key=None
    print(json.dumps({'lane':a.lane,'status':status['status'],'encrypted_evidence':status.get('encrypted_evidence')is not None}))
    raise SystemExit(code)
if __name__=='__main__':main()
