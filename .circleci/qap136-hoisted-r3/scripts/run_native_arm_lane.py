"""PREPARED ONLY. Full current QAP source-bound ARM lane; Root dispatch required."""
import argparse,hashlib,json,os,stat,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser();p.add_argument('--payload',type=Path,required=True)
    p.add_argument('--python312',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--include-nop',action='store_true');p.add_argument('--execute',action='store_true')
    a=p.parse_args();assert a.execute and os.geteuid()==0
    src=a.payload.resolve(strict=True);out=a.output.resolve();assert not out.exists();out.mkdir(parents=True)
    python=a.python312.resolve(strict=True);H=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
    manifest=json.loads((src/'SOURCE-PAYLOAD-MANIFEST.json').read_text())
    got={str(q.relative_to(src)):{'SHA256':H(q),'bytes':q.stat().st_size,'mode':stat.S_IMODE(q.stat().st_mode)}for q in src.rglob('*')if q.is_file()and q.name!='SOURCE-PAYLOAD-MANIFEST.json'}
    assert got==manifest['files']and not any(q.is_symlink()for q in src.rglob('*'))
    snapshot=src/'snapshots/hoisted-rank2-delta'
    assert H(snapshot/'home/workspace/qap/submission/main.cpp')=='adb4b97d345fd7eede03e6a4e41f8eecfee369f4252ac95e2a1056cfd61143c2'
    rows=[];report={'status':'RUNNING_NOT_PASS','steps':rows,'no_models':True,'candidate_source_SHA256':H(snapshot/'home/workspace/qap/submission/main.cpp'),'original_T272_F533_unchanged':True,'ARM_timing_not_AMD_noise_equivalence':True}
    def save(): (out/'lane-report.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(argv,label,cwd=out,timeout=2400):
        t=time.monotonic()
        with(out/(label+'.stdout')).open('wb')as so,(out/(label+'.stderr')).open('wb')as se:
            result=subprocess.run([str(v)for v in argv],cwd=cwd,stdout=so,stderr=se,timeout=timeout)
        rows.append({'step':label,'argv':[str(v)for v in argv],'cwd':str(cwd),'exit':result.returncode,'wall_sec':time.monotonic()-t});save();assert result.returncode==0,label
    try:
        run([python,'-I','-c','import sys;assert sys.version_info[:2]==(3,12)'],'check-python',timeout=30)
        run([python,HERE/'preflight_circle_arm.py','--python312',python,'--output',out/'prerequisites.json'],'read-only-preflight',timeout=90)
        run([python,HERE/'build_native_arm_roles.py','--contexts',src/'public-contexts','--source-map',HERE/'ACTUAL-SOURCE-SET-SHA256-r1.json','--output',out/'native-build','--execute'],'build-native-roles',timeout=5100)
        bridge=out/'ARM-deployment';images=out/'native-build/images.json'
        run([python,HERE/'derive_arm_programless_deployment.py','--source-bridge',src/'bridge','--images',images,'--output',bridge],'derive-ARM-source',timeout=90)
        lock=HERE/'arm64-public-host-wheel-metadata-r1/public-wheel-lock-arm64.json';cache=out/'public-wheel-cache'
        run([python,HERE/'download_locked_public_wheels.py','--lock',lock,'--cache',cache,'--output',out/'actual95-body-download.json'],'public-wheel-body-download',timeout=600)
        run([python,HERE/'bootstrap_public_pip_venv.py','--python312',python,'--venv',bridge/'.venv','--lock',HERE/'public-pip-bootstrap-lock.json','--cache',out/'public-pip-cache','--output',out/'actual-full-host-pip-bootstrap.json'],'public-pip-clean-venv-bootstrap',cwd=bridge,timeout=240)
        run([python,bridge/'setup_public.py','--wheel-cache',cache,'--venv',bridge/'.venv'],'offline-clean-host-setup',cwd=bridge,timeout=600)
        py=bridge/'.venv/bin/python'
        run([py,HERE/'fetch_and_verify_public_arm_wheels.py','--lock',lock,'--cache',cache,'--output',out/'actual-wheel-metadata-closure.json'],'wheel-metadata-review',timeout=90)
        run([py,bridge/'package_eval.py','prepare','--task',src/'task','--roles-contexts',src/'public-contexts','--contexts-manifest',src/'CONTEXT-MANIFEST-SHA256.json','--output',bridge/'work'],'source-specific-prepare',cwd=bridge,timeout=90)
        run([py,HERE/'measure_arm_readonly.py','--bridge',bridge,'--images',images,'--contexts',src/'public-contexts','--original-probe-source',src/'bridge/evidence/readonly/original-probe-source.py','--execute'],'fresh-ARM-readonly',cwd=bridge,timeout=600)
        run([py,bridge/'package_eval.py','bind','--deployment',bridge/'work','--images',images,'--footprints',bridge/'footprints.json'],'exact-ARM-bind',cwd=bridge,timeout=90)
        run([py,HERE/'smoke_arm_host_imports.py','--bridge',bridge,'--output',out/'actual-full-host-imports.json'],'actual-real-cwd-full-host-imports',cwd=bridge,timeout=90)
        run([py,bridge/'check_legal_namespace.py','--deployment',bridge/'work','--output',out/'legal-namespace','--execute'],'legal-namespace',cwd=bridge,timeout=600)
        if a.include_nop:
            run([py,bridge/'package_eval.py','score','--deployment',bridge/'work','--entry','native','--snapshot',src/'snapshots/nop','--output',out/'nop-native','--execute'],'optional-native-NOP',cwd=bridge,timeout=3900)
        run([py,bridge/'package_eval.py','score','--deployment',bridge/'work','--entry','native','--snapshot',snapshot,'--output',out/'hoisted-rank2-ARM-native','--execute'],'sample5-ARM-native',cwd=bridge,timeout=3900)
        report['status']='ACTUAL_COMMANDS_COMPLETED_INDEPENDENT_RAW_AND_136_INTEGER_REVIEW_STILL_REQUIRED'
    except BaseException as exc:
        report.update(status='STOPPED_FIRST_FAILURE_NO_RETRY',exception_class=type(exc).__name__)
        raise
    finally:save()
if __name__=='__main__':main()
