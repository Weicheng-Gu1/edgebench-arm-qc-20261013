"""Read-only actual Circle machine prerequisite gate; no image create, score or model."""
from pathlib import Path
import argparse,datetime,json,os,platform,shutil,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--python312',type=Path);p.add_argument('--platform',choices=['arm64','amd64'],required=True);a=p.parse_args();assert not a.output.exists();a.output.parent.mkdir(parents=True,exist_ok=True)
cpus=sorted(os.sched_getaffinity(0));mem={x.split(':',1)[0]:int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines()if x.startswith(('MemTotal:','MemAvailable:'))};fs=os.statvfs(a.output.parent);versions=[]
paths=[a.python312,shutil.which('python3.12')]+list((Path.home()/'.pyenv/versions').glob('3.12*/bin/python3.12'));seen=set()
for candidate in paths:
 if not candidate:continue
 q=Path(candidate).resolve()
 if str(q)in seen:continue
 seen.add(str(q));r=subprocess.run([str(q),'-I','-c','import sys,json;print(json.dumps(list(sys.version_info[:3])))'],capture_output=True,text=True,timeout=5)
 if r.returncode==0:
  v=json.loads(r.stdout)
  if v[:2]==[3,12]:versions.append({'path':str(q),'version':v})
checks={'requested_native_architecture':platform.machine()in(('aarch64','arm64')if a.platform=='arm64'else('x86_64','amd64')),'CPU0_3_actual_allowed':set(range(4))<=set(cpus),'four_actual_cores':len(cpus)>=4,'physical_MemTotal_at_least16GiB':mem['MemTotal']>=16*1024**3,'CPython3_12_already_installed':bool(versions),'ordinary64GiB_conservative_buffer':fs.f_bavail*fs.f_frsize>=64*1024**3,'root':os.geteuid()==0}
r=subprocess.run(['docker','version','--format','{{.Server.Version}}'],capture_output=True,text=True,timeout=30);checks['actual_Docker_server_readable']=r.returncode==0
result={'UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Read-only actual prerequisite gate, no kernel policy changes/images/grades/models','passed':all(checks.values()),'checks':checks,'machine':platform.machine(),'actual_CPU_affinity':cpus,'actual_memory_bytes':mem,'ordinary_free_bytes':fs.f_bavail*fs.f_frsize,'CPython3_12_candidates':versions,'Docker_server_version':r.stdout.strip()if r.returncode==0 else None,'Docker_error_class':'read_failure'if r.returncode else None,'no_automatic_interpreter_install_or_policy_fallback':True};a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'checks':checks}));raise SystemExit(0 if result['passed']else 1)
