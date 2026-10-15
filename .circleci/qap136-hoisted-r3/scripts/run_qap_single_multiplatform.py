"""PREPARED ONLY. One source-bound OCI streaming build/role; no grader or model."""
from pathlib import Path
import argparse,datetime,hashlib,json,os,platform,re,signal,stat,subprocess,threading,time,uuid
from oci_stream_validator import validate_OCI_stream
P=argparse.ArgumentParser();P.add_argument('--role',choices=['agent','verifier'],required=True);P.add_argument('--context',type=Path,required=True);P.add_argument('--source-map',type=Path,required=True);P.add_argument('--output',type=Path,required=True);P.add_argument('--execute',action='store_true');a=P.parse_args();assert a.execute,'Root authorization plus explicit execute required';assert not a.output.exists();a.output.mkdir(parents=True)
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();save=lambda n,x:(a.output/n).write_text(json.dumps(x,indent=2)+'\n');now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
wanted={n.removeprefix(a.role+'/'):v for n,v in json.loads(a.source_map.read_text())['public-contexts']['files'].items()if n.startswith(a.role+'/')};actual={str(p.relative_to(a.context)):{'SHA256':H(p),'bytes':p.stat().st_size,'mode':stat.S_IMODE(p.stat().st_mode)}for p in a.context.rglob('*')if p.is_file()};assert actual==wanted and not any(p.is_symlink()for p in a.context.rglob('*'))
assert platform.machine()in['aarch64','arm64','x86_64'];fs=os.statvfs(a.output);mem=int(next(s.split()[1]for s in Path('/proc/meminfo').read_text().splitlines()if s.startswith('MemTotal:')))*1024;assert mem>=15*1024**3 and len(os.sched_getaffinity(0))>=4 and fs.f_bavail*fs.f_frsize>=35*1024**3
builder=('qap136-single-multi-'+a.role+'-'+uuid.uuid4().hex[:12]).lower();name='buildx_buildkit_'+builder+'0';volume=name+'_state';created=False;record={'status':'running','started_utc':now(),'role':a.role,'context_manifest':actual,'context_manifest_source_SHA256':H(a.source_map),'builder':builder,'single_buildx_both_platforms':True,'worker_CPU':4,'worker_memory_bytes':16*1024**3,'QEMU_build_only_not_native_grade':True,'model_calls':0}
def run(argv,label,timeout=180):
 t=time.monotonic()
 with(a.output/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
 save(label+'.command.json',{'argv':argv,'exit':r.returncode,'wall_seconds':time.monotonic()-t});assert r.returncode==0,(label,r.returncode)
try:
 run(['docker','version'],'docker-version');run(['docker','buildx','version'],'buildx-version');other='amd64'if platform.machine()in['aarch64','arm64']else'arm64';run(['docker','run','--rm','--privileged','tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0','--install',other],'own-CI-job-binfmt')
 cfg=a.output/'buildkitd.toml';cfg.write_text('[worker.oci]\n max-parallelism = 2\n');assert subprocess.run(['docker','buildx','inspect',builder],capture_output=True).returncode!=0;created=True
 run(['docker','buildx','create','--name',builder,'--driver','docker-container','--driver-opt','image=moby/buildkit@sha256:a38cf64aa6415899097fac5bfcf6c07c95d5a68c67a21e3d254ba398a3c9187f','--driver-opt','memory=16g','--driver-opt','memory-swap=16g','--driver-opt','cpu-period=100000','--driver-opt','cpu-quota=400000','--driver-opt','network=host','--buildkitd-config',str(cfg),'--bootstrap'],'create-owned-builder',300)
 inspect=json.loads(subprocess.check_output(['docker','inspect',name]));save('actual-builder-inspect.json',inspect);h=inspect[0]['HostConfig'];assert h['Memory']==h['MemorySwap']==16*1024**3 and h['CpuPeriod']==100000 and h['CpuQuota']==400000
 argv=['docker','buildx','build','--builder',builder,'--pull','--no-cache','--platform','linux/amd64,linux/arm64','--provenance=false','--progress','plain','--metadata-file',str(a.output/'buildx-metadata.json'),'--output','type=oci,dest=-','--file',str(a.context/'Dockerfile'),str(a.context)];save('build-command.json',{'argv':argv,'started_utc':now()});t=time.monotonic()
 with(a.output/'build.stderr').open('wb')as err:
  child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=err,start_new_session=True);timer=threading.Timer(2400,lambda:os.killpg(child.pid,signal.SIGKILL)if child.poll()is None else None);timer.start()
  try:record['OCI']=validate_OCI_stream(child.stdout);code=child.wait(timeout=60);assert code==0
  finally:
   timer.cancel()
   if child.poll()is None:child.kill();child.wait()
 record.update(status='actual_both_platforms_stream_verified',build_exit=code,actual_build_wall_seconds=time.monotonic()-t)
finally:
 if created:
  r=subprocess.run(['docker','buildx','rm','--force',builder],capture_output=True,text=True,timeout=180);(a.output/'remove-builder.stdout').write_text(r.stdout);(a.output/'remove-builder.stderr').write_text(r.stderr);ci=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=30);vi=subprocess.run(['docker','volume','inspect',volume],capture_output=True,text=True,timeout=30);bi=subprocess.run(['docker','buildx','inspect',builder],capture_output=True,text=True,timeout=30);save('actual-lowercase-owned-cleanup.json',{'builder':builder,'container':name,'volume':volume,'rm_exit':r.returncode,'container_exit':ci.returncode,'container_stderr':ci.stderr,'volume_exit':vi.returncode,'volume_stderr':vi.stderr,'builder_exit':bi.returncode,'all_absent':all(x.returncode!=0 for x in [ci,vi,bi])});assert r.returncode==0 and all(x.returncode!=0 for x in [ci,vi,bi])
 record['finished_utc']=now();save('report.json',record)
print(json.dumps({'status':record['status'],'role':a.role,'platforms':record['OCI']['actual_platforms']}))
