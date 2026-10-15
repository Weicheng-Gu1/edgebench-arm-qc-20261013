"""One actual OCI multi-platform build per exact Lux role. No grading/model."""
from pathlib import Path
import argparse,datetime,hashlib,json,os,platform,signal,subprocess,tarfile,threading,time,traceback
SOURCE_SHA='167fb02b96360978dfb433ceff3eb7c72d3843a71a304858e13eacfdfe9f835f'
SOURCE_MANIFEST_SHA='6e5a921a649ea346164864b850bf068959006387b51b231624570273782d574d'
BUILDKIT='moby/buildkit@sha256:a38cf64aa6415899097fac5bfcf6c07c95d5a68c67a21e3d254ba398a3c9187f'
BINFMT='tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0'
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
H=lambda p:hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
def save(p,x):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')
class HashingReader:
    def __init__(self,stream):self.stream=stream;self.hasher=hashlib.sha256();self.bytes=0
    def read(self,size=-1):
        data=self.stream.read(size);self.hasher.update(data);self.bytes+=len(data);return data
def validate_OCI_stream(stream):
    reader=HashingReader(stream);members={};index=None;layout=None
    with tarfile.open(fileobj=reader,mode='r|')as tar:
        for member in tar:
            name=member.name.removeprefix('./');p=Path(name)
            assert not p.is_absolute()and'..'not in p.parts,name
            if member.isdir():continue
            assert member.isfile()and name not in members,('nonregular/duplicate',name)
            h=hashlib.sha256();size=0;small=bytearray()if member.size<=8*1024**2 else None
            with tar.extractfile(member)as blob:
                while chunk:=blob.read(8*1024**2):
                    h.update(chunk);size+=len(chunk)
                    if small is not None:small.extend(chunk)
            assert size==member.size
            digest=h.hexdigest()
            if name.startswith('blobs/sha256/'):assert name=='blobs/sha256/'+digest,('blob SHA mismatch',name)
            parsed=None
            if small is not None:
                try:parsed=json.loads(small)
                except(UnicodeDecodeError,json.JSONDecodeError):pass
            members[name]={'bytes':size,'sha256':digest,'json':parsed}
            if name=='index.json':index=parsed
            if name=='oci-layout':layout=parsed
    while reader.read(8*1024**2):pass
    assert layout=={'imageLayoutVersion':'1.0.0'}
    assert isinstance(index,dict)and index.get('schemaVersion')==2
    checked={};platforms=[];configs=[]
    def visit(desc):
        digest=desc['digest'];assert digest.startswith('sha256:')
        member=members['blobs/sha256/'+digest[7:]]
        assert member['bytes']==desc['size']and member['sha256']==digest[7:]
        if digest in checked:return
        media=desc.get('mediaType','');checked[digest]={'bytes':member['bytes'],'mediaType':media}
        if media.endswith(('index.v1+json','manifest.list.v2+json')):
            for child in member['json']['manifests']:visit(child)
        elif media.endswith(('manifest.v1+json','manifest.v2+json')):
            manifest=member['json'];visit(manifest['config'])
            for child in manifest['layers']:visit(child)
            config=members['blobs/sha256/'+manifest['config']['digest'][7:]]['json']
            actual=config['os']+'/'+config['architecture'];platforms.append(actual)
            configs.append({'platform':actual,'config':config,'manifest_digest':digest,'manifest':manifest})
            if 'platform'in desc:assert desc['platform']['os']+'/'+desc['platform']['architecture']==actual
    for desc in index['manifests']:visit(desc)
    assert sorted(platforms)==['linux/amd64','linux/arm64'],platforms
    assert set(name for name in members if name.startswith('blobs/sha256/'))=={'blobs/sha256/'+d[7:]for d in checked},'unreferenced OCI blob'
    return {'index':index,'oci_layout':layout,'all_blob_SHA_and_descriptor_size_verified':True,
            'checked_descriptors':checked,'actual_platforms':platforms,'image_configs':configs,
            'actual_exported_OCI_tar_bytes':reader.bytes,'actual_exported_OCI_tar_SHA256':reader.hasher.hexdigest(),
            'OCI_large_payload_stored_or_uploaded':False,'stored_OCI_payload_bytes':0}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--role',choices=['agent','verifier'],required=True)
    ap.add_argument('--payload',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    p=a.payload.resolve(strict=True);out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    builder='lux-single-multi-r1-'+a.role+'-'+os.environ.get('GITHUB_RUN_ID','local')
    assert platform.machine()=='x86_64','This QEMU build is not an ARM native grade'
    record={'started_utc':NOW(),'role':a.role,'kind':'one_actual_buildx_invocation_both_platforms',
            'source_archive_SHA256':SOURCE_SHA,'native_ARM_grade_claimed':False,'model_calls':0,
            'large_OCI_published_or_delivered':False,'builder':builder,'status':'running','build_invocations':0}
    created=False
    def run(argv,label,timeout=120):
        began=time.monotonic()
        with(out/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        save(out/(label+'.command.json'),{'command':argv,'actual_exit':r.returncode,'wall_seconds':time.monotonic()-began})
        assert r.returncode==0,(label,r.returncode)
    try:
        assert H(p/'source-public-runtime-r5.tar.gz')==SOURCE_SHA
        assert H(p/'source/SOURCE-MANIFEST.json')==SOURCE_MANIFEST_SHA
        full=json.loads((p/'source/SOURCE-MANIFEST.json').read_text())
        context=p/'source/contexts'/a.role
        wanted={n.removeprefix('contexts/'+a.role+'/'):v for n,v in full.items()if n.startswith('contexts/'+a.role+'/')}
        actual={f.relative_to(context).as_posix():{'sha256':H(f),'bytes':f.stat().st_size}for f in context.rglob('*')if f.is_file()}
        assert wanted==actual and not any(f.is_symlink()for f in context.rglob('*'))
        record.update(context_files=len(actual),context_raw_bytes=sum(v['bytes']for v in actual.values()),
                      context_manifest=actual,Dockerfile_SHA256=H(context/'Dockerfile'))
        save(out/'source-binding.json',{k:v for k,v in record.items()if k not in ['status']})
        fs=os.statvfs(out);free=fs.f_bavail*fs.f_frsize
        mem=int(next(s.split()[1]for s in Path('/proc/meminfo').read_text().splitlines()if s.startswith('MemTotal:')))*1024
        save(out/'host-resource-gate.json',{'ordinary_free_bytes':free,'memory_bytes':mem,'host_cpus':os.cpu_count(),
            'memory_limit_bytes':16*1024**3,'aggregate_cpu_quota':4,'supplier_build_buffer_bytes':35*1024**3,
            'buffer_is_not_customer_task_contract':True,'OCI_export_is_streamed':True})
        run(['df','-B1',str(out)],'actual-df-before')
        if free<35*1024**3:
            record.update(status='infrastructure_capacity_not_started',reason='supplier35GiB conservative build buffer unavailable')
            raise RuntimeError(record['reason'])
        assert mem>=15*1024**3 and (os.cpu_count()or 0)>=4
        run(['docker','version'],'actual-docker-version');run(['docker','buildx','version'],'actual-buildx-version')
        run(['docker','run','--privileged','--rm',BINFMT,'--install','arm64'],'pinned-job-only-binfmt',180)
        cfg=out/'buildkitd.toml';cfg.write_text('[worker.oci]\n  max-parallelism = 2\n')
        assert subprocess.run(['docker','buildx','inspect',builder],capture_output=True).returncode!=0,'owned builder name collision'
        created=True
        run(['docker','buildx','create','--name',builder,'--driver','docker-container','--driver-opt','image='+BUILDKIT,
             '--driver-opt','memory=16g','--driver-opt','memory-swap=16g','--driver-opt','cpu-period=100000',
             '--driver-opt','cpu-quota=400000','--driver-opt','network=host','--buildkitd-config',str(cfg),'--bootstrap'],'create-owned-builder',240)
        name='buildx_buildkit_'+builder+'0';inspect=json.loads(subprocess.check_output(['docker','inspect',name]))[0]
        save(out/'actual-owned-builder-inspect.json',inspect);hc=inspect['HostConfig']
        assert hc['Memory']==16*1024**3 and hc['MemorySwap']==16*1024**3 and hc['CpuPeriod']==100000 and hc['CpuQuota']==400000
        cmd=['docker','buildx','build','--builder',builder,'--pull','--no-cache','--platform','linux/amd64,linux/arm64',
             '--provenance=false','--progress','plain','--metadata-file',str(out/'buildx-metadata.json'),
             '--output','type=oci,dest=-','--file',str(context/'Dockerfile'),str(context)]
        began=time.monotonic();started=NOW();timedout=False;error=None;result=None
        def timeout_child(child):
            nonlocal timedout
            timedout=True
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        with(out/'actual-single-multiplatform-build.stderr').open('wb')as log:
            child=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=log,start_new_session=True);record['build_invocations']=1
            timer=threading.Timer(10800,timeout_child,args=(child,));timer.daemon=True;timer.start()
            try:result=validate_OCI_stream(child.stdout)
            except BaseException as exc:error=exc
            finally:
                if error is not None:
                    while child.stdout.read(8*1024**2):pass
                rc=child.wait();timer.cancel()
        save(out/'actual-single-multiplatform-build.command.json',{'command':cmd,'PID':child.pid,'started_utc':started,
            'wall_seconds':time.monotonic()-began,'actual_exit':rc,'outer_timeout':timedout,'OCI_stream_validated':result is not None})
        if error:raise error
        assert rc==0 and not timedout
        save(out/'actual-OCI-validation.json',result)
        assert {f.relative_to(context).as_posix():{'sha256':H(f),'bytes':f.stat().st_size}for f in context.rglob('*')if f.is_file()}==wanted
        record.update(status='completed',actual_exit=0,actual_platforms=result['actual_platforms'],
                      OCI_tar_SHA256=result['actual_exported_OCI_tar_SHA256'],OCI_tar_bytes=result['actual_exported_OCI_tar_bytes'])
    except BaseException as exc:
        if record['status']=='running':record.update(status='failed')
        record.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc());raise
    finally:
        if created:
            cp=subprocess.run(['docker','buildx','rm',builder],capture_output=True,text=True,timeout=180)
            name='buildx_buildkit_'+builder+'0';container=subprocess.run(['docker','inspect',name],capture_output=True,text=True)
            volume=subprocess.run(['docker','volume','inspect',name+'_state'],capture_output=True,text=True)
            record['owned_builder_cleanup']={'actual_exit':cp.returncode,'stdout':cp.stdout,'stderr':cp.stderr,
                'container_absent':container.returncode!=0,'state_volume_absent':volume.returncode!=0}
        record['finished_utc']=NOW();save(out/'report.json',record)
if __name__=='__main__':main()
