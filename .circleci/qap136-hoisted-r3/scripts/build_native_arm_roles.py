"""Not executed. Source-bound native ARM image build, own bounded worker only."""
import argparse,datetime,hashlib,json,os,platform,stat,subprocess,time,uuid
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--contexts',type=Path,required=True)
    p.add_argument('--source-map',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--execute',action='store_true');a=p.parse_args()
    assert a.execute and os.geteuid()==0 and platform.machine()in('aarch64','arm64')
    assert not a.output.exists();a.output.mkdir(parents=True)
    H=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
    files=json.loads(a.source_map.read_text())['public-contexts']['files']
    actual={str(f.relative_to(a.contexts)):{'SHA256':H(f),'bytes':f.stat().st_size,'mode':stat.S_IMODE(f.stat().st_mode)}for f in a.contexts.rglob('*')if f.is_file()}
    assert actual==files and not any(f.is_symlink()for f in a.contexts.rglob('*'))
    name='qap136-native-arm-'+uuid.uuid4().hex[:12];container='buildx_buildkit_'+name+'0';volume=container+'_state'
    save=lambda n,x:(a.output/n).write_text(json.dumps(x,indent=2)+'\n')
    def run(argv,label,timeout=180):
        t=time.monotonic()
        with(a.output/(label+'.log')).open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        save(label+'.command.json',{'argv':argv,'exit':r.returncode,'wall_sec':time.monotonic()-t});assert r.returncode==0,label
    assert subprocess.run(['docker','buildx','inspect',name],capture_output=True).returncode!=0
    cfg=a.output/'buildkitd.toml';cfg.write_text('[worker.oci]\n max-parallelism = 1\n');images={}
    try:
        run(['docker','buildx','create','--name',name,'--driver','docker-container','--driver-opt','image=moby/buildkit@sha256:a38cf64aa6415899097fac5bfcf6c07c95d5a68c67a21e3d254ba398a3c9187f','--driver-opt','memory=16g','--driver-opt','memory-swap=16g','--driver-opt','cpu-period=100000','--driver-opt','cpu-quota=400000','--driver-opt','network=host','--buildkitd-config',str(cfg),'--bootstrap'],'create',300)
        v=json.loads(subprocess.check_output(['docker','inspect',container]))[0];save('builder-inspect.json',v);h=v['HostConfig']
        assert h['Memory']==h['MemorySwap']==16*1024**3 and h['CpuQuota']==400000 and h['CpuPeriod']==100000
        for role in ['agent','verifier']:
            ctx=a.contexts/role;iid=a.output/(role+'.iid')
            run(['docker','buildx','build','--builder',name,'--pull','--no-cache','--platform','linux/arm64','--load','--iidfile',str(iid),'--file',str(ctx/'Dockerfile'),str(ctx)],role+'-build',2400)
            image=iid.read_text().strip();v=json.loads(subprocess.check_output(['docker','image','inspect',image]))[0]
            assert v['Id']==image and v['Architecture']=='arm64'and v['Os']=='linux'
            save(role+'-image-inspect.json',v);images[role]={'image_id':image,'architecture':'arm64','source_manifest_SHA256':H(a.source_map)}
        assert len({x['image_id']for x in images.values()})==2;save('images.json',images)
    finally:
        r=subprocess.run(['docker','buildx','rm','--force',name],capture_output=True,text=True,timeout=180)
        (a.output/'remove.stdout').write_text(r.stdout);(a.output/'remove.stderr').write_text(r.stderr)
        checks={}
        for kind,item in [('container',container),('volume',volume),('builder',name)]:
            argv=['docker','buildx','inspect',item]if kind=='builder'else['docker',kind if kind=='volume'else'container','inspect',item]
            z=subprocess.run(argv,capture_output=True,text=True,timeout=30);checks[kind]={'name':item,'exit':z.returncode,'stderr':z.stderr}
        save('owned-cleanup.json',{'remove_exit':r.returncode,'checks':checks,'all_absent':all(x['exit']!=0 for x in checks.values())})
        assert r.returncode==0 and all(x['exit']!=0 for x in checks.values())
    print(json.dumps({'native_ARM_roles_built':2,'images':images,'models':0}))
if __name__=='__main__':main()
