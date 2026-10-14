from pathlib import Path
import sys,json,hashlib,platform,os
sys.path.insert(0,str(Path(sys.argv[1])/'scripts'))
from owned_storage import OwnedStorage,measure_readonly,invoke
P=Path(sys.argv[1]);O=Path(sys.argv[2]);O.mkdir(exist_ok=False)
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
assert platform.machine()=='aarch64'and len(os.sched_getaffinity(0))>=4
source=json.loads((P/'package/frozen-manifest.json').read_text())['files'];assert len(source)==400 and all(hashlib.sha256((P/'package'/f).read_bytes()).hexdigest()==d for f,d in source.items())
for role in ['base','agent']:
 tag='edgebench-ariel-public-abi-r3-'+role
 cmd=['docker','build','--platform','linux/arm64','--network=none','--pull=false','-t',tag,'-f',str(P/'recipes'/('base.Dockerfile'if role=='base'else'agent.Dockerfile'))]
 if role=='agent':cmd+=['--build-arg','TOOLCHAIN_IMAGE=edgebench-ariel-public-abi-r3-base']
 cmd+=[str(P/('locked-apt'if role=='base'else'context-agent'))];r=invoke(cmd,1200,check=False);save(O/(role+'-build.json'),r);assert r['returncode']==0
image=json.loads(invoke(['docker','image','inspect','edgebench-ariel-public-abi-r3-agent'])['stdout'])[0];assert image['Architecture']=='arm64'
m=measure_readonly(image['Id'],O/'readonly-agent','linux/arm64')
with OwnedStorage(image['Id'],m,O/'bounded-ABI','linux/arm64')as disk:
 cmd=disk.argv(entrypoint='/bin/sleep');cmd.insert(2,'-d');r=invoke(cmd+['120']);assert r['returncode']==0
 code="set -e; id; uname -m; test ! -e /tests; test ! -e /solution; test ! -r /opt/ariel-private/anchors.json; /opt/ariel-venv/bin/python -c \"import numpy,scipy,taurex,nestle; from importlib.metadata import version; import json; print(json.dumps({k:version(k) for k in ('numpy','scipy','taurex','nestle')},sort_keys=True))\"; mkdir /tmp/compiler-probe; cd /tmp/compiler-probe; printf 'int main(){return 37;}' > helper.cpp; g++ -std=c++17 -O2 helper.cpp -o helper; set +e; ./helper; rc=$?; set -e; test $rc -eq 37; echo ACTUAL_GXX_ELF_EXIT37; dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n'"
 r=invoke(['docker','exec','--user','1500:1500',disk.name,'/bin/bash','-lc',code],120,check=False);save(O/'actual-public-ABI.json',r);assert r['returncode']==0
 version_line=next(x for x in r['stdout'].splitlines()if x.startswith('{'));versions=json.loads(version_line);assert versions=={'numpy':'2.0.2','scipy':'1.14.1','taurex':'3.3.2','nestle':'0.2.1'}
 info=disk.inspect();assert not info['State']['OOMKilled']
assert disk.evidence['destroyed']and disk.evidence['owned_disk_removed']
save(O/'summary.json',{'passed':True,'actual_native_arm':True,'original_source400_exact':True,'versions_actual':versions,'candidate_UID':1500,'set_e_fail_closed':True,'gxx_ELF_exit37_actual':True,'readonly_image':image['Id'],'total_storage_bytes':15*1024**3,'storage':disk.evidence,'model_requests':0,'scope':'Corrected public scientific version/ABI diagnostic only; r2 original13 scoring remains unchanged'})
