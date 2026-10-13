import argparse,json,platform,sys,hashlib,time,subprocess,os
from pathlib import Path
import owned_storage as s
ap=argparse.ArgumentParser();ap.add_argument('--payload-root',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--image');a=ap.parse_args();P=a.payload_root.resolve();O=a.output.resolve();O.mkdir(parents=True,exist_ok=False);arch='arm64'if platform.machine()=='aarch64'else'amd64';platform_name='linux/'+arch
if a.image:image=a.image
else:
 tag='edgebench-nle-world-diagnostic:'+str(os.getpid());cmd=['docker','build','--platform',platform_name,'-t',tag,str(P/'task/tests')]
 with (O/'build.log').open('wb')as log:
  p=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  try:rc=p.wait(timeout=3600)
  except BaseException:os.killpg(p.pid,9);p.wait();raise
 if rc:raise RuntimeError('Diagnostic native build failed')
 image=json.loads(s.invoke(['docker','image','inspect',tag])['stdout'])[0]['Id']
measurement=s.measure_readonly(image,O/'measurement',platform_name)
with s.OwnedStorage(image,measurement,O/'storage',platform_name)as own:
 execution=s.invoke(own.argv([(P/'scripts/fixed_world.py','/opt/fixed_world.py')],entrypoint='/opt/nethack-env/bin/python')+['-B','-I','/opt/fixed_world.py'],300,check=False);actual=own.inspect();own.export_logs(O/'logs');report={'execution':execution,'state':actual['State'],'image':image,'actual_policy':actual['HostConfig'],'world':json.loads((O/'logs/fixed-world.json').read_text())if(O/'logs/fixed-world.json').exists()else None,'model_requests':0,'credentials_injected':False}
report['cleanup']=json.loads((O/'storage/lifecycle.json').read_text());(O/'report.json').write_text(json.dumps(report,indent=2));assert execution['returncode']==0 and report['cleanup']['destroyed']and report['cleanup']['owned_disk_removed'];print('world probe native complete',arch)
