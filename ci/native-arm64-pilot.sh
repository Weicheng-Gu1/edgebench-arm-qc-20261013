#!/usr/bin/env bash
set -euo pipefail
umask 077
mkdir -p evidence
IMAGE='docker.io/library/alpine@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412'
date -u +%Y-%m-%dT%H:%M:%SZ > evidence/started-utc.txt
sha256sum ci/native-arm64-pilot.sh .circleci/config.yml > evidence/executed-source-sha256.txt
uname -a > evidence/host-uname.txt
lscpu > evidence/host-lscpu.txt
cat /proc/meminfo > evidence/host-meminfo.txt
python3 - <<'PY'
from pathlib import Path
import datetime,json,os,platform
root=Path('/proc/sys/fs/binfmt_misc')
handlers={p.name:p.read_text()for p in root.iterdir()if p.is_file()and p.name not in ['register','status']}if root.is_dir()else{}
active_qemu={n:s for n,s in handlers.items()if 'qemu'in(n+s).lower()and s.startswith('enabled')}
r={'UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'uname_machine':platform.machine(),'effective_affinity_CPUs':len(os.sched_getaffinity(0)),'MemTotal_kB':int(Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),'binfmt_misc_handlers':handlers,'active_QEMU_binfmt_handlers':active_qemu,'resource_class_requested':'arm.large','machine_image_requested':'ubuntu-2204:2026.05.1','scope':'Native ARM64 machine/Docker admission pilot; no model, Lean build, or mathematical score.'}
Path('evidence/host-native-arm64.json').write_text(json.dumps(r,indent=2)+'\n')
assert r['uname_machine']=='aarch64',r['uname_machine']
assert r['effective_affinity_CPUs']==4,r['effective_affinity_CPUs']
assert r['MemTotal_kB']>=14*1024*1024,r['MemTotal_kB']
assert not active_qemu,'QEMU binfmt handler enabled; native-only pilot refuses'
PY
docker version --format '{{json .}}' > evidence/docker-version.json
docker info --format '{"Architecture":"{{.Architecture}}","OSType":"{{.OSType}}","NCPU":{{.NCPU}},"MemTotal":{{.MemTotal}},"KernelVersion":"{{.KernelVersion}}","OperatingSystem":"{{.OperatingSystem}}"}' > evidence/docker-daemon.json
timeout --signal=TERM --kill-after=10s 180 docker pull --platform linux/arm64 "$IMAGE" > evidence/docker-pull.stdout 2> evidence/docker-pull.stderr
docker image inspect "$IMAGE" > evidence/pinned-image-inspect.json
timeout --signal=TERM --kill-after=10s 60 docker run --rm --platform linux/arm64 --network none --pids-limit 64 --read-only --cpus 1 --memory 128m --cap-drop ALL --security-opt no-new-privileges "$IMAGE" /bin/sh -eu -c 'uname -m; uname -a; sha256sum /bin/busybox; cat /etc/alpine-release; printf "NATIVE_ARM64_CONTAINER_EXECUTED_SUCCESSFULLY\n"' > evidence/container-output.txt 2> evidence/container-stderr.txt
python3 - <<'PY'
from pathlib import Path
import datetime,hashlib,json
d=Path('evidence');host=json.loads((d/'host-native-arm64.json').read_text());daemon=json.loads((d/'docker-daemon.json').read_text());image=json.loads((d/'pinned-image-inspect.json').read_text());output=(d/'container-output.txt').read_text()
assert daemon['Architecture']in['aarch64','arm64']and daemon['OSType']=='linux'
assert daemon['NCPU']==4 and daemon['MemTotal']>=14*1024**3
assert len(image)==1 and image[0]['Architecture']=='arm64'and image[0]['Os']=='linux'
assert output.splitlines()[0]=='aarch64'and'NATIVE_ARM64_CONTAINER_EXECUTED_SUCCESSFULLY'in output
index='sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412'
assert any(index in x for x in image[0]['RepoDigests'])
r={'UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,'scope':'Native ARM64 CircleCI machine and real linux/arm64 Docker execution only; not Lean score, Oracle, full task ARM control, or Aliyun resource equivalence.','host':host,'daemon':daemon,'container_image_architecture':image[0]['Architecture'],'container_uname':output.splitlines()[0],'public_multiarch_index_digest':index,'QEMU_or_emulator_used':False,'container_network':'none','models':0,'Lean_or_Oracle_runs':0,'source_and_raw_files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(d.iterdir())if p.is_file()}}
(d/'native-arm64-pilot-receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'native_ARM64_pilot_passed':True,'host_machine':host['uname_machine'],'host_CPUs':host['effective_affinity_CPUs'],'host_MemTotal_kB':host['MemTotal_kB'],'Docker_architecture':daemon['Architecture'],'container_architecture':'arm64','container_uname':'aarch64','mathematical_score_claimed':False}))
PY
