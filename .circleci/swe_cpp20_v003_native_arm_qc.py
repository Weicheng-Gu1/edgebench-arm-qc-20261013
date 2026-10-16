"""Source-built frozen C++ task and actual native ARM tests; private data encrypted."""
from pathlib import Path
import datetime,hashlib,json,os,platform,shutil,subprocess,tarfile,urllib.request
assert platform.machine()=='aarch64'
root=Path('/tmp/swe-cpp20-v003-native-arm-private-r1');root.mkdir(mode=0o700)
public=Path('/tmp/swe-cpp20-v003-native-arm-public-r1');public.mkdir()
key=root/'transport-key';key.write_text(os.environ['SWE_CPP20_V3_QC_KEY_R1']);key.chmod(0o600)
def run(argv,log,timeout=1800):
    with (root/log).open('wb') as f:p=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
    assert p.returncode==0,'Inspect encrypted details for '+log
report={'scope':'Frozen C++20 native ARM task grading, corpus conformance and isolation',
        'passed':False,'model_calls':0,'full_delivery_pass':False,'actual_native_host_machine':platform.machine(),
        'job_url':os.environ.get('CIRCLE_BUILD_URL'),'revision':os.environ.get('CIRCLE_SHA1'),
        'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
try:
    encrypted=root/'payload.enc'
    with urllib.request.urlopen(os.environ['SWE_CPP20_V3_QC_PAYLOAD_URL_R1'],timeout=120) as src,encrypted.open('wb') as dst:shutil.copyfileobj(src,dst)
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest()==os.environ['SWE_CPP20_V3_QC_PAYLOAD_SHA256_R1']
    run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-md','sha256','-in',str(encrypted),'-out',str(root/'payload.tar.gz'),'-pass','file:'+str(key)],'decrypt.log',120)
    with tarfile.open(root/'payload.tar.gz') as t:t.extractall(root/'payload',filter='data')
    payload=root/'payload';task=payload/'task';manifest=json.loads((payload/'manifest.json').read_text())
    hashes={str(p.relative_to(task)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(task.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
    assert hashes==manifest['task_hashes'];report['frozen_task_hashes_verified']=True
    image='swe-cpp20-v003-native-arm-qc:20261016-r1'
    run(['docker','build','--platform','linux/arm64','--network=none','-t',image,str(task/'verifier')],'actual-grader-source-build.log',1800)
    info=json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
    assert info['Architecture']=='arm64';report['actual_grader_image_architecture']=info['Architecture'];report['actual_grader_image_id']=info['Id']
    common=['docker','run','--rm','--platform','linux/arm64','--network','none','--cpus','4','--memory','16g','--memory-swap','16g','--read-only','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=4g']
    for name,script in [('corpus-conformance','cpp20_corpus_conformance.py'),('adversarial-controls','cpp20_adversarial_controls.py')]:
        directory=root/name;directory.mkdir(mode=0o700);driver=Path('.circleci')/script
        run(common+['-v',str(driver.resolve())+':/trusted-author-check.py:ro','-v',str(directory)+':/logs/verifier:rw','--entrypoint','/usr/bin/python3',image,'/trusted-author-check.py'],name+'.log',1800)
        actual=json.loads((directory/('report.json' if name=='corpus-conformance' else 'adversarial-controls.json')).read_text())
        assert actual['passed'];report[name]={k:v for k,v in actual.items() if k!='rows'}
    grades={}
    for name,expected in [('partial-a',3/68),('partial-b',1/68),('empty',0.)]:
        directory=root/name;directory.mkdir(mode=0o700)
        run(common+['-v',str(payload/name)+':/home/workspace/swe-cpp20-frontend/submission:ro','-v',str(directory)+':/logs/verifier:rw','--entrypoint','/bin/sh',image,'/tests/test.sh'],name+'.log',1800)
        actual=json.loads((directory/'score.json').read_text());native=float((directory/'reward.txt').read_text())
        assert actual['valid'] and abs(actual['score']-expected)<1e-12 and native==actual['score']
        grades[name]={'score':native,'pass_rate':actual['pass_rate'],'submission_sha256':actual['submission_sha256'],'native_reward_parity':True}
    report.update(passed=True,actual_grades=grades)
finally:
    report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    (root/'public-report.json').write_text(json.dumps(report,indent=2));(public/'report.json').write_text(json.dumps(report,indent=2))
    archive=root/'results.tar.gz'
    with tarfile.open(archive,'w:gz') as t:
        for p in root.iterdir():
            if p.name not in ['transport-key','payload.enc','payload.tar.gz','results.tar.gz','payload']:t.add(p,arcname=p.name)
    run(['openssl','enc','-aes-256-cbc','-salt','-pbkdf2','-iter','200000','-md','sha256','-in',str(archive),'-out',str(public/'details.enc'),'-pass','file:'+str(key)],'encrypt-results.log',120)
    key.unlink(missing_ok=True)
    print(json.dumps({'passed':report['passed'],'scope':report['scope'],'job_url':report['job_url']}))
assert report['passed']
