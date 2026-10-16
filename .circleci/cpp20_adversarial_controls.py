"""Trusted control driver, executed only inside the task's cloud verifier."""
from pathlib import Path
import hashlib,json,os,sys,tempfile,subprocess
sys.path.insert(0,'/tests')
from operation_grader import grade
from sandbox import compile_sources,execute,restricted
out=Path('/logs/verifier');out.mkdir(parents=True,exist_ok=True)
rows=[]
def write(directory,source):
    directory.mkdir(parents=True);directory.chmod(0o755)
    (directory/'main.cpp').write_text(source);(directory/'main.cpp').chmod(0o644)
    return directory
with tempfile.TemporaryDirectory(prefix='cpp20-author-controls-') as folder:
    root=Path(folder);root.chmod(0o755)
    for mode in ['always_reject','always_accept_empty']:
        answer='J{{"accepted",false}}' if mode=='always_reject' else 'J{{"accepted",true},{"stdout",""},{"exit_code",0}}'
        source='#include "json.hpp"\n#include <iostream>\nusing J=nlohmann::json;int main(){J in;std::cin>>in;J out;out["results"]=J::array();for(auto& c:in["cases"])out["results"].push_back('+answer+');std::cout<<out.dump();}\n'
        directory=write(root/mode,source)
        result=grade(directory,'/tests/private','/tests/json.hpp',out/mode)
        assert result['valid'] and result['build']['status']=='compiled' and result['score']==0
        if mode=='always_reject':assert 0<result['pass_rate']<1
        rows.append({'control':mode,'score':result['score'],'raw_case_pass_rate':result['pass_rate'],
                     'actual_compiled':True,'passed':True})
    attack=r'''#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
int main(){FILE* a=fopen("/tests/private/corpus.json","rb");FILE* b=fopen("/logs/verifier/forbidden-write","wb");
bool private_read=a!=nullptr,reward_write=b!=nullptr;if(a)fclose(a);if(b)fclose(b);
bool compiler_access=access("/usr/bin/g++",X_OK)==0;int p=fork();if(p==0)_exit(0);if(p>0)waitpid(p,nullptr,0);
int command=system("/usr/bin/g++ --version >/tmp/compiler-out 2>/tmp/compiler-err");
printf("{\"private_read\":%s,\"reward_write\":%s,\"compiler_access\":%s,\"fork_denied\":%s,\"external_compiler_command_failed\":%s}",private_read?"true":"false",reward_write?"true":"false",compiler_access?"true":"false",p<0?"true":"false",command!=0?"true":"false");}
'''
    directory=write(root/'runtime-boundary',attack)
    binary,build=compile_sources(directory,'/tests/json.hpp',root/'boundary-build');assert binary and build['status']=='compiled'
    raw,measurement=execute(binary,b'',root,10)
    report=json.loads(raw)
    assert measurement['status']=='completed' and report=={'private_read':False,'reward_write':False,'compiler_access':False,'fork_denied':True,'external_compiler_command_failed':True}
    rows.append({'control':'actual_runtime_private_reward_and_external_compiler_boundaries','actual_observation':report,'measurement':measurement,'passed':True})
    # Use a valid assembler directive; compile failure must be private-file denial.
    source=r'''asm(".incbin \"/tests/private/corpus.json\"\n");
int main(){return 0;}
'''
    (out/'completed-before-compile-probe.json').write_text(json.dumps(rows,indent=2))
    directory=write(root/'compile-private-path',source)
    binary,build=compile_sources(directory,'/tests/json.hpp',root/'compile-private-build')
    diagnostic='\n'.join(p.read_text(errors='replace') for p in (root/'compile-private-build').glob('compile-*.log'))
    (out/'compile-private-denial.log').write_text(diagnostic)
    assert binary is None and build['status']=='compile_failure'
    assert '/tests/private/corpus.json' in diagnostic
    # GNU assembler may report EACCES as "file not found". Establish both a
    # valid identical directive and actual EACCES under the compilation UID.
    marker=root/'public-marker.bin';marker.write_bytes(b'author-public-compile-control');marker.chmod(0o644)
    positive_source=source.replace('/tests/private/corpus.json',str(marker))
    directory=write(root/'compile-public-path',positive_source)
    positive_binary,positive_build=compile_sources(directory,'/tests/json.hpp',root/'compile-public-build')
    assert positive_binary and positive_build['status']=='compiled','Public directive control must really compile'
    checker="import json;from pathlib import Path;\ntry:\n f=open('/tests/private/corpus.json','rb');f.close();print(json.dumps({'errno':0}))\nexcept OSError as e: print(json.dumps({'errno':e.errno}))"
    denied=subprocess.run(['/usr/bin/python3','-I','-c',checker],capture_output=True,text=True,timeout=10,preexec_fn=lambda:restricted(cpu=5))
    assert denied.returncode==0 and json.loads(denied.stdout)=={'errno':13},'Actual compilation UID must receive EACCES'
    rows.append({'control':'identical_public_incbin_positive_and_private_compile_UID_EACCES','public_build':positive_build,'private_open_errno':13,'passed':True})
    rows.append({'control':'actual_unprivileged_compilation_private_incbin_denied','build':build,'private_file_permission_denial_observed':True,'passed':True})
report={'kind':'actual_Cpp20_score_shortcuts_and_compiler_runtime_isolation_controls',
        'passed':all(x['passed'] for x in rows),'rows':rows,'model_calls':0,
        'all_controls_executed_inside_cloud_verifier':True,
        'universal_originality_claimed':False,'full_delivery_pass':False}
(out/'adversarial-controls.json').write_text(json.dumps(report,indent=2))
print(json.dumps({'passed':report['passed'],'controls':len(rows)}))
