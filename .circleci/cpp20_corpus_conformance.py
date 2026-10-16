"""Trusted authored-program conformance, separate from any solver or Oracle grade."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,platform,subprocess,tempfile
assert platform.machine()=='aarch64'
out=Path('/logs/verifier');out.mkdir(parents=True,exist_ok=True)
corpus=json.loads(Path('/tests/private/corpus.json').read_text())
cases=[case for group in corpus['groups'] for case in group['cases']]
def one(item):
    index,case=item
    with tempfile.TemporaryDirectory(prefix='trusted-authored-cpp20-') as folder:
        root=Path(folder);source=root/'input.cpp';source.write_text(case['source']);binary=root/'program'
        command=['/usr/bin/g++','-std=c++20','-pedantic-errors','-O2',str(source)]
        command+=['-o',str(binary)] if case['expected_compile'] else ['-fsyntax-only']
        result=subprocess.run(command,capture_output=True,timeout=90)
        (out/f'compile-{index}.log').write_bytes(result.stderr)
        row={'index':index,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compile_exit':result.returncode,'expected_compile':case['expected_compile']}
        if case['expected_compile'] and result.returncode==0:
            executed=subprocess.run([str(binary)],capture_output=True,timeout=5)
            row.update(run_exit=executed.returncode,stdout=executed.stdout.decode(),stderr=executed.stderr.decode())
            row['passed']=executed.returncode==0 and executed.stdout.decode()==case['expected_stdout'] and not executed.stderr
        else:
            row['passed']=not case['expected_compile'] and result.returncode==1 and b'error:' in result.stderr and b'file not found' not in result.stderr
        (out/f'case-{index}.json').write_text(json.dumps(row,indent=2))
        return row
with ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(one,enumerate(cases)))
report={'kind':'actual_native_ARM_authored_Cpp20_corpus_conformance','passed':all(r['passed'] for r in rows),
        'cases':len(rows),'groups':len(corpus['groups']),'actual_compilations':len(rows),
        'actual_executions':sum('run_exit' in r for r in rows),'actual_native_host_machine':platform.machine(),
        'compiler_version':subprocess.check_output(['/usr/bin/g++','--version'],text=True).splitlines()[0],
        'author_comparison_only_not_a_candidate_or_Oracle':True,'rows':rows,'model_calls':0,'full_delivery_pass':False}
(out/'report.json').write_text(json.dumps(report,indent=2))
assert report['passed'],'Inspect actual native corpus failures in encrypted artifacts'
