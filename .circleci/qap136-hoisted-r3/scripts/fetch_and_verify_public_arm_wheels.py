"""Public locked wheel bodies only; no install, CI, containers, credentials or models."""
import argparse, concurrent.futures, datetime, email, hashlib, json, os
from pathlib import Path
import urllib.parse, urllib.request, zipfile


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--lock', type=Path, required=True)
    p.add_argument('--cache', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert not a.output.exists()
    lock = json.loads(a.lock.read_text())
    assert lock['count'] == len(lock['files']) == 95
    a.cache.mkdir(parents=True, exist_ok=True)

    def fetch(row):
        assert Path(row['wheel']).name == row['wheel']
        assert urllib.parse.urlparse(row['url']).hostname == 'files.pythonhosted.org'
        dest = a.cache / row['wheel']
        if not dest.exists():
            with urllib.request.urlopen(row['url'], timeout=90) as response:
                data = response.read(row['size'] + 1)
            assert len(data) == row['size']
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            temp = dest.with_suffix('.download-' + str(os.getpid()))
            temp.write_bytes(data)
            temp.replace(dest)
        assert dest.stat().st_size == row['size']
        assert hashlib.sha256(dest.read_bytes()).hexdigest() == row['sha256']
        with zipfile.ZipFile(dest) as z:
            metadata = [n for n in z.namelist() if n.endswith('.dist-info/METADATA')]
            wheel = [n for n in z.namelist() if n.endswith('.dist-info/WHEEL')]
            assert len(metadata) == len(wheel) == 1
            m = email.message_from_bytes(z.read(metadata[0]))
            w = email.message_from_bytes(z.read(wheel[0]))
            assert m['Version'] == row['version']
            return {'package': m['Name'], 'version': m['Version'],
                    'wheel': row['wheel'], 'SHA256': row['sha256'],
                    'bytes': row['size'], 'Requires-Python': m['Requires-Python'],
                    'Requires-Dist': m.get_all('Requires-Dist', []),
                    'Provides-Extra': m.get_all('Provides-Extra', []),
                    'actual_WHEEL_tags': w.get_all('Tag', [])}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(fetch, lock['files']))
    # This is an actual metadata dependency check, not ARM installation proof.
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name
    installed = {canonicalize_name(r['package']): r for r in rows}
    assert len(installed) == 95
    env = default_environment()
    env.update(python_version='3.12', python_full_version='3.12.0',
               implementation_name='cpython', implementation_version='3.12.0',
               platform_python_implementation='CPython', os_name='posix',
               sys_platform='linux', platform_system='Linux',
               platform_machine='aarch64', extra='')
    checked = []
    problems = []
    for row in rows:
        if row['Requires-Python'] and '3.12.0' not in SpecifierSet(row['Requires-Python']):
            problems.append({'package': row['package'], 'python_constraint': row['Requires-Python']})
        for raw in row['Requires-Dist']:
            req = Requirement(raw)
            if req.marker and not req.marker.evaluate(env):
                continue
            target = installed.get(canonicalize_name(req.name))
            ok = target is not None and target['version'] in req.specifier
            checked.append({'from': row['package'], 'requirement': raw, 'satisfied': ok})
            if not ok:
                problems.append(checked[-1])
    result = {'UTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status': 'actual_public_wheel_bytes_and_default_dependency_metadata_verified' if not problems else 'HOLD_dependency_metadata_mismatch',
              'lock_SHA256': hashlib.sha256(a.lock.read_bytes()).hexdigest(),
              'actual_wheels': rows, 'actual_total_bytes': sum(r['bytes'] for r in rows),
              'target_marker_environment': env, 'default_requirements_checked': checked,
              'problems': problems,
              'scope': 'Default extras only; actual ARM pip resolver/pip check and full host imports remain required',
              'actual_ARM_install_or_import': False, 'CI_build_grade_model_calls': 0}
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'wheels': len(rows),
                      'bytes': result['actual_total_bytes'], 'problems': len(problems)}))
    raise SystemExit(0 if not problems else 1)


if __name__ == '__main__':
    main()
