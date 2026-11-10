"""Exercise an installed wheel with the public fixture, outside the source tree.

    python tests/package_smoke.py dist
"""
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv


def main():
    wheels = list(Path(sys.argv[1]).resolve().glob('*.whl'))
    if len(wheels) != 1:
        raise SystemExit('Expected exactly one wheel in the distribution directory')
    fixture = Path(__file__).with_name('sample.conf')
    with tempfile.TemporaryDirectory(prefix='rulescope-package-') as tmp:
        root = Path(tmp)
        env = root / 'venv'
        venv.EnvBuilder(with_pip=True, symlinks=os.name != 'nt').create(env)
        scripts = env / ('Scripts' if os.name == 'nt' else 'bin')
        python = scripts / ('python.exe' if os.name == 'nt' else 'python')
        command = scripts / ('rulescope.exe' if os.name == 'nt' else 'rulescope')
        process_env = dict(os.environ)
        process_env.pop('PYTHONPATH', None)
        process_env.pop('PYTHONHOME', None)
        process_env['PYTHONNOUSERSITE'] = '1'

        def run(args, expected=0):
            result = subprocess.run([str(a) for a in args], cwd=root, env=process_env,
                                    text=True, capture_output=True, timeout=60)
            if result.returncode != expected:
                raise AssertionError(f'{args}: expected exit {expected}, got {result.returncode}\n'
                                     f'{result.stdout}\n{result.stderr}')
            return result.stdout

        run([python, '-m', 'pip', 'install', '--no-index', '--no-deps', wheels[0]])
        # -I and an external cwd prevent a missing wheel file being supplied by the checkout.
        installed = json.loads(run([python, '-I', '-c',
            'import importlib.metadata, json, rulescope; print(json.dumps({'
            '"path": rulescope.__file__, "code": rulescope.__version__, '
            '"metadata": importlib.metadata.version("rulescope")}))']))
        assert env.resolve() in Path(installed['path']).resolve().parents
        assert installed['code'] == installed['metadata']
        assert run([command, '--version']).strip() == 'rulescope ' + installed['metadata']
        run([command, '--help'])
        shutil.copyfile(fixture, root / 'sample.conf')

        run([command, 'collect', '--config', 'sample.conf', '--out', 'snapshots'])
        snapshots = list((root / 'snapshots').rglob('*.json'))
        assert len(snapshots) == 1
        snapshot = snapshots[0]
        outputs = ['audit.html', 'audit.json', 'audit.csv', 'remediation.txt', 'practices.csv']
        run([command, 'audit', '--config', 'sample.conf', '--advisories', 'off',
             '--html', outputs[0], '--json', outputs[1], '--csv', outputs[2],
             '--cli', outputs[3], '--practices-csv', outputs[4]])
        for name in outputs:
            assert (root / name).stat().st_size > 0, name
        audit = json.loads((root / 'audit.json').read_text(encoding='utf-8'))
        assert audit['findings'], 'The public fixture should exercise findings'
        assert '<html' in (root / 'audit.html').read_text(encoding='utf-8').lower()
        with (root / 'audit.csv').open(encoding='utf-8-sig', newline='') as fh:
            assert len(list(csv.reader(fh))) > 1
        assert (root / 'remediation.txt').read_text(encoding='utf-8').startswith('# rulescope')

        run([command, 'analyze', snapshot, '--baseline', snapshot, '--redact',
             '--advisories', 'off', '--json', 'comparison.json'])
        compared = json.loads((root / 'comparison.json').read_text(encoding='utf-8'))
        assert compared['device']['hostname'] == 'FIREWALL'
        assert compared['comparison']['new'] == compared['comparison']['resolved'] == []
        run([command, 'diff', snapshot, snapshot, '--json', 'diff.json'])
        assert json.loads((root / 'diff.json').read_text(encoding='utf-8'))['empty']
        run([command, 'audit', '--config', 'sample.conf', '--advisories', 'off', '--fail-on', 'info'], expected=2)
        run([command, 'analyze', snapshot, '--unknown-option'], expected=2)
        print(f'Installed rulescope {installed["metadata"]}: CLI, snapshot, reports, '
              'redacted baseline, diff and failure exits passed.')


if __name__ == '__main__':
    main()
