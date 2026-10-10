import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


ez = module('bootstrap_eztools')
dfir = module('bootstrap_dfir_ntfs')


def test_existing_nonrepository_preserved(tmp_path):
    directory = tmp_path / 'tool'
    directory.mkdir()
    sentinel = directory / 'local.txt'
    sentinel.write_text('keep')
    with pytest.raises(ez.BootstrapError, match='refusing'):
        ez.checkout_pinned({'checkout': 'tool', 'commit_sha': 'a' * 40}, tmp_path,
                          lambda *a, **k: pytest.fail('no command'), 'git')
    assert sentinel.read_text() == 'keep'


def test_dirty_checkout_not_cleaned(tmp_path):
    (tmp_path / 'tool/.git').mkdir(parents=True)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, ' M edited.cs\n', '')
    with pytest.raises(ez.BootstrapError, match='local changes'):
        ez.checkout_pinned({'checkout': 'tool', 'commit_sha': 'a' * 40}, tmp_path, run, 'git')
    assert len(calls) == 1 and 'status' in calls[0]


def test_dfir_plan_pins_commit_and_python(tmp_path):
    lock = {'tool': 'dfir_ntfs', 'source': 'https://github.com/msuhanov/dfir_ntfs',
            'commit_id': 'a' * 40, 'python_version': '3.13.5'}
    assert dfir.install_requirement(lock).endswith('@' + 'a' * 40)
    assert dfir.venv_command('uv', lock, tmp_path)[-3:] == ['--python', '3.13.5', str(tmp_path)]
    assert {'--no-deps', '--no-cache'} <= set(dfir.install_command('uv', lock, tmp_path))
    with pytest.raises(dfir.BootstrapError):
        dfir.install_requirement({**lock, 'commit_id': 'main'})


@pytest.mark.skipif(shutil.which('git') is None, reason='git is not installed')
def test_dfir_ntfs_is_checked_out_with_its_committed_line_endings_under_git_for_windows_defaults(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'LogFile.py').write_bytes(b'line one\nline two\n')
    plain = {**os.environ, 'HOME': str(tmp_path), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_COUNT': '0'}

    def git(*args, env=plain, cwd=source):
        subprocess.run(['git', *args], cwd=cwd, env=env, check=True, capture_output=True)

    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=t', '-c', 'user.email=t@example.org', 'commit', '-qm', 'lf')
    windows = {**plain, 'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.autocrlf', 'GIT_CONFIG_VALUE_0': 'true'}
    git('clone', '-q', str(source), str(tmp_path / 'default'), env=windows, cwd=tmp_path)
    git('clone', '-q', str(source), str(tmp_path / 'locked'), env=dfir.install_environment(windows), cwd=tmp_path)
    assert (tmp_path / 'default' / 'LogFile.py').read_bytes() == b'line one\r\nline two\r\n'
    assert (tmp_path / 'locked' / 'LogFile.py').read_bytes() == b'line one\nline two\n'


def test_custom_lock_rebuild_refuses_before_mutation(tmp_path):
    args = dfir.build_parser().parse_args(['--lock', str(tmp_path / 'custom.json')])
    with pytest.raises(dfir.BootstrapError, match='custom locks'):
        dfir.rebuild(args, run=lambda *a, **kw: pytest.fail('no command'), which=lambda _: 'uv')


