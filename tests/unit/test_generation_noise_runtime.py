import json
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('legacy_array_behavior', [False, True])
def test_resolved_noise_keeps_each_operation_separate(tmp_path, legacy_array_behavior):
    pwsh = shutil.which('pwsh')
    if pwsh is None:
        pytest.skip('PowerShell executable is required for the script regression')
    tasks = yaml.safe_load((ROOT / 'src/fmb/generation/ansible/roles/noise/tasks/main.yml').read_text())
    source = next(t['ansible.windows.win_copy']['content'] for t in tasks if 'ansible.windows.win_copy' in t)
    if legacy_array_behavior:
        source = source.replace('| ConvertFrom-Json', '| ConvertFrom-Json -NoEnumerate')
    script = tmp_path / 'noise.ps1'
    script.write_text(source)
    plan = [dict(path=str(tmp_path / f'object-{i}.txt'), content=f'original {i}',
                 append_content=f'append {i}', delete=i % 3 != 0, sleep_ms=0) for i in range(36)]
    result = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script), '-ResolvedPlan'],
                            input=json.dumps(plan), text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['completed_count'] == 36
    for row in plan:
        target = Path(row['path'])
        assert target.exists() != row['delete']
        if target.exists():
            assert row['content'] in target.read_text()
            assert row['append_content'] in target.read_text()
