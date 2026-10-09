from __future__ import annotations

import base64
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_ROOT = PROJECT_ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks"


def scenario_source(name: str) -> str:
    if name in {"typed_path_residue_01.yml", "bitmap_trailing_data_01.yml",
                "usbstor_setupapi_discrepancy_01.yml", "usb_volume_activity_gap_01.yml", "ntfs_allocation_01.yml"}:
        name = "pilot_" + name
    return (SCENARIO_ROOT / name).read_text(encoding="utf-8")


def render_public_helper_lookups(source: str) -> str:
    import re
    pattern = re.compile(
        r"\{\{ lookup\('file', role_path \+ '/files/([^']+)'\)"
        r"(?: \| indent\((\d+)\))? \}\}"
    )
    def replace(match):
        helper = (SCENARIO_ROOT.parent / "files" / match.group(1)).read_text().rstrip()
        if match.group(2):
            lines = helper.splitlines(keepends=True)
            prefix = " " * int(match.group(2))
            helper = lines[0] + "".join((prefix if line.strip() else "") + line for line in lines[1:])
        return helper
    rendered = pattern.sub(replace, source)
    assert "{{ lookup(" not in rendered
    return rendered


def load_population_module():
    module_path = PROJECT_ROOT / "src/fmb/generation" / "population.py"
    spec = importlib.util.spec_from_file_location(
        "scenario_truth_blindness_population", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "scenario_name",
    (
        "timestomp_01.yml",
        "ads_injection_01.yml",
        "prefetch_wipe_01.yml",
        "shimcache_path_residue_01.yml",
        "usn_journal_01.yml",
        "typed_path_residue_01.yml",
        "bitmap_trailing_data_01.yml",
        "directory_cleaning_i30_01.yml",
        "security_log_clear_event_01.yml",
        "usbstor_setupapi_discrepancy_01.yml",
    ),
)
def test_scenario_payloads_do_not_shadow_powershell_input_automatic_variable(
    scenario_name: str,
) -> None:
    source = scenario_source(scenario_name)

    assert "$scenarioInput = [Console]::In.ReadToEnd()" in source
    assert "$input" not in source.casefold()


def media_helper_source() -> str:
    return (SCENARIO_ROOT.parent / "files/pilot_media_prepare.ps1").read_text()


def test_external_media_scenario_keeps_answer_metadata_off_guest() -> None:
    source = scenario_source("usbstor_setupapi_discrepancy_01.yml")
    helper = media_helper_source()
    assert "GROUND_TRUTH_BEGIN" in source
    assert "native_bindings = $bindings" in source
    for banned in ("NO_TRANSFER", "filesystem_probe", "candidate_id", "supported", "Set-ItemProperty"):
        assert banned.casefold() not in helper.casefold()
    assert "physical_host_device = $false" in helper
    assert "attachment_kind = 'hypervisor_virtual_usb_mass_storage'" in helper


def test_external_media_uses_native_device_enumeration_and_safe_empty_media() -> None:
    source = media_helper_source()
    assert "Get-CimInstance Win32_DiskDrive" in source
    assert "Get-Disk -Number" in source
    assert "$disk.IsBoot -or $disk.IsSystem" in source
    assert "$partitions[0].Offset -ne 0" in source
    assert "$boot | Where-Object { $_ -ne 0 }" in source
    assert "GetFileInformationByHandle" in source
    assert "CreateSubKey" not in source
    assert "SetValue(" not in source


def test_external_media_cases_share_native_attachment_before_intervention() -> None:
    source = scenario_source("usbstor_setupapi_discrepancy_01.yml")
    assert "@($scenarioInput.media).Count -ne 3" in source
    assert "native_binding=$binding" in source
    helper = media_helper_source()
    assert "$case" not in helper
    assert helper.index("fsutil usn createjournal") < helper.index("[IO.File]::Copy(")
    assert "FSCTL" not in helper or "0x000900f4" in helper
    assert "journal_start_usn = $journalStartUsn" in helper
    assert "[IO.File]::AppendAllText($afterPath" in helper
    assert "WriteAllText('C:\\Windows\\INF" not in helper


def test_new_file_scenarios_use_neutral_subject_names_and_content() -> None:
    source = "\n".join(
        (
            scenario_source("bitmap_trailing_data_01.yml"),
            scenario_source("directory_cleaning_i30_01.yml"),
        )
    )

    assert "".join(("F", "MD_")) not in source
    assert "REMOVED_" + "EVIDENCE" not in source
    assert "BOUNDED_" + "TRAILING_CONTENT" not in source


def test_i30_scenario_populates_both_native_index_strata_before_deletion() -> None:
    source = scenario_source("directory_cleaning_i30_01.yml")
    assert "$leafNames.Count -ne 80" in source
    assert "$directoryCases.Count -ne $expectedPopulationCount" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert source.index("$created.Add($path)") < source.index("Remove-Item -LiteralPath $path")
    assert "$remainingLeafCount -eq ($created.Count - $removedLeafCount)" in source


def test_i30_operation_cardinality_follows_each_frozen_profile() -> None:
    population = load_population_module()
    for image in ("i1", "i2", "i3"):
        contract = population.load_population_contract(
            PROJECT_ROOT / f"src/fmb/generation/populations.pilot-{image}-20260918.json")
        manifest = population.build_public_manifest(experiment="full_scale", seed=84, contract=contract)
        assignment = population.select_private_assignment(manifest, entropy=b"directory-profile-cardinality")
        inputs = population.build_guest_plan(manifest, assignment, case="positive")["scenario_inputs"]["directory_cleaning_i30_01"]
        expected = contract["scenarios"]["directory_cleaning_i30_01"]["manipulation_count"]
        assert inputs["expected_operation_count"] == len(inputs["operation_refs"]) == expected

    source = scenario_source("directory_cleaning_i30_01.yml")
    assert "$case -eq 'positive' -and $expectedOperationCount -lt 1" in source
    assert "$case -eq 'benign' -and $expectedOperationCount -ne 0" in source
    assert "$(if ($case -eq 'positive') { 1 } else { 0 })" not in source


def test_active_scenarios_do_not_write_answer_bearing_guest_markers() -> None:
    source = "\n".join(
        scenario_source(name)
        for name in (
            "timestomp_01.yml",
            "ads_injection_01.yml",
            "prefetch_wipe_01.yml",
            "shimcache_path_residue_01.yml",
            "usn_journal_01.yml",
            "typed_path_residue_01.yml",
        )
    )
    banned = (
        "hidden_" + "evidence",
        "hidden_" + "payload",
        "not_" + "malware",
        "suspicious_" + "script",
        "transient_" + "evidence",
        "Confidential_" + "Data",
        "stolen_" + "plans",
        "Top " + "Secret",
        "SECRET_" + "DATA",
        "".join(("F", "MD_Confidential_Path")),
    )

    assert not any(token.casefold() in source.casefold() for token in banned)


def test_typed_path_scenario_uses_typed_paths_without_unrelated_shell_artifacts() -> None:
    source = scenario_source("typed_path_residue_01.yml")

    assert "Explorer\\TypedPaths" in source
    assert 'Name ("url{0}" -f ($index + 1))' in source
    assert "-PropertyType String -Value $directory" in source
    assert "RecentDocs" not in source
    assert "MRUListEx" not in source
    assert "-PropertyType Binary" not in source
    assert "$missingTypedPaths.Count -eq 0" in source
    assert ".lnk" not in source
    assert "CreateShortcut" not in source
    assert "$paths | Where-Object {Test-Path -LiteralPath $_}).Count -eq 0" in source


def test_typed_path_benign_case_retains_paths_and_registry_values() -> None:
    source = scenario_source("typed_path_residue_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert "$retainedPaths.Count -eq $populationPaths.Count" in source
    assert "$missingTypedPaths.Count -eq 0" in source


def test_usn_benign_case_updates_but_does_not_delete_population_members() -> None:
    source = scenario_source("usn_journal_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert "Add-Content -LiteralPath ([string]$path)" in source
    assert "$retainedCount -eq $populationPaths.Count" in source


def test_security_log_benign_case_verifies_no_clear_event_is_emitted() -> None:
    source = scenario_source("security_log_clear_event_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$paths.Count -ne 0" in source
    assert "Clear-EventLog" in source
    assert "StartTime" not in source
    assert "$verified = $null -eq $event" in source


def test_bitmap_benign_case_verifies_no_trailing_bytes_in_the_population() -> None:
    source = scenario_source("bitmap_trailing_data_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert "$populationPaths.Count -ne $expectedPopulationCount" in source
    assert "$unexpectedLengths.Count -eq 0" in source


def test_prefetch_postcondition_uses_the_executable_name_including_extension() -> None:
    source = scenario_source("prefetch_wipe_01.yml")

    assert "[IO.Path]::GetFileName([string]$path)" in source
    assert "GetFileNameWithoutExtension" not in source
    assert "Get-ChildItem -LiteralPath 'C:\\Windows\\Prefetch'" in source
    assert '-Filter "$prefetchName-*.pf"' in source


def test_prefetch_benign_case_generates_residue_and_retains_every_executable() -> None:
    source = scenario_source("prefetch_wipe_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert "$retainedCount -eq $populationPaths.Count" in source
    assert "$prefetchCount -eq $populationPaths.Count" in source


def test_timestomp_postcondition_verifies_every_assigned_si_timestamp() -> None:
    source = scenario_source("timestomp_01.yml")

    assert "private static extern bool SetFileTime(" in source
    assert "private static extern bool SuppressLastAccessUpdate(" in source
    assert "long preserveLastAccess = -1;" in source
    assert "timestampUtc.ToFileTimeUtc()" in source
    assert "\n    '@\n" in source
    assert "[LocalFileTimes]::SetAllUtc($path, $stompUtc)" in source
    assert "$observed.CreationTimeUtc.Ticks -ne $stompUtc.Ticks" in source
    assert "$observed.LastWriteTimeUtc.Ticks -ne $stompUtc.Ticks" in source
    assert "$observed.LastAccessTimeUtc.Ticks -ne $stompUtc.Ticks" in source
    assert "$file.CreationTime =" not in source
    assert "$file.LastWriteTime =" not in source
    assert "$file.LastAccessTime =" not in source


@pytest.mark.parametrize(
    "scenario_id",
    ("timestomp_01", "bitmap_trailing_data_01"),
)
def test_selected_paths_are_not_reemitted_in_guest_receipt_instances(
    scenario_id: str,
) -> None:
    source = scenario_source(f"{scenario_id}.yml")

    assert "file = $path" not in source


def test_timestomp_failure_reporting_is_phase_only_and_keeps_inputs_hidden() -> None:
    source = scenario_source("timestomp_01.yml")

    assert "failure_phase = $fmbFailurePhase" in source
    assert "} catch {" in source
    assert "no_log: true" in source
    assert "Timestamp generation failed during" in source


def test_timestomp_benign_case_retains_the_complete_unmodified_population() -> None:
    source = scenario_source("timestomp_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$populationPaths.Count -ne $expectedPopulationCount" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert "$missingPaths.Count -ne 0" in source


def test_ads_uses_native_content_with_nonempty_benign_stream_controls() -> None:
    source = scenario_source("ads_injection_01.yml")
    assert "-Stream 'Zone.Identifier'" in source
    assert "-Stream $metadataName" in source
    assert "whoami.exe" in source
    assert source.index("-Stream $metadataName") < source.index("$failureStage = 'payload_file_read'")
    assert "Start-Process" not in source
    assert "Set-Content -LiteralPath ([string]$paths[0]) -Stream $streamName -Value $payload -Encoding Byte" in source
    assert "Get-Content -LiteralPath ([string]$paths[0]) -Stream $streamName -Encoding Byte -ReadCount 0" in source
    assert "[IO.File]::WriteAllBytes($streamPath" not in source
    assert "[IO.File]::ReadAllBytes($streamPath" not in source
    assert "$readback.Length -eq $payload.Length" in source
    assert "ComputeHash($readback)" in source
    assert "ToBase64String($observedHash) -ceq $expectedHash" in source


@pytest.mark.pwsh
@pytest.mark.parametrize("scenario", ["ads_injection_01", "shellbag_path_residue_01"])
def test_failure_diagnostic_exposes_stage_and_type_without_exception_text(tmp_path, scenario) -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is not installed")
    yaml = pytest.importorskip("yaml")
    tasks = yaml.safe_load(scenario_source(scenario + ".yml"))
    source = tasks[0]["ansible.windows.win_shell"]
    source = render_public_helper_lookups(source)
    path = tmp_path / "failure-probe.ps1"
    path.write_text(source)
    sentinel = "PRIVATE_DO_NOT_EMIT"
    result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-File", str(path)],
                            input=sentinel + " {", text=True, capture_output=True, check=False)
    assert result.returncode == 0
    diagnostic = json.loads(result.stdout)
    expected_fields = {"ok", "failure_stage", "error_type"}
    if scenario == "shellbag_path_residue_01":
        expected_fields.update({"native_failure_code", "completed_public_visits", "dispatch_diagnostic", "snapshot_diagnostic"})
        assert diagnostic["completed_public_visits"] == 0
        assert diagnostic["dispatch_diagnostic"] is None
        assert diagnostic["snapshot_diagnostic"] is None
        assert diagnostic["native_failure_code"] == "not_available"
    assert set(diagnostic) == expected_fields
    assert diagnostic["ok"] is False
    assert diagnostic["failure_stage"] == "decode_input"
    assert diagnostic["error_type"].endswith("Exception")
    assert all(part.isidentifier() for part in diagnostic["error_type"].split("."))
    assert sentinel not in result.stdout + result.stderr
    assert not result.stderr.strip()
    assert tasks[0]["no_log"] is True
    assertion = tasks[1]["ansible.builtin.assert"]
    assert "failure_stage" in assertion["fail_msg"]
    assert "error_type" in assertion["fail_msg"]
    assert "stderr" not in assertion["fail_msg"]
    assert ".receipt | to_json" in tasks[2]["ansible.builtin.debug"]["msg"][1]


def test_shimcache_executes_each_dynamic_native_executable_directly() -> None:
    source = scenario_source("shimcache_path_residue_01.yml")

    assert "foreach ($path in $populationPaths)" in source
    assert "Start-Process -FilePath ([string]$path)" in source
    assert "-WindowStyle Hidden -Wait" in source
    assert "cmd.exe" not in source.casefold()


def test_shimcache_benign_case_generates_residue_and_retains_every_executable() -> None:
    source = scenario_source("shimcache_path_residue_01.yml")

    assert "$case -eq 'positive'" in source
    assert "$paths.Count -ne $expectedOperationCount" in source
    assert "$retainedCount -eq $populationPaths.Count" in source


def test_each_scenario_starts_with_a_fresh_remote_connection() -> None:
    main = scenario_source("main.yml")
    wrapper = scenario_source("execute_scenario.yml")

    assert "execute_scenario.yml" in main
    assert "loop_var: fmb_scenario_item" in main
    assert "ansible.builtin.meta: reset_connection" in wrapper
    assert "{{ fmb_scenario_item.strip() }}.yml" in wrapper
    assert wrapper.index("reset_connection") < wrapper.index("include_tasks")


def test_bounded_population_streams_one_payload_without_writing_it_to_guest() -> None:
    source = scenario_source("materialize_population.yml")
    main = scenario_source("main.yml")

    assert "ansible.windows.win_copy" not in source
    assert "fmb-generation-population.json" not in source
    assert "generation_inputs.population_members | to_json" in source
    assert "$members = [Console]::In.ReadToEnd() | ConvertFrom-Json" in source
    assert "stdin:" in source
    assert "ansible.windows.win_file" not in source
    assert "batch(" not in source
    assert "loop:" not in source
    assert "fmb_population_materialization.stdout" in source
    assert "generation_inputs.population_members | length" in source
    assert "candidate_id" not in source
    assert "subject_id" not in source
    assert "offender" not in source.casefold()
    assert "target" not in source.casefold()
    assert "no_log: true" in source
    assert "postcondition_verified" in source
    assert "materialize_population.yml" in main
    assert main.index("materialize_population.yml") < main.index(
        "Include specific scenario tasks"
    )


def test_executable_population_materialization_copies_a_native_guest_binary() -> None:
    source = scenario_source("materialize_population.yml")

    assert "'executable'" in source
    assert '"$env:SystemRoot\\System32\\whoami.exe"' in source
    assert "-Destination $path -Force" in source
    assert "x_" not in source


def test_every_active_scenario_consumes_operational_inputs_and_emits_one_receipt() -> (
    None
):
    helper = (SCENARIO_ROOT.parent / "files/operations.ps1").read_text()
    assert "[Security.Cryptography.SHA256]::Create()" in helper
    assert "generation_operation_refs.v1`n$json" in helper
    assert (
        r'''$json.Replace('\u0026', '&').Replace('\u0027', "'").Replace('\u003c', '<').Replace('\u003e', '>')'''
        in helper
    )

    scenario_ids = (
        "timestomp_01",
        "ads_injection_01",
        "prefetch_wipe_01",
        "security_log_clear_event_01",
        "usn_journal_01",
        "shimcache_path_residue_01",
        "typed_path_residue_01",
        "bitmap_trailing_data_01",
        "directory_cleaning_i30_01",
        "usbstor_setupapi_discrepancy_01",
    )

    for scenario_id in scenario_ids:
        source = scenario_source(f"{scenario_id}.yml")
        assert f"generation_inputs.scenario_inputs.{scenario_id}" in source
        assert "$scenarioInput = [Console]::In.ReadToEnd() | ConvertFrom-Json" in source
        assert "$case = [string]$scenarioInput.case" in source
        assert "case = $case" in source
        assert "stdin:" in source
        assert "$input = @'" not in source
        assert source.count("GROUND_TRUTH_BEGIN") == 1
        assert source.count("GROUND_TRUTH_END") == 1
        assert "scenario_id" in source
        assert "$scenarioInput.operation_refs" in source
        assert "operation_refs = $paths" not in source
        assert "operation_count = $paths.Count" in source
        assert "operation_refs_sha256 = $operationRefsSha256" in source
        assert "$operationRefsSha256 = Get-OperationRefsSha256 $paths" in source
        assert "{{ lookup('file', role_path + '/files/operations.ps1') | indent(4) }}" in source
        assert "postcondition_verified" in source
        assert "candidate_id" not in source
        assert "subject_id" not in source
        assert "offender" not in source.casefold()


def test_usb_control_requires_an_exact_setupapi_section_not_a_serial_substring() -> None:
    source = media_helper_source()
    assert r"Device Install \(Hardware initiated\)" in source
    assert "$encodedInstance = $instance.Replace('\\', '#')" in source
    assert "$encodedInstance + '#{'" in source
    assert "[String]::Equals($observed, $instance" in source
    assert "-not (Test-Path -LiteralPath $registryPath)" in source
    assert "$setupMatches.Count -lt 1" in source
    assert "$observed, $current" not in source


@pytest.mark.pwsh
@pytest.mark.parametrize(
    "refs",
    [
        [],
        ["Security"],
        [
            r"C:\Users\vagrant\Desktop\f_alpha.txt",
            r"C:\Users\vagrant\Documents\f_beta.txt",
        ],
        [r"USBSTOR\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00\SERIAL"],
    ],
)
def test_operation_reference_digest_matches_powershell(refs: list[str]) -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is not installed")
    population = load_population_module()
    payload = base64.b64encode(json.dumps({"refs": refs}).encode()).decode()
    script = (
        "$input=[Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($args[0]))|ConvertFrom-Json;"
        "$paths=@($input.refs);"
        "[object[]]$strings=@($paths|ForEach-Object{[string]$_});"
        "$json=ConvertTo-Json -InputObject $strings -Compress;"
        "$json=$json.Replace('\\u0026','&').Replace('\\u0027',\"'\")"
        ".Replace('\\u003c','<').Replace('\\u003e','>');"
        "$hasher=[Security.Cryptography.SHA256]::Create();"
        "try{$digest=([BitConverter]::ToString($hasher.ComputeHash("
        "[Text.Encoding]::UTF8.GetBytes("
        '"generation_operation_refs.v1`n$json"))))'
        ".Replace('-', '').ToLowerInvariant()}finally{$hasher.Dispose()};"
        "Write-Output $digest"
    )

    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-CommandWithArgs", script, payload],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == population.operation_refs_sha256(refs)


@pytest.mark.pwsh
def test_generation_powershell_blocks_parse_when_pwsh_is_available() -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is not installed")
    yaml = pytest.importorskip("yaml")
    parser = (
        "$code=[Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($args[0]));"
        "$tokens=$null;$errors=$null;"
        "[Management.Automation.Language.Parser]::ParseInput("
        "$code,[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors.Count){$errors|ForEach-Object{Write-Error $_.Message};exit 1}"
    )
    parsed_scenarios: set[str] = set()

    for path in sorted(SCENARIO_ROOT.glob("*.yml")):
        for task in yaml.safe_load(path.read_text(encoding="utf-8")):
            if not isinstance(task, dict) or "ansible.windows.win_shell" not in task:
                continue
            parsed_scenarios.add(path.stem)
            source = str(task["ansible.windows.win_shell"])
            source = source.replace("{{ item | to_json }}", "{}")
            source = source.replace(
                "{{ generation_inputs.scenario_inputs." + path.stem + " | to_json }}",
                "{}",
            )
            source = render_public_helper_lookups(source)
            encoded = base64.b64encode(source.encode()).decode()
            result = subprocess.run(
                [
                    pwsh,
                    "-NoProfile",
                    "-NonInteractive",
                    "-CommandWithArgs",
                    parser,
                    encoded,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, f"{path.name}: {result.stderr}"

    assert {
        "timestomp_01",
        "ads_injection_01",
        "prefetch_wipe_01",
        "security_log_clear_event_01",
        "usn_journal_01",
        "shimcache_path_residue_01",
        "pilot_typed_path_residue_01",
        "pilot_bitmap_trailing_data_01",
        "directory_cleaning_i30_01",
        "pilot_usbstor_setupapi_discrepancy_01",
    }.issubset(parsed_scenarios)


def test_shellbag_helper_travels_in_stdin_below_createprocess_command_limit() -> None:
    yaml = pytest.importorskip("yaml")
    import gzip
    tasks = yaml.safe_load(scenario_source("shellbag_path_residue_01.yml"))
    command = tasks[0]["ansible.windows.win_shell"]
    files = SCENARIO_ROOT.parent / "files"
    command = render_public_helper_lookups(command)
    payload = (files / "native_shellbag.ps1.gz.b64").read_text().strip()
    assert gzip.decompress(base64.b64decode(payload)) == (files / "native_shellbag.ps1").read_bytes()
    assert payload not in command
    assert "$scenarioInput.native_helper_payload" in command
    assert "$scenarioInput.native_helper_sha256" in command
    assert "native_helper_payload" in tasks[0]["args"]["stdin"]
    assert "hash('sha256')" in tasks[0]["args"]["stdin"]
    encoded_length = len(base64.b64encode(command.encode("utf-16le")))
    assert encoded_length + 2048 < 32767


@pytest.mark.pwsh
def test_native_scenario_templates_pass_installed_ansible_argument_parser(tmp_path) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible is not installed")
    import shlex
    import os
    interpreter = shlex.split(Path(executable).read_text().splitlines()[0].removeprefix("#!"))
    parser = """import sys
from pathlib import Path
import yaml
from ansible.parsing.mod_args import ModuleArgsParser
seen = set()
for path in sorted(Path(sys.argv[1]).glob('*.yml')):
    for task in yaml.safe_load(path.read_text()):
        if isinstance(task, dict) and 'ansible.windows.win_shell' in task:
            try:
                ModuleArgsParser(task).parse(skip_action_validation=True)
            except Exception as error:
                raise AssertionError(path.name) from error
            seen.add(path.stem)
assert {'shellbag_path_residue_01', 'pilot_usbstor_setupapi_discrepancy_01'} <= seen
"""
    result = subprocess.run(
        [*interpreter, "-c", parser, str(SCENARIO_ROOT)],
        env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path)),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_shellbag_native_failure_codes_accept_only_exact_source_owned_messages(tmp_path) -> None:
    import re
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is not installed")
    helper = SCENARIO_ROOT.parent / "files/native_shellbag.ps1"
    extractor = r"""
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Native helper syntax is invalid'}
$functions=@($ast.FindAll({param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -ceq 'Get-LocalNativeShellbagFailureCode'
},$true))
if($functions.Count -ne 1){throw 'Expected one native failure-code function'}
$functions[0].Extent.Text
"""
    extracted = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-CommandWithArgs", extractor, str(helper)],
        text=True, capture_output=True, check=False, timeout=30,
    )
    assert extracted.returncode == 0, extracted.stderr
    assert not extracted.stderr.strip(), extracted.stderr
    function = extracted.stdout.strip()
    mappings = re.findall(r'"([^"\n]+)" \{ return "([a-z_]+)" \}', function)
    assert len(mappings) == 49
    sentinel = r"PRIVATE_DO_NOT_EMIT C:\Private\hidden-name"
    cases = [(message, code) for message, code in mappings]
    cases += [(sentinel, "unrecognized_native_failure"), ("", "unrecognized_native_failure")]
    cases += [(message + sentinel, "unrecognized_native_failure") for message, _ in mappings]
    cases += [(message.lower(), "unrecognized_native_failure") for message, _ in mappings if message != message.lower()]
    script = tmp_path / "safe-code.ps1"
    script.write_text(function + "\n$messages=[Console]::In.ReadToEnd()|ConvertFrom-Json\n"
                      "@($messages|ForEach-Object{Get-LocalNativeShellbagFailureCode -Message $_})|ConvertTo-Json -Compress\n")
    result = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-File", str(script)],
                            input=json.dumps([message for message, _ in cases]),
                            text=True, capture_output=True, check=False, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [code for _, code in cases]
    assert sentinel not in result.stdout + result.stderr
    assert not result.stderr.strip()
