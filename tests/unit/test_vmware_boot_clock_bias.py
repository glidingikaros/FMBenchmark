from __future__ import annotations

import json
import shutil
import subprocess

import pytest
import yaml
from jsonschema import Draft202012Validator

import test_generation_recipe as recipe_tests
from test_generation_recipe import SOURCE, pipeline, recipe

locked_recipe = recipe_tests.locked_recipe


@pytest.mark.parametrize("bias", [480])
def test_frozen_bias_reaches_private_input(
    locked_recipe, tmp_path, monkeypatch, bias
):
    _, lock, config, public, assignment, plan = locked_recipe
    config = {
        **config,
        "clock_policy": "host_sync_then_service_stopped",
        "vmware_boot_clock_bias_minutes": bias,
    }
    directory = tmp_path / "clock-recipe"
    recipe.freeze_recipe(
        directory,
        source_root=SOURCE,
        config=config,
        population=public,
        assignment=assignment,
        guest_plan=plan,
        dependency_lock=lock,
        activity_seed=config["population_seed"],
        hardware_seed=config["population_seed"],
    )
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    seen = []

    def run(instance):
        instance.prepare_population()
        try:
            payload = json.loads(instance.population_inputs_path.read_text())
            seen.append(payload["fmb_vmware_boot_clock_bias_minutes"])
            assert payload["generation_inputs"] == plan
        finally:
            instance.cleanup_population_inputs()

    monkeypatch.setattr(pipeline.GenerationPipeline, "run", run)
    from fmb.replication import steps

    monkeypatch.setattr(steps, "_load_generation_pipeline", lambda: pipeline)
    assert steps.generate(recipe=str(directory), output_root=str(tmp_path / "run"))["status"] == "completed"
    assert seen == [bias]


@pytest.mark.parametrize("bias", [True, "480", 480.0, -841, 841])
def test_invalid_bias_cannot_be_frozen(locked_recipe, bias):
    _, _, config, public, assignment, plan = locked_recipe
    with pytest.raises(ValueError, match="fixed paper"):
        recipe.validate_resolved_inputs(
            {
                **config,
                "clock_policy": "host_sync_then_service_stopped",
                "vmware_boot_clock_bias_minutes": bias,
            },
            public,
            assignment,
            plan,
        )


@pytest.mark.parametrize("bias", [None, -840, 0, 480, 840, True, "480", 841])
def test_actual_vagrant_ruby_evaluation_has_no_implicit_bias(tmp_path, bias):
    ruby = shutil.which("ruby")
    if not ruby:
        pytest.skip("Ruby unavailable")
    payload = {
        "fmb_hardware": {
            "base_mac": "001122334455",
            "uuid_bios": "public",
            "uuid_location": "public",
            "display_name": "public",
        }
    }
    if bias is not None:
        payload["fmb_vmware_boot_clock_bias_minutes"] = bias
    layout = []
    for unit, port in zip([8,9,10], [5,3,2]):
        path = tmp_path/f"media-{unit}.vmdk"
        path.write_bytes(b"local fixture")
        layout.append({"unit":unit,"port":port,"path":str(path),"source_file":path.name})
    payload["generation_inputs"] = {"scenario_inputs":{"usbstor_setupapi_discrepancy_01":{"media":layout}}}
    inputs = tmp_path / "input.json"
    inputs.write_text(json.dumps(payload))
    script = tmp_path / "evaluate.rb"
    script.write_text("""require 'json'
require 'rbconfig'
RbConfig::CONFIG['host_os']='darwin'
RbConfig::CONFIG['host_cpu']='arm64'
class Time; def self.now; Time.at(2000000000); end; end
class Mock
  attr_reader :vmx
  def initialize; @vmx={}; end
  def method_missing(*args); self; end
  def provider(name); yield $machine, self if name=='vmware_desktop'; end
  def provision(*args); yield self; end
end
$machine=Mock.new
module Vagrant
  module Util; module IsPortOpen; end; end
  def self.configure(*args); yield Mock.new; end
end
$LOADED_FEATURES << 'vagrant/util/is_port_open.rb'
ENV['FMB_RECIPE_MODE']='1'
ENV['FMB_GENERATION_INPUTS_PATH']=ARGV[1]
ENV['FMB_BOX_VERSION']='0'
ENV['FMB_NATIVE_MEDIA_SOURCES']=ARGV[2]
load ARGV[0]
puts JSON.generate($machine.vmx.select{|k,v| k.start_with?('rtc.')})
""")
    result = subprocess.run(
        [ruby, str(script), str(SOURCE / "Vagrantfile"), str(inputs), json.dumps(layout)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if (
        type(bias) is not int
        and bias is not None
        or type(bias) is int
        and not -840 <= bias <= 840
    ):
        assert result.returncode != 0
        assert "Frozen VMware boot clock bias is invalid" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == (
            {}
            if bias is None
            else {
                "rtc.startInUTC": "TRUE",
                "rtc.startTime": str(2000000000 - bias * 60),
            }
        )


def test_boot_receipt_schema_and_action_optional_field():
    schema = json.loads(
        (SOURCE.parent / "contracts/schemas/generation_recipe.schema.json").read_text()
    )
    boot = schema["$defs"]["clock_receipt_v2"]["properties"]["boot_clock"]
    validator = Draft202012Validator(boot)
    value = {
        "expected_rtc_bias_minutes": 480,
        "observed_rtc_bias_minutes": 480,
        "clock_adjustment_ticks": 1,
        "forward_only": True,
    }
    assert validator.is_valid(value)
    for changed in [
        {"forward_only": False},
        {"clock_adjustment_ticks": -1},
        {"observed_rtc_bias_minutes": True},
        {"unexpected": 1},
    ]:
        assert not validator.is_valid({**value, **changed})
    task = yaml.safe_load((SOURCE / "ansible/recipe_clock.yml").read_text())[0]
    assert (
        task["fmb_clock"]["expected_rtc_bias_minutes"]
        == "{{ fmb_vmware_boot_clock_bias_minutes | default(omit) }}"
    )


