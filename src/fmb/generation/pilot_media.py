from __future__ import annotations

import json
import re
from pathlib import Path

from fmb.generation import ntfs_surface_injection as native
from fmb.generation.native_media_generation import alter_setupapi_identity
from fmb.generation.qemu_image import QemuImageReader, ntfs_partition_offsets
from fmb.index.scanners.ntfs import parse_boot_sector


def check_slots(vmx_text: str, layout: list[dict]) -> None:
    for item in layout:
        unit, port = int(item["unit"]), int(item["port"])
        if (re.search(rf"(?im)^\s*usb_xhci:{unit}\.", vmx_text)
                or re.search(rf'(?im)^\s*usb_xhci:\d+\.port\s*=\s*"{port}"', vmx_text)):
            raise RuntimeError("selected VMware source occupies a pilot USB slot or compatible port")


def prepare(controller) -> None:
    layout = controller.population_guest_plan["scenario_inputs"]["usbstor_setupapi_discrepancy_01"]["media"]
    sources = []
    for item in layout:
        path = controller.output_dir / item["source_file"]
        if path.exists():
            raise FileExistsError("refusing to overwrite a pilot USB backing")
        controller.run_command(["qemu-img", "create", "-f", "vmdk", str(path), str(item["disk_size_bytes"])])
        sources.append({"path": path, "unit": item["unit"], "port": item["port"]})
    controller.native_media_sources = sources


def match_backings(sources: list[dict], bindings: list[dict], *, reader_factory=QemuImageReader) -> dict[str, Path]:
    if len(sources) != 3 or len(bindings) != 3:
        raise ValueError("pilot backing reconciliation requires exactly three volumes")
    by_serial = {}
    for source in sources:
        path = Path(source["path"])
        reader = reader_factory(path, max_read_bytes=67_108_864)
        offsets = ntfs_partition_offsets(reader)
        if reader.size != 67_108_864 or len(offsets) != 1:
            raise ValueError("pilot backing is not a sole bounded NTFS volume")
        boot = parse_boot_sector(reader.read_at(offsets[0], 512))
        serial = boot["volume_serial_number"][-8:].lower()
        if serial in by_serial:
            raise ValueError("pilot native volume serials are duplicated")
        by_serial[serial] = (path, offsets[0])
    result = {}
    for row in bindings:
        binding = row["native_binding"]
        serial = binding["volume_serial_number"].lower()
        if serial not in by_serial or by_serial[serial][1] != binding["partition_offset_bytes"]:
            raise ValueError("pilot backing does not match its observed guest identity")
        if row["subject_ref"] in result:
            raise ValueError("pilot binding repeats a device")
        result[row["subject_ref"]] = by_serial.pop(serial)[0]
    if by_serial:
        raise ValueError("pilot backing was not bound to a device")
    return result


def export(controller, system_image: Path) -> list[Path]:
    bindings = controller.native_media_binding
    if not isinstance(bindings, list):
        raise ValueError("pilot export lacks the three verified native bindings")
    sources = match_backings(controller.native_media_sources, bindings)
    layout = controller.population_guest_plan["scenario_inputs"]["usbstor_setupapi_discrepancy_01"]["media"]
    if [row["subject_ref"] for row in bindings] != [row["subject_ref"] for row in layout]:
        raise ValueError("pilot export bindings differ from the frozen device roster")
    artifacts = []
    for item, row in zip(layout, bindings, strict=True):
        binding = row["native_binding"]
        source = sources[row["subject_ref"]]
        companion = controller.output_dir / item["companion_file"]
        controller.run_post_export_intervention(
            "native_media_export_" + companion.stem, companion,
            lambda source=source, companion=companion: controller.convert_and_publish(source, companion, "vmdk"),
            creates_image=True,
        )
        if item["installation_discrepancy"]:
            def setup_operation(binding=binding, item=item):
                def transform(data):
                    controller.retain_factual_checkpoint("checkpoint-03.log", data)
                    return alter_setupapi_identity(data, binding["device_instance_id"])
                receipt = native.transform_native_file(system_image, r"C:\Windows\INF\setupapi.dev.log", transform)
                receipt["native_subject_ref"] = item["subject_ref"]
                return controller.bind_post_export_receipt("usbstor_setupapi_discrepancy_01", receipt)
            controller.run_post_export_intervention("usbstor_setupapi_discrepancy_01", system_image, setup_operation)
        if item["history_discrepancy"]:
            def history_operation(binding=binding, item=item, companion=companion):
                if companion.stat().st_size > 128 * 1024**2:
                    raise ValueError("pilot companion exceeds its bounded checkpoint size")
                controller.retain_factual_checkpoint("checkpoint-04.vmdk", companion.read_bytes())
                receipt = native.rewrite_usb_history_names(companion,
                    file_reference_number=int(binding["target_file_reference_number"]),
                    original_name=item["file_name"], replacement_name=item["replacement_name"])
                receipt.update(native_subject_ref=item["subject_ref"], companion_file=companion.name)
                return controller.bind_post_export_receipt("usb_volume_activity_gap_01", receipt)
            controller.run_post_export_intervention("usb_volume_activity_gap_01", companion, history_operation)
        binding_path = controller.output_dir / item["binding_file"]
        payload = (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode()
        if binding_path.exists():
            if binding_path.read_bytes() != payload:
                raise ValueError("existing pilot binding differs; preserve the failed realization")
        else:
            with binding_path.open("xb") as stream:
                stream.write(payload)
        artifacts.extend((companion, binding_path))
    return artifacts
