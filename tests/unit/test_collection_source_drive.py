from fmb.collection.inputs import source_drive


def test_source_drive_normalization_accepts_drive_roots_only() -> None:
    assert source_drive.normalize_source_drive("E:") == "E:"
    assert source_drive.normalize_source_drive("e:\\") == "E:"
    assert source_drive.normalize_source_drive(" E:/ ") == "E:"
    assert source_drive.normalize_source_drive("E:\\case") is None
    assert source_drive.normalize_source_drive(None) is None


def test_explicit_non_boot_source_drive_requires_true_non_boot_claim() -> None:
    assert source_drive.has_explicit_non_boot_source_drive("e:\\", True) is True
    assert source_drive.has_explicit_non_boot_source_drive("C:", True) is False
    assert source_drive.has_explicit_non_boot_source_drive("E:", False) is False
    assert source_drive.has_explicit_non_boot_source_drive("E:", None) is False


def test_an_image_file_read_on_the_host_may_label_its_system_volume_c():
    image = "host_sleuthkit_read_only"
    assert source_drive.has_explicit_non_boot_source_drive("C:", True, mount_mode=image) is True
    assert source_drive.has_explicit_non_boot_source_drive("C:", False, mount_mode=image) is False
    assert source_drive.has_explicit_non_boot_source_drive("not a drive", True, mount_mode=image) is False
    assert source_drive.has_explicit_non_boot_source_drive("C:", True, mount_mode="windows_mounted_volume") is False
