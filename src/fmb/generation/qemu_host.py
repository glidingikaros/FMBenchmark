from __future__ import annotations

from pathlib import Path

QEMU_ACCELERATORS = {"Linux": "kvm", "Windows": "whpx", "Darwin": "hvf"}
QEMU_CPU = {"kvm": "host,-vmx,-svm,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time", "whpx": "max,-vmx,-svm",
            "hvf": "host"}
QEMU_FIRMWARE = (
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("share/edk2-x86_64-code.fd", "share/edk2-i386-vars.fd"),
    ("../share/qemu/edk2-x86_64-code.fd", "../share/qemu/edk2-i386-vars.fd"),
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ("/usr/share/qemu/ovmf-x86_64-4m-code.bin", "/usr/share/qemu/ovmf-x86_64-4m-vars.bin"),
)


def uefi_firmware(qemu: Path) -> tuple[Path, Path]:
    for code, variables in QEMU_FIRMWARE:
        pair = (qemu.parent / code).resolve(), (qemu.parent / variables).resolve()
        if pair[0].is_file() and pair[1].is_file():
            return pair
    raise FileNotFoundError(f"no x86-64 UEFI firmware (OVMF) beside {qemu} or where Debian, Ubuntu, Fedora, Arch or "
                            "openSUSE install it: install your distribution's OVMF package (ovmf or edk2-ovmf)")
