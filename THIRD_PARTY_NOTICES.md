# Third-party components

This repository contains no third-party code or data except where stated below. The listed tools are
used as separate programs or dependencies; they are not redistributed here unless stated.

| Component | Licence | How it is used | Source |
|---|---|---|---|
| dfir_ntfs (Maxim Suhanov) | GPL-3.0 | `$LogFile` parsing, run as a separate process by the GPL-3.0-or-later driver `tools/dfir_ntfs/fmb_logfile_records.py` (outside the MIT package); installed separately, not vendored | https://github.com/msuhanov/dfir_ntfs |
| KapeFiles target and module definitions (Eric Zimmerman and contributors) | MIT | **Vendored:** the 32 definitions the collector uses, from commit `c47575d8` (12 Dec 2022) with annotations removed, with their licence, in `src/fmb/collection/tools/kape/assets/kapefiles/` | https://github.com/EricZimmerman/KapeFiles |
| EvtxECmd Maps (Eric Zimmerman and contributors) | MIT | Event-log maps for EvtxECmd, written by `scripts/bootstrap_eztools.py` from commit `503bd274` (5 Dec 2022) plus three maps from `5aa1d999` (13 Jul 2022); not redistributed | https://github.com/EricZimmerman/evtx |
| RECmd batch files (Eric Zimmerman and contributors) | MIT | `Kroll_Batch.reb` and other batch examples, written by `scripts/bootstrap_eztools.py` from commit `36ebdaeb` (11 Sep 2022); not redistributed | https://github.com/EricZimmerman/RECmd |
| MFTECmd, EvtxECmd, RECmd, LECmd, JLECmd, AmcacheParser, AppCompatCacheParser, RegistryPlugins (Eric Zimmerman) | MIT | Parsers built from the pinned sources in `src/fmb/collection/tools/host/eztools-lock.json`; the built bytes are redistributed in `tools/eztools/eztools-net9-locked.tar.gz` (with PECmd's source build), next to `tools/eztools/EZTOOLS-LICENSES.txt` holding each upstream MIT licence | https://github.com/EricZimmerman |
| PECmd (Eric Zimmerman) | MIT | Prefetch parser; it runs only on Windows, so the Windows parser VM uses the official download (validated builds listed in the lock), which is not redistributed; its source build is in `tools/eztools/eztools-net9-locked.tar.gz` | https://github.com/EricZimmerman/PECmd |
| SBECmd (Eric Zimmerman) | Freeware, no source release | ShellBags parser run in the Windows parser VM; download from the author (validated builds listed in the lock); not redistributed | https://ericzimmerman.github.io |
| python-evtx (Willi Ballenthin) | Apache-2.0 | Optional dependency | https://github.com/williballenthin/python-evtx |
| python-registry (Willi Ballenthin) | Apache-2.0 | Optional dependency | https://github.com/williballenthin/python-registry |
| jsonschema, PyYAML | MIT | Dependencies | PyPI |
| pytsk3 20260715 (bindings for The Sleuth Kit 4.15.0, which it includes with talloc) | Apache-2.0; The Sleuth Kit CPL-1.0 and IBM Public License 1.0; talloc LGPL-3.0-or-later | Optional `collection` dependency: the collection stage reads the evidence image through it (collected files, native NTFS surfaces, USB companion volumes); used as a library, not vendored | https://github.com/py4n6/pytsk |
| libvmdk-python 20260714 (libvmdk) | LGPL-3.0-or-later | Optional `collection` dependency: VMDK images are read through it; used as a library, not vendored. The LGPL permits this dynamic use from MIT code | https://github.com/libyal/libvmdk |
| pefile (Ero Carrera) | MIT | Dependency: decodes the PE/COFF headers of named-stream content | https://github.com/erocarrera/pefile |
| QEMU `qemu-img`, `qemu-io` | GPL-2.0 | Image export, and the generator's edits of exported images; external programs | https://www.qemu.org |
| Vagrant, VMware Fusion | BUSL-1.1 / proprietary | VM provisioning and hypervisor for image generation, external | vendors |
| Windows 11 (Microsoft) | Microsoft licence | Guest operating system of the generated images; the base box and full disk images are not redistributed | Microsoft |

KAPE (Kroll Artifact Parser and Extractor) is a product of Kroll. This work is not affiliated with or endorsed
by Kroll; it executes the community KapeFiles definitions and does not include or require kape.exe.
