# FMBenchmark

The code of the framework and the image generator from the paper *Can LLMs Spot Anti-Forensics? A Modular
Framework for Benchmarking Large Language Models in Disk Forensics*.

![Figure 1: technique-driven forensic assessment](assets/figure1.svg)

*Figure 1 of the paper.* A forensic question, each targeting one anti-forensic technique, selects the
artefacts collected from a disk image and prepared as shared evidence cards. A deterministic engine (S3)
and an LLM (S3′) receive the same case input and produce independent predictions; neither sees the other's
output or the ground truth. Their result sets are compared and scored against ground truth. **S** labels
processing stages, **G** labels data interfaces.

## Architecture

The code follows Figure 1. `src/fmb/pipeline` runs the stages S1 to S4 for one case and writes each data
interface G1 to G5 as a JSON file; every stage reads only the interfaces before it.

| Figure 1 | | Code |
|---|---|---|
| Disk image | A synthetic Windows 11 NTFS case and its recorded ground truth | `src/fmb/generation` |
| G1 | Evidence image | |
| S1 | Resolve profile: the question's artefact families, collection targets and parser outputs | `src/fmb/profiles.py`, `src/fmb/question_packs.py` |
| G2 | Artefact profile | |
| S2 | Collect and prepare: parse the artefacts, list all subjects, cut one evidence card per subject | `src/fmb/collection`, `src/fmb/index`, `src/fmb/preparation` |
| G3 | Evidence cards | |
| S3 | Deterministic assessment with fixed forensic rules | `src/fmb/assessment`, `src/fmb/analysis` |
| S3′ | LLM assessment of the same cards with the generic forensic question | `src/fmb/assessment/llm.py`, `src/fmb/interpretation` |
| G4 | Result sets, separate for each engine | |
| S4 | Compare and score both against ground truth | `src/fmb/evaluation` |
| G5 | Evaluation report | |

The generator freezes a recipe for each paper image (I1, I2, I3), boots a Windows guest from a base image,
plays the scenario's activity and anti-forensic techniques through Ansible
(`src/fmb/generation/ansible`) and exports the disk image with its ground truth. The paper's guest is
Windows 11 ARM64 under VMware Fusion (`tools/base-image/windows11-arm64`); on Linux and Windows hosts the
same guest definition runs on QEMU with a Windows 11 x64 base built from Microsoft's ISO
(`tools/base-image/windows11-x64`). The question definitions, the protocol and the data contracts of every
interface are in `src/fmb/contracts`.

## Replicating the paper

`fmb replicate` generates I1, I2 and I3 on your machine, collects their evidence and runs S1 to S4 with
the deterministic engine. An image replicates when strict admission passes, which requires S3 to answer
all nine questions exactly. The LLM conditions are frozen but not dispatched, so no provider account is
needed.

| Host | Guest engine | Windows guest |
|---|---|---|
| macOS on Apple silicon | VMware Fusion through Vagrant, the paper's setup | Windows 11 ARM64, the paper's box |
| Linux x86-64 | QEMU with KVM | Windows 11 Pro x64, built from Microsoft's ISO |
| Windows x64 | QEMU with Windows Hypervisor Platform; Ansible in WSL 1 | Windows 11 Pro x64, built from Microsoft's ISO |

### Requirements

- [uv](https://docs.astral.sh/uv/) and a clone of this repository;
- about 40 GB of free disk per image in flight, plus about 10 GB for the Windows base;
- internet access during setup.

On Linux and Windows, also Microsoft's Windows 11 ISO, which you download yourself (its links last a
day): on [microsoft.com/software-download/windows11](https://www.microsoft.com/software-download/windows11)
choose *Windows 11 (multi-edition ISO for x64 devices)*, then *English (United States)*. The file is
`Windows11_Client_x64_en-us_26300_9457.iso`, and setup checks its SHA-256. Microsoft offers only its
current build; for a newer one, add `--unpinned-iso` to setup, and every result records the build and the
ISO's SHA-256.

**Linux** (Debian or Ubuntu)

```bash
sudo apt-get update && sudo apt-get install qemu-system-x86 qemu-utils ovmf
```

On Fedora, `sudo dnf install qemu-system-x86-core qemu-img edk2-ovmf`; on Arch,
`sudo pacman -S qemu-system-x86 qemu-img edk2-ovmf`; on openSUSE,
`sudo zypper install qemu-x86 qemu-tools qemu-ovmf-x86_64`. Your user needs read-write access to
`/dev/kvm`: if it lacks it, run `sudo usermod -aG kvm $USER` and log in again.

**Windows** (an administrator PowerShell, then one reboot)

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -PropertyType DWord -Force
winget install SoftwareFreedomConservancy.QEMU
wsl --install -d Ubuntu-24.04 --no-launch
wsl --set-version Ubuntu-24.04 1
```

**macOS**: VMware Fusion 13, Vagrant with the `vagrant-vmware-desktop` plugin, Ansible
(`brew install ansible`), and the paper's box, built with
`tools/base-image/windows11-arm64/build-vmware-box.sh`.

### Run

```bash
uv sync --locked --all-extras
uv run fmb replicate doctor
uv run fmb replicate setup --iso ~/Downloads/Windows11_Client_x64_en-us_26300_9457.iso
uv run fmb replicate run I1 I2 I3
```

- `doctor` checks the host and prints the command that fixes anything missing.
- `setup` installs the pinned .NET runtime, Ansible and collection tools under `~/.cache/fmb` (or
  `FMB_CACHE`). On Linux and Windows it also builds the Windows base from the ISO, once, in about 30 to
  50 minutes. On macOS it takes no `--iso`.
- `run` writes each image to `replication/<image>/` and `replication/summary.json`, which lists per image
  the admission result, the number of exact questions and F1. An image takes about an hour. On Linux and
  Windows, the first image after a base build waits about 70 minutes before generating, until the guest's
  clock is past the base build's last events.

Generation retries a boot or provisioning failure with the same frozen recipe, up to `--attempts` times
(default 3). Images are never bit-identical: each frozen recipe draws a fresh random assignment. What
replicates is the protocol and the result.

## Licence

MIT (`LICENSE`), except the `$LogFile` driver `tools/dfir_ntfs/fmb_logfile_records.py`, which is
GPL-3.0-or-later (`LICENSES/`). Third-party components are listed in `THIRD_PARTY_NOTICES.md`.
