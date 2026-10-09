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
Windows 11 ARM64 under VMware Fusion (`tools/base-image/windows11-arm64`); on Linux hosts the same guest
definition runs on QEMU with a Windows 11 x64 base built from Microsoft's ISO
(`tools/base-image/windows11-x64`). The question definitions, the protocol and the data contracts of every
interface are in `src/fmb/contracts`.

## Using it

```bash
uv sync --locked --all-extras
uv run fmb setup --check     # what this machine still needs
uv run fmb setup             # on Linux: uv run fmb setup --iso ~/Downloads/Windows11_Client_x64_en-us_26300_9457.iso
uv run fmb generate I1       # a disk image with its ground truth
uv run fmb run I1            # the pipeline, S1 to S4, scored against that ground truth
```

Replicating the paper is `fmb generate I1 I2 I3` and `fmb run I1 I2 I3`. An image replicates when its
strict admission passes, which requires S3 to answer all nine questions exactly.

### Hosts

| Host | Guest engine | Windows guest |
|---|---|---|
| macOS on Apple silicon | VMware Fusion through Vagrant, the paper's setup | Windows 11 ARM64, the paper's box |
| Linux x86-64 | QEMU with KVM | Windows 11 Pro x64, built from Microsoft's ISO |

Windows hosts are not supported yet: the base builds and the images generate under the Windows Hypervisor
Platform, but collecting their evidence still fails on a fresh machine.

You need [uv](https://docs.astral.sh/uv/), a clone of this repository, internet access during setup, and
about 40 GB of free disk per image in flight plus about 10 GB for the Windows base.

**Linux** (Debian or Ubuntu): `sudo apt-get update && sudo apt-get install qemu-system-x86 qemu-utils ovmf`.
On Fedora, `sudo dnf install qemu-system-x86-core qemu-img edk2-ovmf`; on Arch,
`sudo pacman -S qemu-system-x86 qemu-img edk2-ovmf`; on openSUSE,
`sudo zypper install qemu-x86 qemu-tools qemu-ovmf-x86_64`. Your user needs read-write access to
`/dev/kvm`: if it lacks it, run `sudo usermod -aG kvm $USER` and log in again. Download Microsoft's Windows
11 ISO yourself (its links last a day): on
[microsoft.com/software-download/windows11](https://www.microsoft.com/software-download/windows11) choose
*Windows 11 (multi-edition ISO for x64 devices)*, then *English (United States)*. The file is
`Windows11_Client_x64_en-us_26300_9457.iso`, and setup checks its SHA-256. Microsoft offers only its
current build; for a newer one, add `--unpinned-iso`, and every result records the build and the ISO's
SHA-256.

**macOS**: VMware Fusion 13, Vagrant with the `vagrant-vmware-desktop` plugin, Ansible
(`brew install ansible`), and the paper's box, built with
`tools/base-image/windows11-arm64/build-vmware-box.sh`.

### `fmb setup`

`fmb setup --check` checks this machine and prints the command that fixes anything missing. `fmb setup`
installs the pinned .NET runtime, Ansible and collection tools under `~/.cache/fmb` (or `FMB_CACHE`); on
Linux it also builds the Windows base from the ISO, once, in about 30 minutes.

### `fmb generate`

`images/` holds one JSON file per image: `I1.json`, `I2.json` and `I3.json` are the paper's images,
`template.json` is the starting point for your own, and `decoys.json` is an example (I3 with twice as many
untouched objects around the same manipulations). `fmb generate NAME` builds `images/NAME.json` into
`generated/NAME/`: the disk image, its ground truth and the receipts of every generation task. Without a
name it lists `images/` and asks. An image takes about an hour; on Linux, the first image after a base build
waits about 70 minutes, until the guest's clock is past the base build's last events. A boot or
provisioning failure is retried with the same frozen recipe, up to `--attempts` times (default 3).

To make your own image, copy `images/template.json` to `images/<name>.json` and edit:

- `seed`, which picks the objects' names and folders and the virtual hardware;
- `scenarios`: how many objects each anti-forensic technique creates (`configured_count`). Its guest
  script fixes how many of them it manipulates, so `manipulation_count` keeps the paper's value;
- `native_pilot_parameters.case_classes`: each question's supplementary cases and controls, at most as
  many of each as I3 has.

`fmb generate` checks the file before it starts and says what does not fit: all fourteen scenarios stay,
and the USB, NTFS-allocation and event-log scenarios keep their number of objects. The paper's image files
must match the released definitions. Which objects are manipulated is drawn when the recipe is frozen, so
two images from one file share a population, not a disk.

### `fmb run`

`fmb run NAME` runs S1 to S4 on `generated/NAME/` and scores the result against its ground truth. Without
a name it lists the generated images and asks, then asks at which stage of Figure 1 to compare an LLM.
Only S3 can be compared for now: `--compare S3 --llm CONDITION` sends the same evidence cards to that
model (S3'), three passes as in the paper. The conditions are the paper's eight, listed by
`fmb run --help`; they need `OPENAI_API_KEY` or `OPENROUTER_API_KEY`. `--cap-usd` is the most the LLM
requests of one image may cost, and the run sends nothing that could exceed it; a condition without a
recorded price also needs `--price CONDITION=INPUT,OUTPUT`, in US dollars per million tokens. As in the
paper, the LLM is asked only about images that pass admission. Without `--llm` nothing is sent.

The terminal shows a headline per image: admission, S3's exact questions and F1, and each LLM condition's
range over its passes and its cost. Everything else is in `results/NAME/<time>/`:

- `report.md`: the headline, the image, the paper's results table, every question for S3 and each pass of
  S3', the assessors' settings, and every receipt with its SHA-256;
- `receipts/`: the image definition, the generation recipe, `ground_truth.json`, `finding_reference.json`
  and the receipts of every generation task;
- `run/`: the data interfaces G1 to G5, `run-manifest.json` and the sealed stage outputs;
- `summary.json`: the headline in JSON.

### Changing the code

New techniques, questions or rules are code changes:

| To add | Change |
|---|---|
| A technique | Its Ansible task in `src/fmb/generation/ansible/roles/manipulation/tasks/`, its scenario in `SCENARIO_ANALYSIS` (`src/fmb/generation/population.py`) and in your population file, its definition in `src/fmb/analysis/catalog.py`, and its rule in `src/fmb/analysis/shared_rules.py` |
| A supplementary case | `CASE_CLASSES` in `src/fmb/generation/pilot_profile.py`, its construction in `src/fmb/generation/ansible/roles/manipulation/files/pilot_challenge.ps1`, and its expected answer in `src/fmb/evaluation/factual_reference.py` |
| A question | A question pack in `src/fmb/contracts/questions/`, `QIDS` in `src/fmb/core/case_contract.py`, and its rule; collection, preparation and evaluation assume the nine-question roster, so let the tests guide you |
| An S3 engine or a stage implementation | `ENGINES` in `src/fmb/assessment/stage.py`, or `IMPLEMENTATIONS` in `src/fmb/pipeline/implementations.py` |

The paper's images run with the released code only: `fmb generate` and `fmb run` stop if any file differs.
Your own images also run with changed code; `summary.json` and `report.md` list the changed files, and each
run keeps a copy of the code it ran.

## Licence

MIT (`LICENSE`), except the `$LogFile` driver `tools/dfir_ntfs/fmb_logfile_records.py`, which is
GPL-3.0-or-later (`LICENSES/`). Third-party components are listed in `THIRD_PARTY_NOTICES.md`.
