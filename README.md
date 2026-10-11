# FMBenchmark

![Figure 1: the pipeline of the paper](assets/figure1.svg)

*Figure 1 of the paper.* S1 to S4 are the processing stages. G1 to G5 are the data interfaces. S3 (rules)
and S3′ (LLM) receive the same evidence cards. S4 scores the two result sets against the ground truth.

## Function

FMBenchmark does three tasks:

1. It prepares the host.
2. It generates a synthetic Windows disk image with known anti-forensic manipulations. It records the
   ground truth.
3. It runs the pipeline (S1 to S4) on the image. It scores S3 and, as an option, S3′ against the ground
   truth.

| Command | Function |
|---|---|
| `fmb setup --check` | Checks the host. Shows the missing items and the commands that install them. |
| `fmb setup` | Installs the pinned tools. On Linux and Windows, builds the Windows base from the ISO (approximately 30 min). |
| `fmb generate NAME` | Generates `images/NAME.json` into `generated/NAME/` (approximately 1 h). |
| `fmb run NAME` | Runs S1 to S4 on `generated/NAME/`. Writes `results/NAME/<time>/`. |

Without `NAME`, `fmb generate` and `fmb run` show the choices and ask.

## Procedure

1. Install [uv](https://docs.astral.sh/uv/). Clone this repository.
2. Install the host requirements (see [Hosts](#hosts)).
3. Run `uv sync --locked --all-extras`.
4. Run `uv run fmb setup --check`. Correct each item that shows `NO`.
5. Run `uv run fmb setup`. On Linux and Windows, add `--iso <path of the ISO>`.
6. Run `uv run fmb generate I1`.
7. Run `uv run fmb run I1`.

To replicate the paper, generate and run I1, I2 and I3. An image replicates when its admission passes. For
admission, S3 must be exact on all the questions of the image (nine for the images of the paper).

The first image after a base build waits until approximately 5 min after the build. The guest clock must be after the
last event of the base build.

If you stop `fmb generate` (Ctrl-C, closing the terminal or `kill`), it removes its virtual machine first. If a
crash leaves one behind, `fmb setup --check` lists it and the next `fmb generate` removes it. On macOS, Windows
activity in the guest sometimes overwrites a timestamp change in the `$LogFile` before the export. `fmb generate`
then deletes the disk of that attempt and tries again with the same recipe.

## Images

`images/` contains one JSON file for each image.

| File | Content |
|---|---|
| `I1.json`, `I2.json`, `I3.json` | The images of the paper. FMBenchmark compares them with the released definitions. |
| `template.json` | The start point for a new image. |

To make a new image:

1. Copy `images/template.json` to `images/<name>.json`.
2. Change `seed`. The seed sets the object names, the folders and the virtual hardware.
3. For each scenario in `scenarios`, set `configured_count` (the number of objects) and `manipulation_count` (the
   number of manipulated objects, 1 to `configured_count`).
4. As an option, remove questions. Remove all the scenarios of a question from `experiments.full_scale` and from
   `scenarios`, and remove its cases from `native_pilot_parameters.case_classes`.
5. Change `native_pilot_parameters.case_classes`. This value sets the supplementary cases and controls for each
   question. Use each case not more times than I3 does.
6. As an option, add the `generation` settings.
7. Run `uv run fmb generate <name>`.

| Question | Scenarios |
|---|---|
| BQ-TIME-01 | `timestomp_01` |
| BQ-DELETE-01 | `typed_path_residue_01`, `usn_journal_01` |
| BQ-SHELLBAG-01 | `shellbag_path_residue_01` |
| BQ-DIRECTORY-01 | `directory_cleaning_i30_01` |
| BQ-STREAM-01 | `ads_injection_01` |
| BQ-USB-01 | `usbstor_setupapi_discrepancy_01`, `usb_volume_activity_gap_01` |
| BQ-FILE-01 | `bitmap_trailing_data_01`, `ntfs_allocation_01` |
| BQ-EXEC-01 | `prefetch_wipe_01`, `shimcache_path_residue_01` |
| BQ-LOG-01 | `security_log_clear_event_01`, `event_record_sequence_gap_01` |

| Scenario setting | Function |
|---|---|
| `assignment_pool_count` | FMBenchmark selects the manipulated objects from the first N objects. |
| `timestomp_01.restore_stratum_end_indexes` | Divides the objects into groups that end at these positions. In each group, FMBenchmark restores half of the objects from an archive. This sets older times. The last value is `configured_count`. |
| `ntfs_allocation_01.storage_modes` | One mode for each object: `ordinary`, `resident` or `preallocation_request_then_close`. FMBenchmark manipulates only `ordinary` objects. |
| `directory_cleaning_i30_01.directory_child_counts` | The number of files in each folder, 1 to 200. FMBenchmark cleans only folders with 22 files or more. |

| Generation setting | Function |
|---|---|
| `clock_bias_minutes` | The guest boots behind the true time by this value minus 480 minutes, and the generator then moves the clock forward. On Linux and Windows the guest boots at least 2 minutes behind. The guest's hardware clock starts at UTC minus this value on the Mac. On Linux and Windows, FMBenchmark corrects that start for the bias that Windows saved when the base was built (Pacific's offset that day: 420 in summer, 480 in winter). The generator never moves the clock back, so a value below 480 is refused, except on a Mac box built in summer (420). `"auto"` boots 2 minutes behind. The paper uses 480. |
| `activity_count` | The number of user actions before the manipulations, 1 to 500. The paper uses 12. |
| `activity_seed`, `hardware_seed` | The seeds of the user actions and of the virtual hardware. The default is `seed`. |

Limits:

- `security_log_clear_event_01` and `event_record_sequence_gap_01` have one object each. The image has one
  Security log.
- The two USB scenarios use the same 2 to 4 virtual drives. Each scenario changes one drive.
- `typed_path_residue_01` has 25 folders or fewer (Explorer keeps 25 typed paths). One folder or more stays.
- `ntfs_allocation_01` and `directory_cleaning_i30_01` have 100 objects or fewer.
- A question lists all its scenarios or none. In BQ-DELETE-01 and BQ-EXEC-01, one of the two scenarios can be
  empty: set its `configured_count` and `manipulation_count` to 0.

To make a random image inside these limits, run `uv run python scripts/random_image.py SEED images/random.json`.
The same seed gives the same file.

`fmb generate` checks the file before it starts and shows each item that is not correct. The recipe sets
the manipulated objects at random. Thus two images from one file have the same population, but not the
same disk. `fmb run` asks only the questions of the image.

## LLM comparison

`fmb run` asks for the stage of Figure 1 where it compares an LLM. At this time, only S3 is available.

| Option | Function |
|---|---|
| `--compare S3` | Compares an LLM (S3′) with S3. |
| `--llm CONDITION` | Selects an LLM condition: one of the eight conditions of the paper, or one of yours (`fmb run --help`). |
| `--conditions FILE` | Declares your own LLM conditions (see [Your conditions](#your-conditions)). |
| `--passes N` | Sets the number of passes of S3′, from 1 to 10. The default is 3, as in the paper. |
| `--cap-usd N` | Sets the maximum cost of the LLM requests for one image, in USD. Necessary with `--llm`. |
| `--price CONDITION=INPUT,OUTPUT` | Sets the price (USD for each million tokens) of a condition without a recorded price. |

- The conditions need `OPENAI_API_KEY` or `OPENROUTER_API_KEY`.
- S3′ uses three passes, as in the paper, unless `--passes` sets another number.
- FMBenchmark does not send a request that can make the cost more than the cap.
- FMBenchmark sends LLM requests only for an image that passes admission.
- Without `--llm`, FMBenchmark sends no request.

### Your conditions

A conditions file, for example `conditions/mine.json`, is a JSON object. Each key is the name of one of
your conditions. The names of the paper's conditions are not available. Each value has the structure of a
condition in `src/fmb/contracts/paper/protocol.json`:

```json
{
  "mistralsmall-t0": {
    "settings": {
      "provider": "openrouter",
      "model": "mistralai/mistral-small-2603",
      "route": "mistral/zdr",
      "reasoning_effort": "high",
      "max_output_tokens": 16384,
      "timeout_seconds": 600,
      "temperature": 0,
      "seed": 7,
      "price_usd_per_million": {"input": "0.150", "output": "0.600"}
    }
  }
}
```

- `provider`, `model`, `reasoning_effort`, `max_output_tokens` and `timeout_seconds` are necessary.
  `provider` is `openai` or `openrouter`. An `openrouter` condition also needs `route`: the one provider
  that OpenRouter can use.
- `context_window_tokens`, `temperature`, `top_p`, `seed` and `price_usd_per_million` are optional. The
  paper's conditions do not set `temperature`, `top_p` or `seed`. The requests send each setting, and
  OpenRouter refuses a route that does not take all of them.
- `upstream_provider`, next to `settings`, is the provider name that OpenRouter reports for the route,
  if that name is not the route (for example `DeepInfra` for `deepinfra/fp4`).
- Without `price_usd_per_million`, give the price with `--price`.
- Each result records the settings of the condition, in `run/conditions/NAME/protocol.json`, in the G4
  gate and in `run/run-manifest.json`.

For example: `uv run fmb run I1 --conditions conditions/mine.json --llm mistralsmall-t0 --cap-usd 5 --passes 2`.

## Results

The terminal shows a headline for each image: the admission, the exact questions and F1 of S3, and the
range and cost of each S3′ condition. `results/NAME/<time>/` contains:

| Item | Content |
|---|---|
| `report.md` | The headline, the image, the results table of the paper, the result of each question, the assessor settings, and each receipt with its SHA-256. |
| `receipts/` | The image definition, the generation recipe, `ground_truth.json`, `finding_reference.json`, and the receipt of each generation task. |
| `run/` | The data interfaces G1 to G5, `run-manifest.json` and the sealed stage outputs. |
| `summary.json` | The headline in JSON. |

## Hosts

| Host | Guest engine | Windows guest |
|---|---|---|
| macOS on Apple silicon | VMware Fusion through Vagrant (the setup of the paper) | Windows 11 ARM64, the box of the paper |
| Linux x86-64 | QEMU with KVM | Windows 11 Pro x64, built from the Microsoft ISO |
| Windows 11 x64 | QEMU with the Windows Hypervisor Platform | Windows 11 Pro x64, built from the Microsoft ISO |

Each host needs internet access during setup. While an image is generated and analysed, it needs free disk of
approximately the Windows guest plus 19 GB on macOS (45 GB with the box of the paper) and twice the Windows
base plus 10 GB on Linux and Windows (30 GB). `fmb setup --check` computes this for your machine. The Windows
base takes approximately 10 GB. A generated image keeps approximately 25 GB and a result approximately 2 GB.
`fmb run NAME --delete-image` deletes the image after a passing run; the result stays.

**Linux.** Install QEMU and OVMF:

- Debian, Ubuntu: `sudo apt-get install qemu-system-x86 qemu-utils ovmf`
- Fedora: `sudo dnf install qemu-system-x86-core qemu-img edk2-ovmf`
- Arch: `sudo pacman -S qemu-system-x86 qemu-img edk2-ovmf`
- openSUSE: `sudo zypper install qemu-x86 qemu-tools qemu-ovmf-x86_64`

A minimal or server installation may also need `git`, `curl`, `tar` and the ICU library (`libicu`, `icu` on
Arch). Your user needs read and write access to `/dev/kvm`. If it does not have it, run
`sudo usermod -aG kvm $USER` and log in again.

**Windows.** Use Windows 11 x64. In an administrator PowerShell, run these commands, then restart Windows:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -PropertyType DWord -Force
winget install SoftwareFreedomConservancy.QEMU
wsl --install -d Ubuntu-24.04 --no-launch
wsl --set-version Ubuntu-24.04 1
```

The Windows guest runs in QEMU with the Windows Hypervisor Platform, and Ansible runs in WSL 1. `fmb` works from
PowerShell 7 and from Windows PowerShell.

On Linux and Windows, download the Windows 11 ISO from
[microsoft.com/software-download/windows11](https://www.microsoft.com/software-download/windows11): select
*Windows 11 (multi-edition ISO for x64 devices)*, then *English (United States)*. The link is valid for one
day. `fmb setup` checks the SHA-256 of `Windows11_Client_x64_en-us_26300_9457.iso`. Microsoft replaces this ISO
from time to time. If the page offers a newer build, add `--unpinned-iso`. Each result then records the build
and the SHA-256 of the ISO. The results of the paper were checked on build 26300 (Linux, Windows and macOS)
and build 22000 (macOS, the box of the paper) only.

**macOS.** Install VMware Fusion 13, Vagrant with the `vagrant-vmware-desktop` plugin, and Ansible
(`brew install ansible`). Without the box of the paper, build a box from the Windows 11 ARM64 ISO: on
[microsoft.com/software-download/windows11arm64](https://www.microsoft.com/software-download/windows11arm64),
select *Windows 11 (multi-edition ISO for Arm64)*, then *English (United States)*. `fmb setup --check` names
the pinned file, `Windows11_Client_arm64_en-us_26300_9457.iso`, and the command that builds the box:
`tools/base-image/windows11-arm64/build-vmware-box.sh <ISO> <its SHA-256>`. The build needs Packer and
approximately 60 GB of free disk, and takes approximately 30 min. The box records its Windows build and its
ISO, and each result names them. I1, I2 and I3 replicate on a box built from the pinned ISO as on the box of
the paper.

## Code

The code follows Figure 1. `src/fmb/pipeline` runs S1 to S4 for one image. It writes each data interface
(G1 to G5) as a JSON file. Each stage reads only the interfaces before it.

| Figure 1 | Function | Code |
|---|---|---|
| Disk image | Generates a synthetic Windows 11 NTFS case and its ground truth | `src/fmb/generation` |
| S1 | Resolves the profile: artefact families, collection targets, parser outputs | `src/fmb/profiles.py`, `src/fmb/question_packs.py` |
| S2 | Collects and parses the artefacts. Lists all subjects. Makes one evidence card for each subject | `src/fmb/collection`, `src/fmb/index`, `src/fmb/preparation` |
| S3 | Assesses the cards with fixed forensic rules | `src/fmb/assessment`, `src/fmb/analysis` |
| S3′ | Assesses the same cards with an LLM and the generic forensic question | `src/fmb/assessment/llm.py`, `src/fmb/interpretation` |
| S4 | Compares the result sets and scores them against the ground truth | `src/fmb/evaluation` |

The question definitions, the protocol and the contracts of the data interfaces are in `src/fmb/contracts`.
The base images are in `tools/base-image/windows11-arm64` (macOS) and `tools/base-image/windows11-x64`
(Linux and Windows).

A new technique, case or question is a change to the code:

| Item | Change |
|---|---|
| Technique | The Ansible task in `src/fmb/generation/ansible/roles/manipulation/tasks/`, the scenario in `SCENARIO_ANALYSIS` and its receipt fields in `_SCENARIO_RECEIPT_FIELDS` (`src/fmb/generation/population.py`), the scenario in the image file, the definition in `src/fmb/analysis/catalog.py`, the phenomenon in `PHENOMENA` (`src/fmb/core/case_contract.py`), the rule in `src/fmb/analysis/shared_rules.py`, and the scenario in a question pack |
| Supplementary case | `CASE_CLASSES` in `src/fmb/generation/pilot_profile.py`, the construction in `src/fmb/generation/ansible/roles/manipulation/files/pilot_challenge.ps1`, and the expected answer in `src/fmb/evaluation/factual_reference.py` |
| Question | A question pack in `src/fmb/contracts/questions/`, `QIDS` in `src/fmb/core/case_contract.py`, and the rule. Collection, preparation and evaluation use the nine questions of the paper: use the tests as a guide |

Two checks name each missing part: `scenario_problems(scenario)` for a technique and `pack_problems(pack)` for a
question pack, both in `src/fmb/question_packs.py`. `tests/unit/test_extensibility.py` runs them on every
scenario and question.

The images of the paper run only with the released code. `fmb generate` and `fmb run` stop if a file is
different. Your images can run with changed code. The results record the changed files and keep a copy of
the code.

## Licence

MIT (`LICENSE`), except the `$LogFile` driver `tools/dfir_ntfs/fmb_logfile_records.py`, which is
GPL-3.0-or-later (`LICENSES/`). `THIRD_PARTY_NOTICES.md` lists the third-party components.
