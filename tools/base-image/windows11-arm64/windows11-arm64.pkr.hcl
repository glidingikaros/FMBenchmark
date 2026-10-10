
packer {
  required_plugins {
    qemu = {
      version = "= 1.1.7"
      source  = "github.com/hashicorp/qemu"
    }
  }
}


variable "iso_path" {
  type        = string
  description = "Absolute path to Microsoft's Windows 11 ARM64 ISO (you download it and accept Microsoft's licence)."
}

variable "iso_sha256" {
  type        = string
  description = "SHA-256 of the ISO, from Microsoft's download page (lowercase hex, no prefix)."
}

variable "drivers_dir" {
  type        = string
  description = <<-EOT
    Absolute path to a directory holding the ARM64 NIC driver (NetKVM) laid out
    as  NetKVM/w11/ARM64/*.inf . make-answer-media.sh copies this onto the answer
    ISO under $WinPEDriver$/ so Windows Setup installs it. Point it at the
    extracted virtio-win ISO root, or a pruned copy containing just NetKVM.
  EOT
}

variable "answer_media" {
  type        = string
  default     = ""
  description = "Answer ISO (autounattend.xml + scripts + NetKVM driver) built by make-answer-media.sh; empty means build/answer.iso next to this template."
}

variable "output_dir" {
  type        = string
  default     = ""
  description = "Directory Packer creates for the build (the qcow2 and efivars.fd land here); empty means output/windows-11-arm64 next to this template."
}

locals {
  answer_media = var.answer_media != "" ? var.answer_media : "${path.root}/build/answer.iso"
  output_dir   = var.output_dir != "" ? var.output_dir : "${path.root}/output/windows-11-arm64"
}

variable "cpus" {
  type        = number
  default     = 4
  description = "vCPUs for the build VM."
}

variable "memory" {
  type        = number
  default     = 8192
  description = "Build VM RAM in MB."
}

variable "disk_size" {
  type        = string
  default     = "64G"
  description = "System disk size (matches the retained VMware base box's 64 GiB)."
}


variable "qemu_binary" {
  type        = string
  default     = "qemu-system-aarch64"
  description = "QEMU binary; the default resolves on PATH from Homebrew."
}

variable "efi_firmware_code" {
  type        = string
  default     = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
  description = "Read-only EDK2 CODE pflash image (Homebrew QEMU)."
}

variable "efi_firmware_vars" {
  type        = string
  default     = "/opt/homebrew/share/qemu/edk2-arm-vars.fd"
  description = "EDK2 VARS template; Packer copies it to <output_dir>/efivars.fd and the guest writes that copy."
}

source "qemu" "win11arm64" {
  iso_url      = var.iso_path
  iso_checksum = "sha256:${var.iso_sha256}"

  qemu_binary = var.qemu_binary
  machine_type = "virt,gic-version=3,its=off,highmem=on"
  accelerator  = "hvf"
  cpu_model    = "host"
  cpus         = var.cpus
  memory       = var.memory

  efi_boot          = true
  efi_firmware_code = var.efi_firmware_code
  efi_firmware_vars = var.efi_firmware_vars

  disk_size = var.disk_size
  format    = "qcow2"

  net_device = "virtio-net-pci"

  output_directory = local.output_dir
  vm_name          = "windows-11-arm64-base.qcow2"
  disk_compression = true

  headless         = true
  vnc_bind_address = "127.0.0.1"

  boot_wait    = "5s"
  boot_command = ["<enter><wait2><enter><wait2><enter><wait2><enter>"]

  communicator   = "winrm"
  winrm_username = "vagrant"
  winrm_password = "vagrant"
  winrm_use_ssl  = false
  winrm_insecure = true
  winrm_timeout  = "2h"

  shutdown_command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\fmb\\scripts\\shutdown.ps1"
  shutdown_timeout = "15m"

  qemuargs = [
    ["-drive", "if=pflash,unit=0,format=raw,readonly=on,file=${var.efi_firmware_code}"],
    ["-drive", "if=pflash,unit=1,format=raw,file={{ .OutputDir }}/efivars.fd"],

    ["-drive", "if=none,id=nvme0,file={{ .OutputDir }}/{{ .Name }},format=qcow2,cache=writeback,discard=unmap"],
    ["-device", "nvme,drive=nvme0,serial=fmb-base,bootindex=1"],

    ["-drive", "if=none,id=install,media=cdrom,readonly=on,format=raw,file=${var.iso_path}"],
    ["-device", "usb-storage,drive=install,removable=on,bootindex=0"],

    ["-drive", "if=none,id=answer,media=cdrom,readonly=on,format=raw,file=${local.answer_media}"],
    ["-device", "usb-storage,drive=answer,removable=on"],

    ["-device", "qemu-xhci,id=xhci"],
    ["-device", "usb-kbd"],
    ["-device", "usb-tablet"],
    ["-device", "ramfb"],

    ["-device", "virtio-net-pci,netdev=user.0"],
  ]
}

build {
  name    = "windows-11-arm64-base"
  sources = ["source.qemu.win11arm64"]

  provisioner "powershell" {
    inline = [
      "Write-Output 'WinRM reachable; first-logon provisioning marker:'",
      "$deadline = (Get-Date).AddMinutes(15); while (-not (Test-Path C:\\fmb\\first-logon-complete.txt) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }",
      "if (Test-Path C:\\fmb\\first-logon-complete.txt) { Get-Content C:\\fmb\\first-logon-complete.txt } else { Write-Output 'MISSING' }",
    ]
  }
}
