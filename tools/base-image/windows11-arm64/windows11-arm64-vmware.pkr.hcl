
packer {
  required_plugins {
    vmware = {
      version = "= 1.2.0"
      source  = "github.com/hashicorp/vmware"
    }
    vagrant = {
      version = "= 1.1.7"
      source  = "github.com/hashicorp/vagrant"
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

variable "answer_iso" {
  type        = string
  description = "Answer CD (rendered autounattend.xml and scripts/) that build-vmware-box.sh makes with make-answer-media.sh."
}

variable "tools_iso" {
  type        = string
  default     = "/Applications/VMware Fusion.app/Contents/Library/isoimages/arm64/windows.iso"
  description = "VMware Tools for Windows on ARM, shipped with VMware Fusion."
}

variable "work_dir" {
  type        = string
  default     = ""
  description = "Folder for the build VM, the box and guest-build.txt; empty means next to this template."
}

variable "rtc_start_time" {
  type        = string
  description = "Guest boot clock, rtc.startTime in Unix seconds. build-vmware-box.sh passes now minus the generator's boot clock bias (480 minutes)."
}

variable "cpus" {
  type    = number
  default = 2
}

variable "memory" {
  type    = number
  default = 4096
}

variable "disk_size_mb" {
  type        = number
  default     = 65536
  description = "System disk size in MB; 64 GiB like the study's base."
}

variable "winrm_timeout" {
  type        = string
  default     = "6h"
  description = "How long Packer waits for the guest's WinRM before it deletes the VM. On a USB hard disk Setup and the first-logon Tools install alone took about 1.5 h."
}

locals {
  work_dir       = var.work_dir != "" ? var.work_dir : path.root
  output_dir     = "${local.work_dir}/output/vmware"
  box_path       = "${local.work_dir}/output/fmb-windows-11-arm64-vmware.box"
  build_info_dir = "${local.work_dir}/build"
}

source "vmware-iso" "win11arm64" {
  iso_url      = var.iso_path
  iso_checksum = "sha256:${var.iso_sha256}"

  guest_os_type = "arm-windows11-64"
  firmware      = "efi"
  version       = 20
  cpus          = var.cpus
  memory        = var.memory

  disk_size          = var.disk_size_mb
  disk_adapter_type  = "nvme"
  disk_type_id       = "1"
  cdrom_adapter_type = "sata"

  network              = "nat"
  network_adapter_type = "vmxnet3"
  usb                  = true


  headless     = true
  boot_wait    = "3s"
  boot_command = ["<spacebar><wait1><spacebar><wait1><spacebar>"]

  communicator   = "winrm"
  winrm_username = "vagrant"
  winrm_password = "vagrant"
  winrm_use_ssl  = false
  winrm_insecure = true
  winrm_timeout  = var.winrm_timeout

  shutdown_command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\fmb\\scripts\\shutdown.ps1"
  shutdown_timeout = "15m"

  output_directory = local.output_dir
  vm_name          = "box"
  vmx_data = {
    "sata0:1.present"        = "TRUE"
    "sata0:1.deviceType"     = "cdrom-image"
    "sata0:1.fileName"       = var.answer_iso
    "sata0:1.startConnected" = "TRUE"
    "sata0:2.present"        = "TRUE"
    "sata0:2.deviceType"     = "cdrom-image"
    "sata0:2.fileName"       = var.tools_iso
    "sata0:2.startConnected" = "TRUE"
    "usb_xhci.present"      = "TRUE"
    "usb_xhci:4.present"    = "TRUE"
    "usb_xhci:4.deviceType" = "hid"
    "usb_xhci:4.port"       = "4"
    "usb_xhci:4.parent"     = "-1"
    "usb_xhci:6.present"    = "TRUE"
    "usb_xhci:6.deviceType" = "hub"
    "usb_xhci:6.port"       = "6"
    "usb_xhci:6.parent"     = "-1"
    "usb_xhci:6.speed"      = "2"
    "usb_xhci:7.present"    = "TRUE"
    "usb_xhci:7.deviceType" = "hub"
    "usb_xhci:7.port"       = "7"
    "usb_xhci:7.parent"     = "-1"
    "usb_xhci:7.speed"      = "4"
    "rtc.startInUTC" = "TRUE"
    "rtc.startTime"  = var.rtc_start_time
  }
  vmx_data_post = {
    "sata0:1.present"        = "FALSE"
    "sata0:1.startConnected" = "FALSE"
    "sata0:1.fileName"       = ""
    "sata0:2.present"        = "FALSE"
    "sata0:2.startConnected" = "FALSE"
    "sata0:2.fileName"       = ""
  }
}

build {
  name    = "fmb-windows-11-arm64-vmware"
  sources = ["source.vmware-iso.win11arm64"]

  provisioner "powershell" {
    inline = [
      "$deadline = (Get-Date).AddMinutes(15); while (-not (Test-Path C:\\fmb\\first-logon-complete.txt)) { if ((Get-Date) -gt $deadline) { throw 'first-logon provisioning did not complete' }; Start-Sleep -Seconds 5 }",
    ]
  }

  provisioner "windows-restart" {
    restart_timeout = "60m"
  }

  provisioner "windows-restart" {
    restart_command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\fmb\\scripts\\repair-vmware-tools.ps1"
    restart_timeout = "60m"
  }

  provisioner "powershell" {
    inline = [
      "if (-not (Get-Service -Name VMTools -ErrorAction SilentlyContinue)) { throw 'VMware Tools are not installed' }",
      "$deadline = (Get-Date).AddMinutes(15); while ((Get-Service -Name VMTools).Status -ne 'Running') { if ((Get-Date) -gt $deadline) { throw 'the VMware Tools service is not running' }; Start-Sleep -Seconds 10 }",
      "(Get-CimInstance Win32_OperatingSystem).BuildNumber | Set-Content -Encoding ascii C:\\fmb\\guest-build.txt",
    ]
  }

  provisioner "powershell" {
    inline = [
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\fmb\\scripts\\offline-base.ps1",
      "if ($LASTEXITCODE -ne 0) { throw \"offline-base.ps1 exited with code $LASTEXITCODE\" }",
    ]
  }

  provisioner "file" {
    direction   = "download"
    source      = "C:\\fmb\\guest-build.txt"
    destination = "${local.build_info_dir}/guest-build.txt"
  }

  post-processor "vagrant" {
    name                = "box"
    output              = local.box_path
    keep_input_artifact = false
  }
}
