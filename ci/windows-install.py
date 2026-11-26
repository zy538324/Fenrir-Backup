"""Install Windows Server (evaluation, Server Core) unattended in QEMU for the bare-metal restore test.

UEFI firmware (OVMF), an AHCI disk (Windows has the driver in the box), and an answer file on a second CD. The
answer file partitions the disk for UEFI (EFI, MSR, Windows), installs image 1 of the ISO (Server Core), and at the
first sign-in registers a start-up task. On every boot that task appends a line to C:\fenrir-boots.txt (and writes
FENRIR-WINDOWS-UP to the first serial port), then shuts Windows down. The proof is read from the disk itself after
the VM stops (losetup + ntfscat, read-only), so it does not depend on the serial port. The installed disk is booted
once and must have recorded that boot.

    sudo python3 ci/windows-install.py <windows.iso> <disk.raw> <work dir> [disk GiB]

Needs root (losetup), qemu-system-x86_64 with KVM, OVMF (/usr/share/OVMF), xorriso, ntfs-3g. 10 to 30 minutes with
KVM. Screens are captured every 30 s into the work dir; on failure Windows Setup's own logs are copied out too.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ISO, DISK, W = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()
GIB = int(sys.argv[4]) if len(sys.argv) > 4 else 32
OVMF = Path("/usr/share/OVMF")
PASSWORD = "Fenrir-CI-restore-1!"  # a throw-away VM with no network
MARKER = "FENRIR-WINDOWS-UP"

UP_CMD = f"""@echo off
echo %DATE% %TIME%>>C:\\fenrir-boots.txt
mode COM1: BAUD=115200 PARITY=n DATA=8 STOP=1 >nul
echo {MARKER}>COM1
shutdown /s /t 5 /f
"""

COMPONENT = ('processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" '
             'versionScope="nonSxS"')
UNATTEND = f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" {COMPONENT}>
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" {COMPONENT}>
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>1</Value></MetaData></InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData><AcceptEula>true</AcceptEula><ProductKey><WillShowUI>Never</WillShowUI></ProductKey></UserData>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" {COMPONENT}>
      <UserAccounts>
        <AdministratorPassword><Value>{PASSWORD}</Value><PlainText>true</PlainText></AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled><Username>Administrator</Username><LogonCount>1</LogonCount>
        <Password><Value>{PASSWORD}</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <OOBE><HideEULAPage>true</HideEULAPage><ProtectYourPC>3</ProtectYourPC></OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order>
          <CommandLine>cmd /c for %d in (D E F G H) do if exist %d:\\fenrir-up.cmd copy /y %d:\\fenrir-up.cmd C:\\fenrir-up.cmd</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add"><Order>2</Order>
          <CommandLine>schtasks /create /tn FenrirUp /sc onstart /ru SYSTEM /rl HIGHEST /f /tr C:\\fenrir-up.cmd</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add"><Order>3</Order>
          <CommandLine>cmd /c echo installed&gt;C:\\fenrir-installed.txt</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add"><Order>4</Order>
          <CommandLine>cmd /c mode COM1: BAUD=115200 PARITY=n DATA=8 STOP=1 &amp; echo FENRIR-INSTALLED&gt;COM1</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add"><Order>5</Order>
          <CommandLine>shutdown /s /t 10 /f</CommandLine></SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def qemu(name, *drives, vars_file, monitor=None):
    log = W / f"{name}.serial"
    log.unlink(missing_ok=True)
    cmd = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "4096",
           "-display", "none", "-vga", "std", "-nic", "none", "-rtc", "base=utc",
           "-drive", f"if=pflash,format=raw,unit=0,file={OVMF / 'OVMF_CODE_4M.fd'},readonly=on",
           "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
           "-drive", f"file={DISK},format=raw,if=none,id=sys,detect-zeroes=unmap,discard=unmap",
           "-device", "ide-hd,drive=sys,bus=ide.0,bootindex=1",
           "-serial", f"file:{log}", *drives]
    if monitor:
        cmd += ["-monitor", f"unix:{monitor},server,nowait"]
    return subprocess.Popen(cmd, stdout=open(W / f"{name}.qemu.log", "w"), stderr=subprocess.STDOUT), log


def part_loop(disk: Path, number: int) -> str:
    """A read-only loop device over partition `number` of a GPT disk image (offsets from sfdisk, so no partition
    device nodes are needed)."""
    table = json.loads(subprocess.run(["sfdisk", "--json", str(disk)], capture_output=True, text=True,
                                      check=True).stdout)["partitiontable"]
    sector = table.get("sectorsize", 512)
    p = table["partitions"][number - 1]
    return subprocess.run(["losetup", "-f", "-r", "--show", "-o", str(p["start"] * sector),
                           "--sizelimit", str(p["size"] * sector), str(disk)],
                          capture_output=True, text=True, check=True).stdout.strip()


def ntfs_files(disk: Path, paths: list[str], part: int = 3) -> dict[str, bytes | None]:
    """Read files from the Windows partition of a raw disk image, read-only (losetup, ntfscat)."""
    dev = part_loop(disk, part)
    try:
        out = {}
        for p in paths:
            r = subprocess.run(["ntfscat", dev, p], capture_output=True)
            out[p] = r.stdout if r.returncode == 0 else None
        return out
    finally:
        subprocess.run(["losetup", "-d", dev], check=False)


def boots(disk: Path) -> list[str]:
    raw = ntfs_files(disk, ["fenrir-boots.txt"])["fenrir-boots.txt"] or b""
    return [l for l in raw.decode("ascii", "replace").splitlines() if l.strip()]


SETUP_LOGS = ["Windows/Panther/setupact.log", "Windows/Panther/setuperr.log",
              "Windows/Panther/UnattendGC/setupact.log", "Windows/Panther/UnattendGC/setuperr.log"]


def keep_setup_logs(tag: str):
    """Copy Windows Setup's logs off the disk into the work dir, for the CI artifact."""
    try:
        for p, data in ntfs_files(DISK, SETUP_LOGS).items():
            if data:
                (W / f"{tag}-{p.replace('/', '_')}").write_bytes(data)
    except Exception as e:  # diagnostics only
        print("  could not read Setup's logs:", e)


def screens(sock_path: Path, stop: threading.Event):
    """A screen every 30 s (the last 4 kept), for the CI artifact."""
    n = 0
    while not stop.wait(30):
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(str(sock_path))
                s.sendall(f"screendump {W / f'screen-{n % 4}.ppm'}\n".encode())
                time.sleep(1)
            n += 1
        except OSError:
            pass


def text(log: Path) -> str:
    return log.read_bytes().decode("utf-8", "replace") if log.exists() else ""


def press_keys(sock_path: Path, seconds: int):
    """Answer the UEFI CD's "Press any key to boot from CD or DVD" by pressing Enter for a while."""
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(str(sock_path))
                while time.time() < end:
                    s.sendall(b"sendkey ret\n")
                    time.sleep(0.5)
        except OSError:
            time.sleep(0.5)


def main():
    assert os.access("/dev/kvm", os.W_OK), "KVM is needed to install Windows in reasonable time"
    W.mkdir(parents=True, exist_ok=True)
    answers = W / "answers"
    shutil.rmtree(answers, ignore_errors=True)
    answers.mkdir()
    (answers / "autounattend.xml").write_text(UNATTEND, encoding="utf-8")
    (answers / "fenrir-up.cmd").write_text(UP_CMD.replace("\n", "\r\n"), encoding="ascii")
    answers_iso = W / "answers.iso"
    subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-J", "-r", "-V", "FENRIR_ANSWERS", "-o", str(answers_iso),
                    str(answers)], check=True)
    DISK.unlink(missing_ok=True)
    with open(DISK, "wb") as f:
        f.truncate(GIB << 30)
    vars_file = W / "install-vars.fd"
    shutil.copy(OVMF / "OVMF_VARS_4M.fd", vars_file)

    t0 = time.time()
    mon = W / "install.monitor"
    vm, log = qemu("install",
                   "-drive", f"file={ISO},media=cdrom,if=none,id=cd0,readonly=on",
                   "-device", "ide-cd,drive=cd0,bus=ide.1,bootindex=0",
                   "-drive", f"file={answers_iso},media=cdrom,if=none,id=cd1,readonly=on",
                   "-device", "ide-cd,drive=cd1,bus=ide.2",
                   vars_file=vars_file, monitor=mon)
    press_keys(mon, 60)
    stop = threading.Event()
    threading.Thread(target=screens, args=(mon, stop), daemon=True).start()
    try:
        vm.wait(timeout=3600)
    except subprocess.TimeoutExpired:
        vm.kill()
        keep_setup_logs("install")
        raise SystemExit("Windows setup did not finish within an hour:\n" + text(log)[-2000:])
    finally:
        stop.set()
    files = ntfs_files(DISK, ["fenrir-installed.txt", "fenrir-up.cmd"])
    if not files["fenrir-installed.txt"] or not files["fenrir-up.cmd"]:
        keep_setup_logs("install")
        raise SystemExit(f"Windows setup stopped before the first sign-in commands ran ({time.time() - t0:.0f}s; "
                         f"files on C: {[k for k, v in files.items() if v]}); see the setup logs and screens")
    print(f"  Windows installed in {time.time() - t0:.0f}s (serial: {'FENRIR-INSTALLED' in text(log)})")

    # One boot from the disk alone: the start-up task records the boot and shuts Windows down.
    t0 = time.time()
    mon = W / "verify.monitor"
    vm, log = qemu("verify", vars_file=vars_file, monitor=mon)
    stop = threading.Event()
    threading.Thread(target=screens, args=(mon, stop), daemon=True).start()
    try:
        vm.wait(timeout=900)
    except subprocess.TimeoutExpired:
        vm.kill()
        raise SystemExit("the installed Windows did not boot and shut itself down within 15 minutes")
    finally:
        stop.set()
    seen = boots(DISK)
    assert len(seen) == 1, f"the installed Windows did not record its boot: {seen}"
    used = os.stat(DISK).st_blocks * 512
    print(f"  the installed Windows boots, runs its start-up task and shuts down ({time.time() - t0:.0f}s; "
          f"serial: {MARKER in text(log)}); {used / (1 << 30):.1f} GiB of the {GIB} GiB disk in use")


if __name__ == "__main__":
    main()
