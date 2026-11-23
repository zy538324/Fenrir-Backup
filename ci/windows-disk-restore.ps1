<#
Whole-disk restore on a running Windows, end to end (design: docs/design/phase-2.md §6,
docs/design/phase-5-hardware.md). Run as Administrator on a Windows machine whose disks may be
touched only through the two virtual disks this script creates:

  * a "PC" disk: GPT, an EFI system partition holding only \EFI\Microsoft\Boot\bootmgfw.efi, and an
    NTFS volume with a Windows folder (a real SYSTEM hive saved with reg.exe, storage driver files);
  * a larger "new" disk with an NTFS volume that is mounted and in use.

The PC disk is backed up with the CLI. Restoring it onto the new disk must first be refused while a
file is open on the new disk's volume, then succeed once it is closed: the volume is locked and
dismounted, the GPT is moved to the new end, the fallback boot loader is added, and Windows mounts
the restored volumes. Finally `fenrir-backup-agent prepare-windows` sets the storage drivers of the
restored Windows to start at boot.

  pwsh ci/windows-disk-restore.ps1 -Cli target\release\fenrir-backup.exe -Agent target\release\fenrir-backup-agent.exe
#>
param(
    [Parameter(Mandatory)] [string] $Cli,
    [Parameter(Mandatory)] [string] $Agent,
    [string] $Work = "$env:RUNNER_TEMP\fenrir-disk-restore"
)
$ErrorActionPreference = 'Stop'
$Cli = (Resolve-Path $Cli).Path
$Agent = (Resolve-Path $Agent).Path
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:FENRIR_PASSPHRASE = 'ci disk restore passphrase'
$repo = "$Work\repo"

function New-Vdisk([string] $Path, [int] $MB) {
    "create vdisk file=`"$Path`" type=fixed maximum=$MB" | Out-File -Encoding ascii "$Work\dp.txt"
    diskpart /s "$Work\dp.txt" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "diskpart could not create $Path" }
    Mount-DiskImage -ImagePath $Path | Out-Null
    $d = Get-DiskImage -ImagePath $Path | Get-Disk
    Initialize-Disk -Number $d.Number -PartitionStyle GPT
    return $d.Number
}
function Fenrir([string[]] $A) {
    $out = & $Cli --json --repo $repo @A
    $global:LASTCODE = $LASTEXITCODE
    return ($out | ConvertFrom-Json)
}
function Check($Cond, [string] $What) {
    if (-not $Cond) { throw "FAILED: $What" }
    Write-Host "  ok: $What"
}

# ---- the PC disk ----------------------------------------------------------------------------
$pcVhd = "$Work\pc.vhd"
$pc = New-Vdisk $pcVhd 200
$esp = New-Partition -DiskNumber $pc -Size 100MB -AssignDriveLetter
Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel ESP -Confirm:$false | Out-Null
$e = (Get-Partition -DiskNumber $pc -PartitionNumber $esp.PartitionNumber).DriveLetter
New-Item -ItemType Directory "${e}:\EFI\Microsoft\Boot" -Force | Out-Null
[IO.File]::WriteAllBytes("${e}:\EFI\Microsoft\Boot\bootmgfw.efi", [Text.Encoding]::ASCII.GetBytes('MZ fenrir ci boot manager'))
$win = New-Partition -DiskNumber $pc -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $win -FileSystem NTFS -NewFileSystemLabel FENRIRSRC -Confirm:$false | Out-Null
$w = (Get-Partition -DiskNumber $pc -PartitionNumber $win.PartitionNumber).DriveLetter
New-Item -ItemType Directory "${w}:\Windows\System32\config", "${w}:\Windows\System32\drivers" -Force | Out-Null
'storahci.sys', 'stornvme.sys' | ForEach-Object { [IO.File]::WriteAllBytes("${w}:\Windows\System32\drivers\$_", [byte[]](0x4D, 0x5A)) }
Set-Content "${w}:\marker.txt" 'restored by fenrir'
# A SYSTEM hive the way Windows has it: storahci and stornvme on demand start, storahci with a
# StartOverride, a driver without a file, and an unrelated service.
$k = 'HKCU\FenrirCI'
reg add "$k\Select" /v Current /t REG_DWORD /d 1 /f | Out-Null
foreach ($s in 'storahci', 'stornvme', 'iaStorV', 'Tcpip') {
    $start = @{ storahci = 3; stornvme = 3; iaStorV = 3; Tcpip = 1 }[$s]
    reg add "$k\ControlSet001\Services\$s" /v Start /t REG_DWORD /d $start /f | Out-Null
    reg add "$k\ControlSet001\Services\$s" /v ImagePath /t REG_EXPAND_SZ /d "System32\drivers\$s.sys" /f | Out-Null
}
reg add "$k\ControlSet001\Services\storahci\StartOverride" /v 0 /t REG_DWORD /d 3 /f | Out-Null
reg save $k "${w}:\Windows\System32\config\SYSTEM" /y | Out-Null
reg delete $k /f | Out-Null
# Only now an EFI system partition (Windows assigns no letter to one).
Remove-PartitionAccessPath -DiskNumber $pc -PartitionNumber $esp.PartitionNumber -AccessPath "${e}:\"
Set-Partition -DiskNumber $pc -PartitionNumber $esp.PartitionNumber -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
# Windows adds a Microsoft reserved partition to a new GPT disk.
$pcParts = (Get-Partition -DiskNumber $pc).Count
Dismount-DiskImage -ImagePath $pcVhd | Out-Null
# A fixed VHD is the raw disk followed by a 512-byte footer.
$img = "$Work\pc.img"
Copy-Item $pcVhd $img
$fs = [IO.File]::Open($img, 'Open'); $fs.SetLength($fs.Length - 512); $fs.Close()

# ---- back it up -----------------------------------------------------------------------------
$r = Fenrir @('repo', 'init', '--recovery-key-out', "$Work\rk.json")
Check ($LASTCODE -eq 0) 'repository created'
$r = Fenrir @('backup', 'disk', $img, '--machine-id', 'ci-pc')
Check ($LASTCODE -eq 0) 'PC disk backed up'
$image = $r.result.image_id

# ---- the new, larger disk, in use ---------------------------------------------------------------
$newVhd = "$Work\new.vhd"
$new = New-Vdisk $newVhd 320
$old = New-Partition -DiskNumber $new -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $old -FileSystem NTFS -NewFileSystemLabel OLDDATA -Confirm:$false | Out-Null
$o = (Get-Partition -DiskNumber $new -PartitionNumber $old.PartitionNumber).DriveLetter
$open = [IO.File]::Open("${o}:\busy.txt", 'Create', 'ReadWrite', 'None')
$target = "\\.\PhysicalDrive$new"

# The disk running Windows is always refused.
$sys = (Get-Partition -DriveLetter ($env:SystemDrive.Trim(':'))).DiskNumber
$r = Fenrir @('restore', 'disk', '--image', $image, '--target', "\\.\PhysicalDrive$sys", '--yes', '--fit')
Check ($LASTCODE -ne 0 -and "$($r.error.message)" -match 'in use|running Windows') "the system disk is refused ($($r.error.message))"

$r = Fenrir @('restore', 'disk', '--image', $image, '--target', $target, '--yes', '--fit', '--boot-fixup')
Check ($LASTCODE -ne 0 -and "$($r.error.message)" -match 'in use') "refused while a file is open on it ($($r.error.message))"
Check ((Get-Volume -DriveLetter $o).FileSystemLabel -eq 'OLDDATA') 'nothing written after the refusal'
$open.Close()

$r = Fenrir @('restore', 'disk', '--image', $image, '--target', $target, '--yes', '--fit', '--boot-fixup', '--grow')
if ($LASTCODE -ne 0) { $r | ConvertTo-Json -Depth 8 | Write-Host }
Check ($LASTCODE -eq 0) 'restored onto the new disk once it was free'
Check ($r.result.boot.added -contains '\EFI\BOOT\BOOTX64.EFI') 'fallback boot loader added'

# Windows mounted the restored volumes.
Start-Sleep -Seconds 3
Update-Disk -Number $new
$parts = Get-Partition -DiskNumber $new
Check ($parts.Count -eq $pcParts) "the PC disk's $pcParts partitions on the new disk ($($parts.Count))"
Check (($parts | Where-Object GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}').Count -eq 1) 'its EFI system partition'
$data = $parts | Where-Object { $_.GptType -eq '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' }
if (-not $data.DriveLetter) { $data | Add-PartitionAccessPath -AssignDriveLetter; $data = Get-Partition -DiskNumber $new -PartitionNumber $data.PartitionNumber }
$n = $data.DriveLetter
Check ((Get-Volume -DriveLetter $n).FileSystemLabel -eq 'FENRIRSRC') 'the restored NTFS volume'
Check ((Get-Content "${n}:\marker.txt") -eq 'restored by fenrir') 'its files'
# --grow: the NTFS volume was the last partition and fills the larger disk.
Check ($r.result.grow.filesystem_grown) "the restored NTFS file system was grown ($($r.result.grow.notes -join '; '))"
$vol = Get-Volume -DriveLetter $n
$end = $data.Offset + $data.Size
Check ($end -gt 316MB) "the last partition reaches the end of the disk (ends at $([math]::Round($end / 1MB)) MB of 320)"
Check ($vol.Size -gt $data.Size - 4MB) "the NTFS volume fills the partition ($([math]::Round($vol.Size / 1MB)) MB)"
$disk = Get-Disk -Number $new
Check ($disk.Size -eq 320MB) 'the GPT covers the larger disk'

# ---- prepare the restored Windows for this hardware --------------------------------------------
$out = & $Agent prepare-windows --device $target
if ($LASTEXITCODE -ne 0) {
    # Which programs hold the restored registry open (Windows Restart Manager).
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class Rm {
  [StructLayout(LayoutKind.Sequential)] public struct UNIQUE_PROCESS { public int Pid; public System.Runtime.InteropServices.ComTypes.FILETIME Start; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct INFO {
    public UNIQUE_PROCESS Process;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string App;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)] public string Service;
    public int Type; public int Status; public int Session; [MarshalAs(UnmanagedType.Bool)] public bool Restartable; }
  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmStartSession(out uint h, int f, string key);
  [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint h);
  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmRegisterResources(uint h, uint n, string[] files, uint a, IntPtr b, uint c, string[] d);
  [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint h, out uint need, ref uint n, [In, Out] INFO[] info, ref uint reasons);
  public static string Who(string path) {
    uint h; RmStartSession(out h, 0, Guid.NewGuid().ToString());
    try {
      RmRegisterResources(h, 1, new[] { path }, 0, IntPtr.Zero, 0, null);
      uint need = 0, n = 0, r = 0; RmGetList(h, out need, ref n, null, ref r);
      var info = new INFO[need]; n = need; RmGetList(h, out need, ref n, info, ref r);
      var s = ""; foreach (var i in info) s += i.App + " (pid " + i.Process.Pid + ", service " + i.Service + "); ";
      return s == "" ? "nobody the Restart Manager can see" : s;
    } finally { RmEndSession(h); } } }
'@
    foreach ($f in 'SYSTEM', 'SYSTEM.LOG1', 'SYSTEM.LOG2') {
        $p = "${n}:\Windows\System32\config\$f"
        if (Test-Path $p) { Write-Host "  $p is held by: $([Rm]::Who($p))" }
    }
    Get-ChildItem "${n}:\Windows\System32\config" -Force | Format-Table Name, Length, LastWriteTime | Out-String | Write-Host
}
Check ($LASTEXITCODE -eq 0) 'prepare-windows ran'
$fix = ($out | Select-Object -Last 1) | ConvertFrom-Json
Write-Host ($fix | ConvertTo-Json -Depth 4)
Check (($fix.boot_start -contains 'storahci') -and ($fix.boot_start -contains 'stornvme')) 'storage drivers set to start at boot'
Check (-not ($fix.boot_start -contains 'iaStorV')) 'a driver without its file is left alone'
Check ($fix.overrides_removed -contains 'storahci') 'StartOverride removed'
reg load HKLM\FenrirCheck "${n}:\Windows\System32\config\SYSTEM" | Out-Null
try {
    $q = reg query 'HKLM\FenrirCheck\ControlSet001\Services\storahci' /v Start
    Check ("$q" -match '0x0') 'the restored hive says Start = 0'
    $q = reg query 'HKLM\FenrirCheck\ControlSet001\Services\Tcpip' /v Start
    Check ("$q" -match '0x1') 'other services unchanged'
    reg query 'HKLM\FenrirCheck\ControlSet001\Services\storahci\StartOverride' 2>$null | Out-Null
    Check ($LASTEXITCODE -ne 0) 'StartOverride gone'
} finally {
    reg unload HKLM\FenrirCheck | Out-Null
}
Check (Test-Path "${n}:\Windows\System32\config\SYSTEM.fenrir-before-hardware") 'a copy of the hive was kept'

Dismount-DiskImage -ImagePath $newVhd | Out-Null
Write-Host 'WINDOWS DISK RESTORE OK'
