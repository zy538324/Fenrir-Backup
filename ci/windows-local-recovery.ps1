<#
Local recovery partition on a real Windows machine (design: docs/design/local-recovery.md).

Installs it with the agent (from this machine's Windows RE, or the ADK's Windows PE when the runner has no
Windows RE), then checks: C: shrank by the partition's size; the partition is a hidden Windows recovery partition;
the boot menu has "Fenrir Recovery" starting \Fenrir\boot.wim from a RAM disk (and as the recovery sequence when
asked); the image holds the agent, the settings and startnet.cmd and no winpeshl.ini. Then removes it: partition and
boot entries gone, the space back on C:, the previous recovery sequence restored.

  pwsh ci/windows-local-recovery.ps1 -Agent bin\fenrir-backup-agent.exe   (as administrator)
#>
param([Parameter(Mandatory)] [string] $Agent, [string] $Work = "$env:RUNNER_TEMP\fenrir-lr")
$ErrorActionPreference = 'Stop'
$Agent = (Resolve-Path $Agent).Path
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:FENRIR_AGENT_STATE = "$Work\state"
function Check($Cond, [string] $What) { if (-not $Cond) { throw "FAILED: $What" }; Write-Host "  ok: $What" }

'{"server":"https://backup.example.lan:8443","pin":"","token":"ci-local-recovery","expires":1900000000}' | Set-Content "$Work\settings.json"
$base = @()
$re = (reagentc /info) -join "`n"
Write-Host $re
if ($re -notmatch 'Windows RE location:\s+\\\\\?\\') {
    $adk = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\en-us\winpe.wim"
    if (-not (Test-Path $adk)) { throw "no Windows RE on this runner and no ADK Windows PE at $adk" }
    $base = @('--base-wim', $adk)
    Write-Host "  (no Windows RE here: building from the ADK's Windows PE)"
}
Get-Disk | Format-Table Number, PartitionStyle, Size, AllocatedSize | Out-Host
Get-Partition | Format-Table DiskNumber, PartitionNumber, DriveLetter, Offset, Size, Type, GptType | Out-Host
Get-PartitionSupportedSize -DriveLetter C | Out-Host
$before = (Get-Partition -DriveLetter C).Size
$seqBefore = ((bcdedit /enum '{current}') -match '^recoverysequence') -replace '^recoverysequence\s+', ''

$out = & $Agent local-recovery install --settings "$Work\settings.json" --auto-start --yes @base 2>&1
if ($LASTEXITCODE -ne 0) { $out | Out-Host; throw "install failed" }
Write-Host $out
$r = ($out | Select-Object -Last 1) | ConvertFrom-Json
$st = $r.state
$p = Get-Partition -DiskNumber $st.disk | Where-Object { $_.Offset -eq $st.offset }
Check ($p -ne $null) "the recovery partition exists (disk $($st.disk), partition $($p.PartitionNumber), $([math]::Round($p.Size / 1MB)) MB)"
Check ((Get-Partition -DriveLetter C).Size -eq $before - $p.Size) 'C: gave up exactly its space'
if ((Get-Disk -Number $st.disk).PartitionStyle -eq 'GPT') {
    Check ($p.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}') "it is a Windows recovery partition ($($p.GptType))"
    Check ($p.IsHidden -or $p.NoDefaultDriveLetter) 'it is hidden, without a drive letter'
}
Check (-not $p.DriveLetter -or $p.DriveLetter -eq [char]0) 'no drive letter left on it'
$entry = (bcdedit /enum $st.bcd_entry) -join "`n"
Write-Host $entry
Check ($entry -match 'Fenrir Recovery') 'the boot menu has Fenrir Recovery'
Check ($entry -match 'ramdisk=\[.*\]\\Fenrir\\boot\.wim') 'it starts \Fenrir\boot.wim from a RAM disk'
Check ($entry -match 'winpe\s+Yes') 'as Windows PE'
Check (((bcdedit /enum '{current}') -join "`n") -match [regex]::Escape($st.bcd_entry)) 'it is the recovery sequence (auto start)'
Check ((Get-Content "$Work\state\local-recovery.json" | ConvertFrom-Json).bcd_entry -eq $st.bcd_entry) 'the agent remembers it'

# Look inside: give it a letter for a moment.
$p | Add-PartitionAccessPath -AssignDriveLetter
$p = Get-Partition -DiskNumber $st.disk | Where-Object { $_.Offset -eq $st.offset }
$d = "$($p.DriveLetter):"
Check (Test-Path "$d\Fenrir\boot.wim") 'the image is on the partition'
Check (Test-Path "$d\Fenrir\boot.sdi") 'and the RAM disk file'
New-Item -ItemType Directory "$Work\mnt" | Out-Null
dism /Mount-Image /ImageFile:"$d\Fenrir\boot.wim" /Index:1 /MountDir:"$Work\mnt" /ReadOnly | Out-Null
try {
    foreach ($f in 'Windows\System32\fenrir-backup-agent.exe', 'Windows\System32\startnet.cmd', 'fenrir\recovery.json', 'fenrir\status.cmd') {
        Check (Test-Path "$Work\mnt\$f") "the image holds $f"
    }
    Check (-not (Test-Path "$Work\mnt\Windows\System32\winpeshl.ini")) 'no winpeshl.ini: startnet.cmd starts the agent'
    Check ((Get-Content -Raw "$Work\mnt\fenrir\recovery.json") -match 'ci-local-recovery') 'with its settings'
    Check ((Get-Content -Raw "$Work\mnt\Windows\System32\startnet.cmd") -match 'fenrir-backup-agent.exe recovery') 'startnet.cmd starts the agent in recovery mode'
} finally {
    dism /Unmount-Image /MountDir:"$Work\mnt" /Discard | Out-Null
    $p | Remove-PartitionAccessPath -AccessPath "$d\"
}

$out = & $Agent local-recovery remove --yes
if ($LASTEXITCODE -ne 0) { throw "remove failed: $out" }
Write-Host $out
Check (-not (Get-Partition -DiskNumber $st.disk | Where-Object { $_.Offset -eq $st.offset })) 'the partition is gone'
Check ((Get-Partition -DriveLetter C).Size -eq $before) 'C: has its space back'
bcdedit /enum $st.bcd_entry 2>&1 | Out-Null
Check ($LASTEXITCODE -ne 0) 'the boot entry is gone'
$seqAfter = ((bcdedit /enum '{current}') -match '^recoverysequence') -replace '^recoverysequence\s+', ''
Check ("$seqAfter" -eq "$seqBefore") "the previous recovery sequence is back ($seqBefore)"
Check (-not (Test-Path "$Work\state\local-recovery.json")) 'the agent forgot it'
Write-Host 'LOCAL RECOVERY OK'
