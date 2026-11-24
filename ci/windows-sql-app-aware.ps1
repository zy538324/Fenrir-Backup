<#
Application-aware backup with a real SQL Server (design: docs/design/app-aware.md).

SQL Server Express holds a database on a data disk (a VHD). The data disk is backed up with VSS in component
mode (`backup system --data-disks-only --include-disk N`), twice:

  * default (VSS COPY): the image lists the database as coordinated, and SQL Server itself records a
    copy-only backup of it in msdb (proof that the SQL writer took part and was told the backup succeeded);
  * --vss-full: SQL Server records a full, non-copy-only backup (the one that lets it truncate its log).

Then the image is restored onto a new disk and the database files are attached as a new database: the rows
written before the backup are there and DBCC CHECKDB finds nothing wrong.

  pwsh ci/windows-sql-app-aware.ps1 -Cli target\release\fenrir-backup.exe   (as administrator, SQL Server Express installed)
#>
param(
    [Parameter(Mandatory)] [string] $Cli,
    [string] $Instance = '.\SQLEXPRESS',
    [string] $Work = "$env:RUNNER_TEMP\fenrir-sql"
)
$ErrorActionPreference = 'Stop'
$Cli = (Resolve-Path $Cli).Path
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
$env:FENRIR_PASSPHRASE = 'ci sql passphrase'
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
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 10) { $out | Write-Host }
    return ($out | ConvertFrom-Json)
}
function Check($Cond, [string] $What) {
    if (-not $Cond) { throw "FAILED: $What" }
    Write-Host "  ok: $What"
}
function Sql([string] $Query) {
    $out = sqlcmd -S $Instance -E -b -h -1 -W -Q "SET NOCOUNT ON; $Query"
    if ($LASTEXITCODE -ne 0) {
        $out | Write-Host
        if ($s) { icacls "${s}:\sql" | Out-Host }
        throw "sqlcmd failed: $Query"
    }
    return $out
}

Start-Service SQLWriter -ErrorAction SilentlyContinue
Check ((Get-Service SQLWriter).Status -eq 'Running') 'the SQL Server VSS writer is running'

# ---- a data disk with a database on it -------------------------------------------------------
$dataVhd = "$Work\data.vhd"
$data = New-Vdisk $dataVhd 600
$p = New-Partition -DiskNumber $data -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel SQLDATA -Confirm:$false | Out-Null
$s = (Get-Partition -DiskNumber $data -PartitionNumber $p.PartitionNumber).DriveLetter
New-Item -ItemType Directory "${s}:\sql" | Out-Null
# SQL Server needs the folder, and the root to reach it. Grant the account its service runs as (as Windows and as
# SQL Server report it) and its service SID; this volume is a throwaway VHD, so Everyone as well, which keeps the
# test about the backup rather than about the runner's account set-up.
$svcName = 'MSSQL$' + ($Instance -replace '^.*\\', '')
$runsAs = (Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartName
$sqlSays = (sqlcmd -S $Instance -E -h -1 -W -Q "SET NOCOUNT ON; SELECT service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%'") | Select-Object -First 1
Write-Host "  SQL Server runs as: $runsAs (SQL Server says: $sqlSays)"
foreach ($who in @("NT SERVICE\$svcName", $runsAs, $sqlSays, '*S-1-1-0') | Where-Object { $_ } | Select-Object -Unique) {
    icacls "${s}:\" /grant "${who}:(OI)(CI)F" | Out-Host
}
icacls "${s}:\sql" /reset /T | Out-Host

Sql "CREATE DATABASE fenrirci ON (NAME = fenrirci, FILENAME = '${s}:\sql\fenrirci.mdf') LOG ON (NAME = fenrirci_log, FILENAME = '${s}:\sql\fenrirci_log.ldf');" | Out-Null
Sql "ALTER DATABASE fenrirci SET RECOVERY FULL;" | Out-Null
Sql "CREATE TABLE fenrirci.dbo.t (id INT PRIMARY KEY, v NVARCHAR(100)); INSERT INTO fenrirci.dbo.t SELECT TOP 5000 ROW_NUMBER() OVER (ORDER BY (SELECT 1)), 'row before the backup' FROM sys.all_objects a CROSS JOIN sys.all_objects b;" | Out-Null
Check ((Sql "SELECT COUNT(*) FROM fenrirci.dbo.t") -eq '5000') 'the database has 5000 rows'

$r = Fenrir @('repo', 'init', '--recovery-key-out', "$Work\rk.json")
Check ($LASTCODE -eq 0) 'repository created'

# ---- backup (VSS COPY): SQL Server records a copy-only backup ------------------------------------
$r = Fenrir @('backup', 'system', '--data-disks-only', '--include-disk', "$data", '--label', 'copy')
Check ($LASTCODE -eq 0 -or $LASTCODE -eq 10) "data disk backed up ($($r.warnings -join '; '))"
$image = $r.result.image_id
$m = (Fenrir @('image', 'show', $image)).result
Check ($m.consistency -eq 'application') "the image is application-consistent ($($m.consistency))"
$db = $m.applications | Where-Object { $_.writer -eq 'SqlServerWriter' -and $_.component -match 'fenrirci' }
if (-not $db) { $m.applications | ConvertTo-Json -Depth 4 | Write-Host }
Check ($db -and $db.included) "the image lists the database as coordinated with SQL Server ($($db.component))"
$copy = Sql "SELECT TOP 1 CONCAT(type, ':', is_copy_only) FROM msdb.dbo.backupset WHERE database_name = 'fenrirci' ORDER BY backup_set_id DESC"
Check ($copy -eq 'D:1') "SQL Server recorded a copy-only full backup ($copy)"

# ---- backup (VSS FULL): a full backup SQL Server counts in its backup chain --------------------------
Sql "INSERT INTO fenrirci.dbo.t VALUES (900001, 'row before the full backup');" | Out-Null
$r = Fenrir @('backup', 'system', '--data-disks-only', '--include-disk', "$data", '--vss-full', '--label', 'full')
Check ($LASTCODE -eq 0 -or $LASTCODE -eq 10) 'data disk backed up with --vss-full'
$fullImage = $r.result.image_id
$full = Sql "SELECT TOP 1 CONCAT(type, ':', is_copy_only) FROM msdb.dbo.backupset WHERE database_name = 'fenrirci' ORDER BY backup_set_id DESC"
Check ($full -eq 'D:0') "SQL Server recorded a full backup in its chain ($full)"

# ---- restore onto a new disk, attach the files as a new database ---------------------------------
Sql "INSERT INTO fenrirci.dbo.t VALUES (900002, 'row after the backup');" | Out-Null
Sql "ALTER DATABASE fenrirci SET OFFLINE WITH ROLLBACK IMMEDIATE;" | Out-Null
Dismount-DiskImage -ImagePath $dataVhd | Out-Null
$newVhd = "$Work\restored.vhd"
$new = New-Vdisk $newVhd 700
$r = Fenrir @('restore', 'disk', '--image', $fullImage, '--target', "\\.\PhysicalDrive$new", '--yes', '--grow')
Check ($LASTCODE -eq 0 -or $LASTCODE -eq 10) 'restored onto a new disk'
Start-Sleep -Seconds 3
Update-Disk -Number $new
$rp = Get-Partition -DiskNumber $new | Where-Object { $_.Type -eq 'Basic' } | Select-Object -First 1
if (-not $rp.DriveLetter) { $rp | Add-PartitionAccessPath -AssignDriveLetter; $rp = Get-Partition -DiskNumber $new -PartitionNumber $rp.PartitionNumber }
$n = $rp.DriveLetter
Sql "CREATE DATABASE fenrirrestored ON (FILENAME = '${n}:\sql\fenrirci.mdf'), (FILENAME = '${n}:\sql\fenrirci_log.ldf') FOR ATTACH;" | Out-Null
Check ((Sql "SELECT COUNT(*) FROM fenrirrestored.dbo.t") -eq '5001') 'the restored database has the rows from before the backup'
Check ((Sql "SELECT COUNT(*) FROM fenrirrestored.dbo.t WHERE id = 900002") -eq '0') '...and not the row written after it'
Sql "DBCC CHECKDB (fenrirrestored) WITH NO_INFOMSGS;" | Out-Null
Check $true 'DBCC CHECKDB finds no errors in the restored database'
Write-Host 'APPLICATION-AWARE SQL SERVER OK'
