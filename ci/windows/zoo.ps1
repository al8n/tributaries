# Builds the scratch volume zoo the Windows integration suites run against.
# The runner executes as Administrator (GitHub-hosted Windows runners), so
# volume creation needs no elevation step. Every volume is a VHDX under the
# workspace — the runner's system volume is never touched, and the whole zoo
# vanishes with the workspace.
#
# What this provisions, and why each substrate is here:
#   NTFS      - the primary substrate, journal-armed for the forced-USN cells
#               and 8.3-alias-enabled so short-name paths are reachable
#   FAT32     - the no-USN fallback substrate
#   WRAP      - NTFS with a deliberately tiny journal, sacrificial to the
#               wrap/truncation cell
#   MOUNTDIR  - NTFS mounted at a DIRECTORY rather than a drive letter, so a
#               watched path can cross a volume boundary with no letter in it
#   REFS      - ReFS, whose file identity and journal surfaces differ from
#               NTFS. Edition-gated: when the image cannot format ReFS the
#               volume is skipped and its variable stays unset, rather than
#               failing the whole zoo.
#
# Usage: pwsh ci/windows/zoo.ps1 -Root <dir>
# Emits TRIBUTARY_ZOO_NTFS / _FAT32 / _WRAP / _MOUNTDIR (and _REFS when the
# image supports it) into $env:GITHUB_ENV, each the root path of a mounted
# scratch volume.

param(
  [Parameter(Mandatory = $true)]
  [string]$Root
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

function Invoke-Diskpart {
  param(
    [string]$Name,
    [string[]]$Lines
  )
  $scriptPath = Join-Path $Root "$Name.diskpart.txt"
  Set-Content -Path $scriptPath -Value ($Lines -join "`r`n") -Encoding ascii
  diskpart /s $scriptPath | Out-Null
  return $LASTEXITCODE
}

function New-ZooVolume {
  param(
    [string]$Name,
    [string]$FileSystem,
    [uint64]$SizeMB,
    # When set, the volume is attached at this DIRECTORY instead of taking a
    # drive letter. The directory must exist and be empty.
    [string]$MountPath
  )
  $vhdx = Join-Path $Root "$Name.vhdx"
  $assign = if ($MountPath) { "assign mount=`"$MountPath`"" } else { 'assign' }
  $rc = Invoke-Diskpart -Name $Name -Lines @(
    "create vdisk file=`"$vhdx`" maximum=$SizeMB type=expandable",
    "select vdisk file=`"$vhdx`"",
    'attach vdisk',
    'create partition primary',
    "format fs=$FileSystem quick label=$Name",
    $assign
  )
  if ($rc -ne 0) {
    throw "diskpart failed building the $Name volume"
  }
  # The freshly-formatted volume: the one whose label matches.
  $volume = Get-Volume -FileSystemLabel $Name -ErrorAction Stop
  if ($MountPath) {
    return (Join-Path $MountPath '')
  }
  if (-not $volume.DriveLetter) {
    throw "the $Name volume mounted without a drive letter"
  }
  return "$($volume.DriveLetter):\"
}

# Detaches and deletes a half-built vdisk so a refused format leaves no raw
# volume behind for the later cells to trip over.
function Remove-ZooVdisk {
  param([string]$Name)
  $vhdx = Join-Path $Root "$Name.vhdx"
  if (Test-Path $vhdx) {
    Invoke-Diskpart -Name "$Name.detach" -Lines @(
      "select vdisk file=`"$vhdx`"",
      'detach vdisk'
    ) | Out-Null
    Remove-Item -Path $vhdx -Force -ErrorAction SilentlyContinue
  }
}

$ntfs = New-ZooVolume -Name 'ZOONTFS' -FileSystem 'ntfs' -SizeMB 512
# Journal creation is an explicit operation: a fresh NTFS volume carries no
# guarantee of an active journal, and the forced-USN cells demand one.
fsutil usn createjournal "m=8388608" "a=1048576" $ntfs.TrimEnd('\')
if ($LASTEXITCODE -ne 0) {
  throw 'creating the NTFS zoo journal failed'
}
# 8.3 alias generation is off by default on modern Server images, which makes
# every short-name path unreachable. It only applies to files created AFTER the
# switch, and this volume is empty, so enabling it here covers the whole suite.
fsutil 8dot3name set $ntfs.TrimEnd('\') 0
if ($LASTEXITCODE -ne 0) {
  throw 'enabling 8.3 alias generation on the NTFS zoo volume failed'
}

$fat32 = New-ZooVolume -Name 'ZOOFAT' -FileSystem 'fat32' -SizeMB 256
# The sacrificial wrap volume: a deliberately tiny journal so the wrap cell
# can force truncation without gigabytes of churn.
$wrap = New-ZooVolume -Name 'ZOOWRAP' -FileSystem 'ntfs' -SizeMB 256
fsutil usn createjournal "m=1048576" "a=262144" $wrap.TrimEnd('\')
if ($LASTEXITCODE -ne 0) {
  throw 'creating the sacrificial journal failed'
}

# The letterless volume: a directory mount point, so a watched path descends
# across a volume boundary without a drive letter marking it.
$mountDir = Join-Path $Root 'mnt-ntfs'
New-Item -ItemType Directory -Force -Path $mountDir | Out-Null
if ((Get-ChildItem -Force -Path $mountDir | Measure-Object).Count -ne 0) {
  throw "the mount-point directory $mountDir is not empty"
}
$mounted = New-ZooVolume -Name 'ZOOMNT' -FileSystem 'ntfs' -SizeMB 256 -MountPath $mountDir

# ReFS is edition-gated; a refusal must not take the rest of the zoo with it.
$refs = $null
try {
  $refs = New-ZooVolume -Name 'ZOOREFS' -FileSystem 'refs' -SizeMB 4096
} catch {
  Write-Host "::warning::ReFS zoo volume unavailable on this image: $($_.Exception.Message)"
  Remove-ZooVdisk -Name 'ZOOREFS'
  $refs = $null
}

"TRIBUTARY_ZOO_NTFS=$ntfs" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"TRIBUTARY_ZOO_FAT32=$fat32" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"TRIBUTARY_ZOO_WRAP=$wrap" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"TRIBUTARY_ZOO_MOUNTDIR=$mounted" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
if ($refs) {
  "TRIBUTARY_ZOO_REFS=$refs" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}
Write-Host "zoo ready: ntfs=$ntfs fat32=$fat32 wrap=$wrap mountdir=$mounted refs=$refs"
