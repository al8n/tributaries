# Builds the scratch volume zoo the Windows integration suites run against.
# The runner executes as Administrator (GitHub-hosted Windows runners), so
# volume creation needs no elevation step. Every volume is a VHDX under the
# workspace — the runner's system volume is never touched, and the whole zoo
# vanishes with the workspace.
#
# W2 subset: NTFS (the primary substrate) + FAT32 (the no-USN fallback
# substrate). The ReFS and sacrificial journal-wrap volumes join with the USN
# backend's suites.
#
# Usage: pwsh ci/windows/zoo.ps1 -Root <dir>
# Emits: TRIBUTARY_ZOO_NTFS / TRIBUTARY_ZOO_FAT32 into $env:GITHUB_ENV,
# each the root path of a mounted scratch volume.

param(
  [Parameter(Mandatory = $true)]
  [string]$Root
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

function New-ZooVolume {
  param(
    [string]$Name,
    [string]$FileSystem,
    [uint64]$SizeMB
  )
  $vhdx = Join-Path $Root "$Name.vhdx"
  $script = @(
    "create vdisk file=`"$vhdx`" maximum=$SizeMB type=expandable",
    "select vdisk file=`"$vhdx`"",
    'attach vdisk',
    'create partition primary',
    "format fs=$FileSystem quick label=$Name",
    'assign'
  )
  $scriptPath = Join-Path $Root "$Name.diskpart.txt"
  Set-Content -Path $scriptPath -Value ($script -join "`r`n") -Encoding ascii
  diskpart /s $scriptPath | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "diskpart failed building the $Name volume"
  }
  # The freshly-assigned drive letter: the volume whose label matches.
  $volume = Get-Volume -FileSystemLabel $Name -ErrorAction Stop
  if (-not $volume.DriveLetter) {
    throw "the $Name volume mounted without a drive letter"
  }
  return "$($volume.DriveLetter):\"
}

$ntfs = New-ZooVolume -Name 'ZOONTFS' -FileSystem 'ntfs' -SizeMB 512
$fat32 = New-ZooVolume -Name 'ZOOFAT' -FileSystem 'fat32' -SizeMB 256
# The sacrificial wrap volume: a deliberately tiny journal so the wrap cell
# can force truncation without gigabytes of churn.
$wrap = New-ZooVolume -Name 'ZOOWRAP' -FileSystem 'ntfs' -SizeMB 256
fsutil usn createjournal "m=1048576" "a=262144" $wrap.TrimEnd('\')
if ($LASTEXITCODE -ne 0) {
  throw 'creating the sacrificial journal failed'
}

"TRIBUTARY_ZOO_NTFS=$ntfs" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"TRIBUTARY_ZOO_FAT32=$fat32" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"TRIBUTARY_ZOO_WRAP=$wrap" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
Write-Host "zoo ready: ntfs=$ntfs fat32=$fat32 wrap=$wrap"
