param(
  [Parameter(Mandatory=$true)][string]$BaseSha,
  [Parameter(Mandatory=$true)][string]$HeadSha,
  [Parameter(Mandatory=$false)][string]$RepoPath = "H:\SG_PROGRAM_CANONICAL\repos\ai-action-firewall-client-v1",
  [Parameter(Mandatory=$false)][string]$ProofRoot = "H:\SG_PROGRAM_CANONICAL\proof"
)

$ErrorActionPreference="Stop"

function Sha256HexUtf8([string]$s){
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
  ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
}

function WriteSha256Sidecar([string]$filePath){
  $h = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
  $name = Split-Path -Leaf $filePath
  ($h + "  " + $name) | Set-Content -LiteralPath ($filePath + ".sha256") -Encoding UTF8 -NoNewline
}

function Require40Hex([string]$x,[string]$label){
  if($x -notmatch '^[0-9a-fA-F]{40}$'){ throw ("STOP_{0}_NOT_40HEX:{1}" -f $label,$x) }
}

function RequireGitCommit([string]$repo,[string]$sha,[string]$label){
  & git -C $repo cat-file -e ($sha + "^{commit}") 2>$null
  if($LASTEXITCODE -ne 0){ throw ("STOP_{0}_NOT_FOUND:{1}" -f $label,$sha) }
}

function ExtractAddedLinesCanonical([string]$repo,[string]$base,[string]$head){
  # Deterministic diff:
  # - unified=0 (no context)
  # - no-color (stable)
  # - base/head passed as TWO ARGS (canonical, no revspec ambiguity)
  $raw = & git -C $repo diff --unified=0 --no-color $base $head
  if($LASTEXITCODE -ne 0){ throw "STOP_GIT_DIFF_FAILED" }

  # Normalize to LF:
  $lines = ($raw -split "`r?`n", 0)

  $added = New-Object System.Collections.Generic.List[string]
  foreach($ln in $lines){
    if($ln.StartsWith("+++ ")){ continue }     # skip diff header
    if($ln.StartsWith("+")){
      $added.Add($ln.Substring(1)) | Out-Null  # remove leading '+'
    }
  }

  # Canonical blob invariant:
  # ALWAYS LF-terminated. If empty: blob = "\n" (single LF).
  if($added.Count -eq 0){
    return @{ blob = "`n"; count = 0 }
  } else {
    $blob = ($added -join "`n") + "`n"
    return @{ blob = $blob; count = $added.Count }
  }
}

function BuildReport([string]$base,[string]$head,[string]$blob,[int]$count){
  $h = Sha256HexUtf8 $blob
@"
BASE=$base
HEAD=$head
CANON_EMPTY_BLOB=LF_ONLY
CANON_BLOB_ALWAYS_LF_TERMINATED=YES
ADDED_LINES_COUNT=$count
ADDED_LINES_SHA256=$h
"@
}

# -----------------------
# Preconditions
# -----------------------
if(-not (Test-Path -LiteralPath $RepoPath)){ throw "STOP_MISSING_REPOPATH" }

$gitRoot = (& git -C $RepoPath rev-parse --show-toplevel 2>$null).Trim()
if(-not $gitRoot){ throw "STOP_NOT_A_GIT_REPO" }

Require40Hex $BaseSha "BASE_SHA"
Require40Hex $HeadSha "HEAD_SHA"
RequireGitCommit $RepoPath $BaseSha "BASE_SHA"
RequireGitCommit $RepoPath $HeadSha "HEAD_SHA"

# -----------------------
# Proof folder
# -----------------------
if(-not (Test-Path -LiteralPath $ProofRoot)){ New-Item -ItemType Directory -Force -Path $ProofRoot | Out-Null }
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path $ProofRoot ("PHASE5_2_DIFF_" + $ts)
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# -----------------------
# Run 1
# -----------------------
$r1 = ExtractAddedLinesCanonical $RepoPath $BaseSha $HeadSha
$rep1 = BuildReport $BaseSha $HeadSha $r1.blob $r1.count
$f1 = Join-Path $outDir "PROOF_PHASE5_2_DIFF_RUN1.txt"
$rep1 | Set-Content -LiteralPath $f1 -Encoding UTF8 -NoNewline
WriteSha256Sidecar $f1

# -----------------------
# Run 2 (must match)
# -----------------------
$r2 = ExtractAddedLinesCanonical $RepoPath $BaseSha $HeadSha
$rep2 = BuildReport $BaseSha $HeadSha $r2.blob $r2.count
$f2 = Join-Path $outDir "PROOF_PHASE5_2_DIFF_RUN2.txt"
$rep2 | Set-Content -LiteralPath $f2 -Encoding UTF8 -NoNewline
WriteSha256Sidecar $f2

if($rep1 -ne $rep2){ throw "STOP_NONDETERMINISTIC_OUTPUT_RUN1_NE_RUN2" }

# -----------------------
# Anchor inputs
# -----------------------
$anchor = Join-Path $outDir "ANCHOR_BASE_HEAD.txt"
@"
BASE=$BaseSha
HEAD=$HeadSha
"@ | Set-Content -LiteralPath $anchor -Encoding UTF8 -NoNewline
WriteSha256Sidecar $anchor

# -----------------------
# GLOBAL hashset (two-pass, excludes GLOBAL itself, no pipe-race)
# -----------------------
function BuildGlobal([string]$dir,[string]$globalPath){
  $files = Get-ChildItem -LiteralPath $dir -File |
           Where-Object { $_.FullName -ne $globalPath } |
           Sort-Object Name

  $rows = New-Object System.Collections.Generic.List[string]
  foreach($fi in $files){
    $h = (Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $rows.Add(("{0}  {1}" -f $h,$fi.Name)) | Out-Null
  }
  $rows | Set-Content -LiteralPath $globalPath -Encoding UTF8
}

$global = Join-Path $outDir "GLOBAL_SHA256SUMS.txt"
$globalSide = $global + ".sha256"

# Pass 1
BuildGlobal $outDir $global
$hG1 = (Get-FileHash -LiteralPath $global -Algorithm SHA256).Hash.ToLowerInvariant()
("{0}  GLOBAL_SHA256SUMS.txt" -f $hG1) | Set-Content -LiteralPath $globalSide -Encoding UTF8 -NoNewline

# Pass 2 (include GLOBAL.sha256 via directory scan; GLOBAL itself still excluded)
BuildGlobal $outDir $global
$hG2 = (Get-FileHash -LiteralPath $global -Algorithm SHA256).Hash.ToLowerInvariant()
("{0}  GLOBAL_SHA256SUMS.txt" -f $hG2) | Set-Content -LiteralPath $globalSide -Encoding UTF8 -NoNewline

"PROOF_DIR=$outDir"
"STATUS=PHASE5_2_DIFF_PROOF_COMPLETE"