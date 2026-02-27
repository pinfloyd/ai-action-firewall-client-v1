param(
  [Parameter(Mandatory=$false)][string]$RepoPath = "H:\SG_PROGRAM_CANONICAL\repos\ai-action-firewall-client-v1",
  [Parameter(Mandatory=$false)][string]$LockPath = "H:\SG_PROGRAM_CANONICAL\repos\ai-action-firewall-client-v1\anchors\freeze.lock.json",
  [Parameter(Mandatory=$false)][string]$FreezeRoot = "H:\SG_PROGRAM_CANONICAL\freeze"
)

$ErrorActionPreference="Stop"

function Require40Hex([string]$x,[string]$label){
  if($x -notmatch '^[0-9a-fA-F]{40}$'){ throw ("STOP_{0}_NOT_40HEX:{1}" -f $label,$x) }
}

function RequireGitCommit([string]$repo,[string]$sha,[string]$label){
  & git -C $repo cat-file -e ($sha + "^{commit}") 2>$null
  if($LASTEXITCODE -ne 0){ throw ("STOP_{0}_NOT_FOUND:{1}" -f $label,$sha) }
}

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

function JsonEscape([string]$s){
  # Minimal JSON string escaper (deterministic) for ASCII+Unicode
  $sb = New-Object System.Text.StringBuilder
  foreach($ch in $s.ToCharArray()){
    $code = [int][char]$ch
    switch ($ch) {
      '"'  { [void]$sb.Append('\"'); continue }
      '\'  { [void]$sb.Append('\\'); continue }
      "`b" { [void]$sb.Append('\b'); continue }
      "`f" { [void]$sb.Append('\f'); continue }
      "`n" { [void]$sb.Append('\n'); continue }
      "`r" { [void]$sb.Append('\r'); continue }
      "`t" { [void]$sb.Append('\t'); continue }
    }
    if($code -lt 0x20){
      [void]$sb.Append(('\u{0:x4}' -f $code))
    } else {
      [void]$sb.Append($ch)
    }
  }
  $sb.ToString()
}

function BuildIntentC14N(
  [string]$added_lines,
  [string]$added_lines_sha256,
  [string]$policy_id,
  [string]$ref,
  [string]$repo,
  [string]$schema
){
  # Keys (fixed and lexicographic): added_lines, added_lines_sha256, policy_id, ref, repo, schema
  $al  = JsonEscape $added_lines
  $als = JsonEscape $added_lines_sha256
  $pi  = JsonEscape $policy_id
  $rf  = JsonEscape $ref
  $rp  = JsonEscape $repo
  $sc  = JsonEscape $schema
  '{"added_lines":"' + $al +
  '","added_lines_sha256":"' + $als +
  '","policy_id":"' + $pi +
  '","ref":"' + $rf +
  '","repo":"' + $rp +
  '","schema":"' + $sc + '"}'
}

function ExtractAddedLinesCanonical([string]$repo,[string]$base,[string]$head){
  $raw = & git -C $repo diff --unified=0 --no-color $base $head
  if($LASTEXITCODE -ne 0){ throw "STOP_GIT_DIFF_FAILED" }
  $lines = ($raw -split "`r?`n", 0)

  $added = New-Object System.Collections.Generic.List[string]
  foreach($ln in $lines){
    if($ln.StartsWith("+++ ")){ continue }   # headers: +++ b/... or +++ /dev/null
    if($ln.StartsWith("+")){
      $added.Add($ln.Substring(1)) | Out-Null
    }
  }

  # Canonical blob: ALWAYS LF-terminated; if empty => "\n"
  if($added.Count -eq 0){
    return @{ blob="`n"; count=0 }
  }
  return @{ blob=(($added -join "`n") + "`n"); count=$added.Count }
}

function ReadKeyValueFromProof([string]$path,[string]$key){
  $raw = Get-Content -LiteralPath $path -Raw
  foreach($line in ($raw -split "`r?`n")){
    if($line -like ($key + "=*")){
      return $line.Substring(($key + "=").Length).Trim()
    }
  }
  return $null
}

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

# -----------------------
# Preconditions: repo + CLEAN state (PASS impossible if dirty)
# -----------------------
if(-not (Test-Path -LiteralPath $RepoPath)){ throw "STOP_MISSING_REPOPATH" }
$gitRoot = (& git -C $RepoPath rev-parse --show-toplevel 2>$null).Trim()
if(-not $gitRoot){ throw "STOP_NOT_A_GIT_REPO" }

$porcelain = (& git -C $RepoPath status --porcelain 2>&1)
if($porcelain -and $porcelain.Trim().Length -gt 0){ throw "STOP_REPO_NOT_CLEAN" }

# -----------------------
# Lockfile: must be policy-bound
# -----------------------
if(-not (Test-Path -LiteralPath $LockPath)){ throw "STOP_LOCKFILE_MISSING" }
$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$policy_id = $lock.policy_id
if(-not $policy_id -or $policy_id.Trim().Length -eq 0){ throw "STOP_POLICY_ID_MISSING" }
if($policy_id -eq "FIXME"){ throw "STOP_POLICY_ID_IS_FIXME" }
if($policy_id -ne "ai-secrets-v1"){ throw ("STOP_POLICY_ID_UNEXPECTED:" + $policy_id) }

# -----------------------
# Bind to latest PHASE 5.2-A freeze (base/head + proven sha)
# -----------------------
if(-not (Test-Path -LiteralPath $FreezeRoot)){ throw "STOP_FREEZE_ROOT_MISSING" }
$diffFreezes = Get-ChildItem -LiteralPath $FreezeRoot -Directory |
  Where-Object { $_.Name -match '^PHASE5_2_DIFF_' } |
  Sort-Object Name -Descending

if($diffFreezes.Count -lt 1){ throw "STOP_NO_PHASE5_2_DIFF_FREEZE_FOUND" }

$srcFreeze = $diffFreezes[0].FullName
$anchorBH = Join-Path $srcFreeze "ANCHOR_BASE_HEAD.txt"
$proofRun1 = Join-Path $srcFreeze "PROOF_PHASE5_2_DIFF_RUN1.txt"

if(-not (Test-Path -LiteralPath $anchorBH)){ throw ("STOP_MISSING_ANCHOR_BASE_HEAD:" + $anchorBH) }
if(-not (Test-Path -LiteralPath $proofRun1)){ throw ("STOP_MISSING_PROOF_RUN1:" + $proofRun1) }

$base = ReadKeyValueFromProof $anchorBH "BASE"
$head = ReadKeyValueFromProof $anchorBH "HEAD"
if(-not $base){ throw "STOP_BASE_MISSING_IN_ANCHOR" }
if(-not $head){ throw "STOP_HEAD_MISSING_IN_ANCHOR" }

Require40Hex $base "BASE_SHA"
Require40Hex $head "HEAD_SHA"
RequireGitCommit $RepoPath $base "BASE_SHA"
RequireGitCommit $RepoPath $head "HEAD_SHA"

$provenAddedSha = ReadKeyValueFromProof $proofRun1 "ADDED_LINES_SHA256"
if(-not $provenAddedSha -or $provenAddedSha -notmatch '^[0-9a-fA-F]{64}$'){ throw "STOP_PROVEN_ADDED_LINES_SHA256_MISSING_OR_BAD" }
$provenAddedSha = $provenAddedSha.ToLowerInvariant()

# -----------------------
# Rebuild added_lines + verify SHA matches proven
# -----------------------
$r = ExtractAddedLinesCanonical $RepoPath $base $head
$added_blob = $r.blob
$added_count = [int]$r.count
$computed_added_sha = (Sha256HexUtf8 $added_blob).ToLowerInvariant()

if($computed_added_sha -ne $provenAddedSha){
  throw ("STOP_ADDED_LINES_SHA256_MISMATCH:computed=" + $computed_added_sha + " proven=" + $provenAddedSha)
}

# -----------------------
# repo/ref (deterministic local binding)
# -----------------------
$repoId = (& git -C $RepoPath config --get remote.origin.url 2>$null).Trim()
if(-not $repoId -or $repoId.Trim().Length -eq 0){ $repoId = "local" }

$ref = $head
$schema = "intent-v1"

# -----------------------
# RUN1/RUN2 (must be identical)
# -----------------------
$intent1 = BuildIntentC14N $added_blob $computed_added_sha $policy_id $ref $repoId $schema
$hash1 = (Sha256HexUtf8 ("HOSTED_L5_INTENT_V1:" + $intent1)).ToLowerInvariant()

$intent2 = BuildIntentC14N $added_blob $computed_added_sha $policy_id $ref $repoId $schema
$hash2 = (Sha256HexUtf8 ("HOSTED_L5_INTENT_V1:" + $intent2)).ToLowerInvariant()

if($intent1 -ne $intent2){ throw "STOP_NONDETERMINISTIC_INTENT_C14N" }
if($hash1 -ne $hash2){ throw "STOP_NONDETERMINISTIC_INTENT_HASH" }

# -----------------------
# Freeze output (PHASE 5.2-B)
# -----------------------
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$dst = Join-Path $FreezeRoot ("PHASE5_2B_INTENT_" + $ts)
New-Item -ItemType Directory -Force -Path $dst | Out-Null

# PROOF files (plain, deterministic)
$run1Path = Join-Path $dst "PROOF_PHASE5_2B_INTENT_RUN1.txt"
$run2Path = Join-Path $dst "PROOF_PHASE5_2B_INTENT_RUN2.txt"
$canonPath = Join-Path $dst "ANCHOR_INTENT_C14N.txt"
$hashPath  = Join-Path $dst "ANCHOR_INTENT_HASH.txt"
$lockCopy  = Join-Path $dst "ANCHOR_FREEZE_LOCK.json"
$bhCopy    = Join-Path $dst "ANCHOR_BASE_HEAD.txt"

@"
POLICY_ID=$policy_id
REPO=$repoId
REF=$ref
BASE=$base
HEAD=$head
ADDED_LINES_COUNT=$added_count
ADDED_LINES_SHA256=$computed_added_sha
CANON_EMPTY_BLOB=LF_ONLY
CANON_BLOB_ALWAYS_LF_TERMINATED=YES
INTENT_HASH=$hash1
"@ | Set-Content -LiteralPath $run1Path -Encoding UTF8 -NoNewline

@"
POLICY_ID=$policy_id
REPO=$repoId
REF=$ref
BASE=$base
HEAD=$head
ADDED_LINES_COUNT=$added_count
ADDED_LINES_SHA256=$computed_added_sha
CANON_EMPTY_BLOB=LF_ONLY
CANON_BLOB_ALWAYS_LF_TERMINATED=YES
INTENT_HASH=$hash2
"@ | Set-Content -LiteralPath $run2Path -Encoding UTF8 -NoNewline

$intent1 | Set-Content -LiteralPath $canonPath -Encoding UTF8 -NoNewline
$hash1   | Set-Content -LiteralPath $hashPath  -Encoding UTF8 -NoNewline

# Anchors: lockfile + base/head
(Get-Content -LiteralPath $LockPath -Raw) | Set-Content -LiteralPath $lockCopy -Encoding UTF8 -NoNewline
(Get-Content -LiteralPath $anchorBH -Raw) | Set-Content -LiteralPath $bhCopy   -Encoding UTF8 -NoNewline

# Sidecars for all non-sidecar files
Get-ChildItem -LiteralPath $dst -File | ForEach-Object {
  if($_.Name -notlike "*.sha256"){ WriteSha256Sidecar $_.FullName }
}

# GLOBAL + its sidecar (two-pass; includes GLOBAL.sha256 via rebuild; no sidecar-of-sidecar)
$global = Join-Path $dst "GLOBAL_SHA256SUMS.txt"
$globalSide = $global + ".sha256"

BuildGlobal $dst $global
$hG1 = (Get-FileHash -LiteralPath $global -Algorithm SHA256).Hash.ToLowerInvariant()
("{0}  GLOBAL_SHA256SUMS.txt" -f $hG1) | Set-Content -LiteralPath $globalSide -Encoding UTF8 -NoNewline

BuildGlobal $dst $global
$hG2 = (Get-FileHash -LiteralPath $global -Algorithm SHA256).Hash.ToLowerInvariant()
("{0}  GLOBAL_SHA256SUMS.txt" -f $hG2) | Set-Content -LiteralPath $globalSide -Encoding UTF8 -NoNewline

"FREEZE_PATH=$dst"
"STATUS=PHASE5_2B_CANON_FREEZE_COMPLETE"
"POLICY_ID=$policy_id"
"INTENT_HASH=$hash1"