param(
  [Parameter(Mandatory=$false)][string]$RepoPath = "H:\SG_PROGRAM_CANONICAL\repos\ai-action-firewall-client-v1"
)

$ErrorActionPreference="Stop"

function Stop([string]$code){
  throw $code
}

function RequirePath([string]$p,[string]$code){
  if(-not (Test-Path -LiteralPath $p)){ Stop ($code + ":" + $p) }
}

function RequireGitRepo([string]$repo){
  $root = (& git -C $repo rev-parse --show-toplevel 2>$null).Trim()
  if(-not $root){ Stop "STOP_NOT_A_GIT_REPO" }
}

function RequireCleanRepo([string]$repo){
  $porc = (& git -C $repo status --porcelain 2>&1)
  if($porc -and $porc.Trim().Length -gt 0){ Stop "STOP_REPO_NOT_CLEAN" }
}

function ReadText([string]$p){
  Get-Content -LiteralPath $p -Raw
}

function RequirePolicyBoundLockfile([string]$lockPath){
  $obj = (ReadText $lockPath) | ConvertFrom-Json
  if(-not $obj.PSObject.Properties.Name.Contains("policy_id")){ Stop "STOP_LOCKFILE_MISSING_policy_id" }
  $pid = [string]$obj.policy_id
  if(-not $pid -or $pid.Trim().Length -eq 0){ Stop "STOP_LOCKFILE_EMPTY_policy_id" }
  if($pid -eq "FIXME"){ Stop "STOP_LOCKFILE_policy_id_IS_FIXME" }
  return $pid
}

function RequireExactRunsOnUbuntu2404([string]$yaml){
  # Fail-closed: require explicit "runs-on: ubuntu-24.04" (no latest)
  if($yaml -notmatch '(?m)^\s*runs-on:\s*ubuntu-24\.04\s*$'){ Stop "STOP_RUNS_ON_NOT_UBUNTU_24_04" }
  if($yaml -match '(?m)^\s*runs-on:\s*ubuntu-latest\s*$'){ Stop "STOP_RUNS_ON_UBUNTU_LATEST_FORBIDDEN" }
}

function RequirePermissionsMinimum([string]$yaml){
  # Fail-closed: require "permissions:" block containing BOTH:
  # - contents: read
  # - id-token: write
  if($yaml -notmatch '(?m)^\s*permissions:\s*$'){ Stop "STOP_PERMISSIONS_BLOCK_MISSING" }

  # We do not implement full YAML parsing; we enforce presence of required lines anywhere in file
  # AND require no explicit "id-token: none" (fail-closed).
  if($yaml -notmatch '(?m)^\s*contents:\s*read\s*$'){ Stop "STOP_PERMISSIONS_CONTENTS_READ_MISSING" }
  if($yaml -notmatch '(?m)^\s*id-token:\s*write\s*$'){ Stop "STOP_PERMISSIONS_ID_TOKEN_WRITE_MISSING" }
  if($yaml -match '(?m)^\s*id-token:\s*none\s*$'){ Stop "STOP_PERMISSIONS_ID_TOKEN_NONE_FORBIDDEN" }
}

function RequireUsesPinned([string]$yaml){
  # Enforce: every non-local "uses:" must be pinned to FULL 40-hex commit SHA.
  # Allow local actions: uses: ./... or uses: ./.github/... (no @)
  $lines = $yaml -split "`r?`n", 0
  $bad = New-Object System.Collections.Generic.List[string]
  foreach($ln in $lines){
    if($ln -match '^\s*uses:\s*(.+?)\s*$'){
      $v = $Matches[1].Trim()
      if($v.StartsWith("./") -or $v.StartsWith(".\")){
        continue
      }

      if($v -notmatch '@'){ $bad.Add("STOP_USES_NOT_PINNED_NO_AT: " + $v) | Out-Null; continue }

      $parts = $v.Split("@",2)
      if($parts.Count -ne 2){ $bad.Add("STOP_USES_BAD_FORMAT: " + $v) | Out-Null; continue }

      $ref = $parts[1].Trim()

      # Forbid floating refs
      if($ref -match '^(?i)(main|master|latest)$'){ $bad.Add("STOP_USES_FLOATING_REF: " + $v) | Out-Null; continue }
      if($ref -match '^(?i)v\d+(\.\d+){0,2}$'){ $bad.Add("STOP_USES_TAG_REF_FORBIDDEN: " + $v) | Out-Null; continue }
      if($ref -match '^(?i)v\d+(\.\d+){0,2}\.\*'){ $bad.Add("STOP_USES_TAG_RANGE_FORBIDDEN: " + $v) | Out-Null; continue }

      # Require full commit SHA
      if($ref -notmatch '^[0-9a-fA-F]{40}$'){ $bad.Add("STOP_USES_NOT_FULL_COMMIT_SHA: " + $v) | Out-Null; continue }
    }
  }
  if($bad.Count -gt 0){
    "USES_PINNING_FAIL_BEGIN"
    $bad
    "USES_PINNING_FAIL_END"
    Stop "STOP_USES_PINNING_FAIL"
  }
}

# -----------------------
# Preconditions
# -----------------------
if(-not (Test-Path -LiteralPath $RepoPath)){ Stop ("STOP_MISSING_REPOPATH:" + $RepoPath) }

RequireGitRepo $RepoPath
RequireCleanRepo $RepoPath

$wf   = Join-Path $RepoPath ".github\workflows\phase5.yml"
$lock = Join-Path $RepoPath "anchors\freeze.lock.json"
$pub  = Join-Path $RepoPath "anchors\authority_pubkey.pem"

RequirePath $wf   "STOP_MISSING_WORKFLOW"
RequirePath $lock "STOP_MISSING_LOCKFILE"
RequirePath $pub  "STOP_MISSING_AUTHORITY_PUBKEY"

$policyId = RequirePolicyBoundLockfile $lock

$yaml = ReadText $wf

RequireExactRunsOnUbuntu2404 $yaml
RequirePermissionsMinimum $yaml
RequireUsesPinned $yaml

"STATUS=PHASE5_3_PRECHECK_OK"
"POLICY_ID=$policyId"
"WORKFLOW=$wf"
"LOCKFILE=$lock"
"PUBKEY=$pub"