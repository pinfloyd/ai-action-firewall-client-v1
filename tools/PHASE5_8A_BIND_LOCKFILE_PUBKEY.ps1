$ErrorActionPreference="Stop"

$REPO="H:\SG_PROGRAM_CANONICAL\repos\ai-action-firewall-client-v1"
$ANCH=Join-Path $REPO "anchors"

$AUTH_PATH=Join-Path $ANCH "authority.json"
$LOCK_PATH=Join-Path $ANCH "freeze.lock.json"

if(-not (Test-Path -LiteralPath $AUTH_PATH)){ throw "STOP_AUTH_MISSING" }
if(-not (Test-Path -LiteralPath $LOCK_PATH)){ throw "STOP_LOCK_MISSING" }

$authObj = (Get-Content -LiteralPath $AUTH_PATH -Raw) | ConvertFrom-Json
$lockObj = (Get-Content -LiteralPath $LOCK_PATH -Raw) | ConvertFrom-Json

if([string]::IsNullOrWhiteSpace($authObj.pubkey_sha256)){
    throw "STOP_AUTH_PUBKEY_EMPTY"
}

if($authObj.pubkey_sha256 -notmatch '^[0-9a-f]{64}$'){
    throw "STOP_AUTH_PUBKEY_NOT_HEX64"
}

# ---- deterministic add/set ----
if(-not ($lockObj.PSObject.Properties.Name -contains "pubkey_sha256")){
    $lockObj | Add-Member -MemberType NoteProperty `
        -Name "pubkey_sha256" `
        -Value $authObj.pubkey_sha256
}
else{
    $lockObj.pubkey_sha256 = $authObj.pubkey_sha256
}

$tmpPath = "$LOCK_PATH.tmp"

($lockObj | ConvertTo-Json -Compress) |
Set-Content -LiteralPath $tmpPath -NoNewline

Move-Item -LiteralPath $tmpPath -Destination $LOCK_PATH -Force

# ---- post verify ----
$verify = (Get-Content -LiteralPath $LOCK_PATH -Raw) | ConvertFrom-Json

if($verify.pubkey_sha256 -ne $authObj.pubkey_sha256){
    throw "STOP_POSTVERIFY_LOCK_PUBKEY"
}

"STATUS=PHASE5_8A_LOCKFILE_PUBKEY_BOUND"
"PUBKEY_SHA256=$($verify.pubkey_sha256)"
"LOCKFILE=$LOCK_PATH"