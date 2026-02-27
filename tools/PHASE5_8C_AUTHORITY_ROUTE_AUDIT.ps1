$ErrorActionPreference="Stop"

Write-Host "STATUS=PHASE5_8C_AUTHORITY_ROUTE_AUDIT_RUNNING"

$AUTH_URL=$env:L5_AUTH_URL
if([string]::IsNullOrWhiteSpace($AUTH_URL)){
    throw "AUTH_URL_MISSING"
}

Write-Host "AUTH_URL=$AUTH_URL"

# --- PUBKEY CHECK ---
try{
    $pub = Invoke-WebRequest `
        -Uri "$AUTH_URL/pubkey" `
        -Method GET `
        -UseBasicParsing `
        -TimeoutSec 5

    Write-Host "PUBKEY_STATUS=$($pub.StatusCode)"
}
catch{
    Write-Host "PUBKEY_FAIL=$($_.Exception.Message)"
}

# --- ADMIT METHOD CHECK ---
try{
    $resp = Invoke-WebRequest `
        -Uri "$AUTH_URL/admit" `
        -Method POST `
        -Body "{}" `
        -ContentType "application/json" `
        -UseBasicParsing `
        -TimeoutSec 5

    Write-Host "ADMIT_STATUS=$($resp.StatusCode)"
}
catch{
    Write-Host "ADMIT_FAIL=$($_.Exception.Message)"
}

Write-Host "STATUS=PHASE5_8C_AUTHORITY_ROUTE_AUDIT_DONE"
