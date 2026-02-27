$ErrorActionPreference="Stop"

"STATUS=PHASE5_8B_FIX_DISCOVERY_RUNNING"

try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:8787/admit" -Method Get -TimeoutSec 2
    "ADMIT_STATUS=$($r.StatusCode)"
} catch {
    "ADMIT_FAIL=$($_.Exception.Message)"
}

try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:8787/pubkey" -Method Get -TimeoutSec 2
    "PUBKEY_STATUS=$($r.StatusCode)"
} catch {
    "PUBKEY_FAIL=$($_.Exception.Message)"
}

"STATUS=PHASE5_8B_FIX_DISCOVERY_DONE"