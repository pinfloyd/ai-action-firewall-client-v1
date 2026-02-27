param(
  [Parameter(Mandatory=$false)][string]$Audience = "hosted-l5"
)

$ErrorActionPreference="Stop"

function OutKV([string]$k,[string]$v){ "$k=$v" }

$inActions = ($env:GITHUB_ACTIONS -eq "true")

$reqUrl   = $env:ACTIONS_ID_TOKEN_REQUEST_URL
$reqToken = $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN

if([string]::IsNullOrWhiteSpace($reqUrl) -or [string]::IsNullOrWhiteSpace($reqToken)){
  if($inActions){
    throw "STOP_OIDC_ENV_MISSING_IN_ACTIONS"
  } else {
    OutKV "STATUS" "OIDC_NOT_AVAILABLE_LOCAL"
    OutKV "GITHUB_ACTIONS" ($env:GITHUB_ACTIONS)
    exit 0
  }
}

# GitHub expects Authorization: bearer <token> and audience query
$uri = $reqUrl
if($uri -match '\?'){ $uri = $uri + "&audience=" + [Uri]::EscapeDataString($Audience) }
else { $uri = $uri + "?audience=" + [Uri]::EscapeDataString($Audience) }

$headers = @{ Authorization = ("bearer " + $reqToken) }

try {
  $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 10
} catch {
  throw ("STOP_OIDC_TOKEN_REQUEST_FAILED:" + $_.Exception.Message)
}

# GitHub returns JSON with "value" (JWT)
$jwt = $resp.value
if([string]::IsNullOrWhiteSpace($jwt)){
  throw "STOP_OIDC_RESPONSE_MISSING_VALUE"
}

OutKV "STATUS" "OIDC_TOKEN_OBTAINED"
OutKV "AUDIENCE" $Audience
OutKV "JWT_LENGTH" ($jwt.Length.ToString())