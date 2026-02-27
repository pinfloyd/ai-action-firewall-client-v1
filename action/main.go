
    }
    }
    // --- PHASE5 FIX: BEFORE_SHA may be missing in checkout; recover deterministically (fail-closed) ---
    const emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    const maxDiffBytes = 5 * 1024 * 1024 // 5 MiB cap (deterministic)

    gitHasCommit := func(sha string) bool {
        if sha == "" { return false }
        c := exec.Command("git", "cat-file", "-e", sha+"^{commit}")
        c.Stdout = nil
        c.Stderr = nil
        return c.Run() == nil
    }

    if !gitHasCommit(before) {
        fmt.Printf("BEFORE_SHA_MISSING:%s
", before)
        if before != "" {
            _ = exec.Command("git", "fetch", "--no-tags", "--depth=1", "origin", before).Run()
        }
        if !gitHasCommit(before) {
            before = emptyTree
        }
    }
    cmd := exec.Command("git", "diff", "--unified=0", before, head)
    out, err := cmd.CombinedOutput()
    if len(out) > maxDiffBytes {
        fmt.Printf("DIFF_BASE_UNAVAILABLE_TOO_LARGE:bytes=%d cap=%d
", len(out), maxDiffBytes)
        return nil, fmt.Errorf("DIFF_BASE_UNAVAILABLE_TOO_LARGE")
    }
    if len(out) > maxDiffBytes {
        fmt.Printf("DIFF_BASE_UNAVAILABLE_TOO_LARGE:bytes=%d cap=%d
", len(out), maxDiffBytes)
        return nil, fmt.Errorf("DIFF_BASE_UNAVAILABLE_TOO_LARGE")
    }
    if len(out) > maxDiffBytes {
        fmt.Printf("DIFF_BASE_UNAVAILABLE_TOO_LARGE:bytes=%d cap=%d
", len(out), maxDiffBytes)
        return nil, fmt.Errorf("DIFF_BASE_UNAVAILABLE_TOO_LARGE")
    }
    if len(out) > maxDiffBytes {
        fmt.Printf("DIFF_BASE_UNAVAILABLE_TOO_LARGE:bytes=%d cap=%d\n", len(out), maxDiffBytes)
        // fail-closed: treat as DENY (caller should propagate as hard fail)
        return nil, fmt.Errorf("DIFF_BASE_UNAVAILABLE_TOO_LARGE")
    }
if err != nil {
return nil, fmt.Errorf("GIT_DIFF_FAIL: %v\n%s", err, string(out))
}

lines := []string{}
for _, raw := range strings.Split(string(out), "\n") {
if strings.HasPrefix(raw, "+++") || strings.HasPrefix(raw, "---") || strings.HasPrefix(raw, "@@") {
continue
}
if strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++") {
lines = append(lines, strings.TrimPrefix(raw, "+"))
}
}
return lines, nil
}

func httpGet(client *http.Client, url string) ([]byte, int, error) {
req, err := http.NewRequest("GET", url, nil)
if err != nil {
return nil, 0, err
}
resp, err := client.Do(req)
if err != nil {
return nil, 0, err
}
defer resp.Body.Close()
b, err := io.ReadAll(resp.Body)
return b, resp.StatusCode, err
}

func httpPostJSON(client *http.Client, url string, body []byte) ([]byte, int, error) {
req, err := http.NewRequest("POST", url, bytes.NewReader(body))
if err != nil {
return nil, 0, err
}
req.Header.Set("Content-Type", "application/json; charset=utf-8")
resp, err := client.Do(req)
if err != nil {
return nil, 0, err
}
defer resp.Body.Close()
b, err := io.ReadAll(resp.Body)
return b, resp.StatusCode, err
}

func main() {
authBase := mustEnv("AUTH_BASE_URL")
expectedPubSHA := strings.ToLower(mustEnv("EXPECTED_PUBKEY_SHA256"))
before := mustEnv("BEFORE_SHA")
head := mustEnv("HEAD_SHA")
repoFull := mustEnv("REPO_FULL")
refFull := mustEnv("REF_FULL")

timeoutMSs := strings.TrimSpace(os.Getenv("TIMEOUT_MS"))
if timeoutMSs == "" {
timeoutMSs = "2000"
}
timeoutMS, err := strconv.Atoi(timeoutMSs)
if err != nil || timeoutMS <= 0 {
fail("BAD_TIMEOUT_MS", timeoutMSs)
}

maxRetriesS := strings.TrimSpace(os.Getenv("MAX_RETRIES"))
if maxRetriesS == "" {
maxRetriesS = "1"
}
maxRetries, err := strconv.Atoi(maxRetriesS)
if err != nil || maxRetries < 0 {
fail("BAD_MAX_RETRIES", maxRetriesS)
}

client := &http.Client{Timeout: time.Duration(timeoutMS) * time.Millisecond}

// 1) /pubkey pin
pubURL := strings.TrimRight(authBase, "/") + "/pubkey"

var pubBody []byte
var pubCode int
var lastErr error
for attempt := 0; attempt <= maxRetries; attempt++ {
b, code, e := httpGet(client, pubURL)
if e != nil {
lastErr = e
continue
}
pubBody, pubCode = b, code
lastErr = nil
break
}
if lastErr != nil {
fail("PUBKEY_FETCH_FAIL", lastErr.Error())
}
if pubCode != 200 {
fail("PUBKEY_HTTP_STATUS", fmt.Sprintf("%d", pubCode), string(pubBody))
}

var pub PubkeyResp
dec := json.NewDecoder(bytes.NewReader(pubBody))
dec.DisallowUnknownFields()
if err := dec.Decode(&pub); err != nil {
fail("PUBKEY_JSON_FAIL", err.Error())
}
if strings.ToLower(pub.PublicKeySHA256) != expectedPubSHA {
mismatch("pubkey_sha256", strings.ToLower(pub.PublicKeySHA256), expectedPubSHA)
}

pubKeyBytes, err := base64.StdEncoding.DecodeString(pub.PublicKeyB64)
if err != nil {
fail("PUBKEY_B64_DECODE_FAIL", err.Error())
}
if len(pubKeyBytes) != ed25519.PublicKeySize {
fail("PUBKEY_BAD_LEN", fmt.Sprintf("%d", len(pubKeyBytes)))
}

// 2) Diff-only added lines
added, err := runGitDiffAddedLines(before, head)
if err != nil {
fail("ADDED_LINES_FAIL", err.Error())
}

// 3) Build intent (fixed policy id, deterministic sha)
intent := IntentV1{
Schema:           SchemaIntentV1,
Repo:             repoFull,
Ref:              refFull,
PolicyID:         PolicyIDFixed,
AddedLines:       added,
AddedLinesSHA256: computeAddedLinesSHA256(added),
}

// 4) Canonical intent + intent_hash
canonIntent := canonicalIntentBytes(intent)
intentHash := domainSeparatedHashHex(IntentPrefix, canonIntent)

// 5) POST /admit
admitURL := strings.TrimRight(authBase, "/") + "/admit"
intentJSON, _ := json.Marshal(intent)

var admitBody []byte
var admitCode int
lastErr = nil
for attempt := 0; attempt <= maxRetries; attempt++ {
b, code, e := httpPostJSON(client, admitURL, intentJSON)
if e != nil {
lastErr = e
continue
}
admitBody, admitCode = b, code
lastErr = nil
break
}
if lastErr != nil {
fail("ADMIT_POST_FAIL", lastErr.Error())
}
if admitCode != 200 {
fail("ADMIT_HTTP_STATUS", fmt.Sprintf("%d", admitCode), string(admitBody))
}

var ar AdmitResp
dec2 := json.NewDecoder(bytes.NewReader(admitBody))
dec2.DisallowUnknownFields()
if err := dec2.Decode(&ar); err != nil {
fail("ADMIT_JSON_FAIL", err.Error())
}

// 6) Verify record fields fail-closed
if ar.Record.IntentHash != intentHash {
mismatch("intent_hash", intentHash, ar.Record.IntentHash)
}
if ar.Record.PolicyID != PolicyIDFixed {
mismatch("policy_id", PolicyIDFixed, ar.Record.PolicyID)
}

// 7) Verify decision matches local evaluation (hard fail on mismatch)
expectedDecision := evalAISecretsV1(added)
if ar.Record.Decision != expectedDecision {
mismatch("decision", expectedDecision, ar.Record.Decision)
}

// 8) Verify signature over canonical record bytes
canonRec := canonicalRecordBytes(ar.Record)
sigBytes, err := base64.StdEncoding.DecodeString(ar.Signature)
if err != nil {
fail("SIG_B64_DECODE_FAIL", err.Error())
}
if len(sigBytes) != ed25519.SignatureSize {
fail("SIG_BAD_LEN", fmt.Sprintf("%d", len(sigBytes)))
}
if ok := ed25519.Verify(ed25519.PublicKey(pubKeyBytes), canonRec, sigBytes); !ok {
fail("SIGNATURE_VERIFY_FALSE")
}

// PASS
fmt.Println("GATE_PASS=TRUE")
fmt.Println("intent_hash=" + intentHash)
fmt.Println("decision=" + ar.Record.Decision)
fmt.Println("authority_id=" + ar.Record.AuthorityID)
fmt.Println("timestamp_utc=" + ar.Record.TimestampUTC)
}