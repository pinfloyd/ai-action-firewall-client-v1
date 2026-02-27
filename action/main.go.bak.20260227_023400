package main

import (
"bytes"
"crypto/ed25519"
"crypto/sha256"
"encoding/base64"
"encoding/hex"
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"os/exec"
"strconv"
"strings"
"time"
)

const (
SchemaIntentV1 = "intent-v1"

PolicyIDFixed = "ai-secrets-v1"

IntentPrefix = "HOSTED_L5_INTENT_V1:"
// RecordPrefix is not used by the client; server signs record. We verify signature over canonical record bytes.
)

type PubkeyResp struct {
Format          string `json:"format"`
PublicKeyB64    string `json:"public_key_b64"`
PublicKeySHA256 string `json:"public_key_sha256"`
AuthorityID     string `json:"authority_id"`
}

type AdmitResp struct {
Record    RecordV1 `json:"record"`
Signature string   `json:"signature"`
}

type IntentV1 struct {
Schema           string   `json:"schema"`
Repo             string   `json:"repo"`
Ref              string   `json:"ref"`
PolicyID         string   `json:"policy_id"`
AddedLines       []string `json:"added_lines"`
AddedLinesSHA256 string   `json:"added_lines_sha256"`
}

type RecordV1 struct {
AuthorityID  string `json:"authority_id"`
Decision     string `json:"decision"`
IntentHash   string `json:"intent_hash"`
PolicyID     string `json:"policy_id"`
TimestampUTC string `json:"timestamp_utc"`
}

func mustEnv(k string) string {
v := strings.TrimSpace(os.Getenv(k))
if v == "" {
fail("MISSING_ENV", k)
}
return v
}

func fail(label string, parts ...string) {
msg := label
for _, p := range parts {
msg += ":" + p
}
fmt.Fprintln(os.Stderr, msg)
os.Exit(1)
}

func mismatch(label, computed, expected string) {
fmt.Println(label + " mismatch")
fmt.Println("COMPUTED=" + computed)
fmt.Println("EXPECTED=" + expected)
os.Exit(1)
}

func sha256Hex(b []byte) string {
h := sha256.Sum256(b)
return hex.EncodeToString(h[:])
}

// SPEC: SHA256(join(added_lines)) with '\n' as separator.
func computeAddedLinesSHA256(lines []string) string {
joined := strings.Join(lines, "\n")
return sha256Hex([]byte(joined))
}

// Canonical intent bytes with FIXED key order (no map iteration):
// added_lines, added_lines_sha256, policy_id, ref, repo, schema.
func canonicalIntentBytes(intent IntentV1) []byte {
var buf bytes.Buffer
buf.WriteByte('{')

buf.WriteString(`"added_lines":[`)
for i, s := range intent.AddedLines {
if i > 0 {
buf.WriteByte(',')
}
enc, _ := json.Marshal(s)
buf.Write(enc)
}
buf.WriteString(`],`)

buf.WriteString(`"added_lines_sha256":`)
encALS, _ := json.Marshal(intent.AddedLinesSHA256)
buf.Write(encALS)
buf.WriteByte(',')

buf.WriteString(`"policy_id":`)
encPol, _ := json.Marshal(intent.PolicyID)
buf.Write(encPol)
buf.WriteByte(',')

buf.WriteString(`"ref":`)
encRef, _ := json.Marshal(intent.Ref)
buf.Write(encRef)
buf.WriteByte(',')

buf.WriteString(`"repo":`)
encRepo, _ := json.Marshal(intent.Repo)
buf.Write(encRepo)
buf.WriteByte(',')

buf.WriteString(`"schema":`)
encSch, _ := json.Marshal(intent.Schema)
buf.Write(encSch)

buf.WriteByte('}')
return buf.Bytes()
}

// Canonical record bytes with FIXED key order:
// authority_id, decision, intent_hash, policy_id, timestamp_utc.
func canonicalRecordBytes(rec RecordV1) []byte {
var buf bytes.Buffer
buf.WriteByte('{')

buf.WriteString(`"authority_id":`)
a, _ := json.Marshal(rec.AuthorityID)
buf.Write(a)
buf.WriteByte(',')

buf.WriteString(`"decision":`)
d, _ := json.Marshal(rec.Decision)
buf.Write(d)
buf.WriteByte(',')

buf.WriteString(`"intent_hash":`)
ih, _ := json.Marshal(rec.IntentHash)
buf.Write(ih)
buf.WriteByte(',')

buf.WriteString(`"policy_id":`)
p, _ := json.Marshal(rec.PolicyID)
buf.Write(p)
buf.WriteByte(',')

buf.WriteString(`"timestamp_utc":`)
ts, _ := json.Marshal(rec.TimestampUTC)
buf.Write(ts)

buf.WriteByte('}')
return buf.Bytes()
}

func domainSeparatedHashHex(prefix string, msg []byte) string {
b := append([]byte(prefix), msg...)
return sha256Hex(b)
}

// Policy ai-secrets-v1: exactly 3 contains rules
func evalAISecretsV1(lines []string) string {
for _, ln := range lines {
if strings.Contains(ln, "sk-") ||
strings.Contains(ln, "OPENAI_API_KEY=") ||
strings.Contains(ln, "ANTHROPIC_API_KEY=") {
return "DENY"
}
}
return "ALLOW"
}

func runGitDiffAddedLines(before, head string) ([]string, error) {
cmd := exec.Command("git", "diff", "--unified=0", before, head)
out, err := cmd.CombinedOutput()
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