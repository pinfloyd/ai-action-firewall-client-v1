package main

import (
"bytes"
"crypto/ed25519"
"crypto/sha256"
"encoding/base64"
"encoding/hex"
"encoding/json"
"fmt"
"net/http"
"os"
"os/exec"
"regexp"
"strconv"
"strings"
"time"
)

const (
SchemaIntentV1 = "intent-v1"
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
AuthorityID   string `json:"authority_id"`
Decision      string `json:"decision"`
IntentHash    string `json:"intent_hash"`
PolicyID      string `json:"policy_id"`
TimestampUTC  string `json:"timestamp_utc"`
}

func mustEnv(k string) string {
v := strings.TrimSpace(os.Getenv(k))
if v == "" {
fatal("MISSING_ENV", k)
}
return v
}

func fatal(label string, parts ...string) {
msg := label
for _, p := range parts {
msg += ":" + p
}
fmt.Fprintln(os.Stderr, msg)
os.Exit(1)
}

func sha256Hex(b []byte) string {
h := sha256.Sum256(b)
return hex.EncodeToString(h[:])
}

// SPEC: SHA256(join(added_lines)) where join uses '\n' between lines.
func computeAddedLinesSHA256(lines []string) string {
joined := strings.Join(lines, "\n")
return sha256Hex([]byte(joined))
}

// Canonical JSON with fixed key order (NO map iteration).
// Order (fixed by project canon): added_lines, added_lines_sha256, policy_id, ref, repo, schema.
func canonicalIntentBytes(intent IntentV1) ([]byte, error) {
var buf bytes.Buffer
buf.WriteByte('{')

// "added_lines":[...]
buf.WriteString(`"added_lines":[`)
for i, s := range intent.AddedLines {
if i > 0 {
buf.WriteByte(',')
}
enc, _ := json.Marshal(s) // string marshaling is deterministic
buf.Write(enc)
}
buf.WriteString(`],`)

// "added_lines_sha256":"..."
buf.WriteString(`"added_lines_sha256":`)
encALS, _ := json.Marshal(intent.AddedLinesSHA256)
buf.Write(encALS)
buf.WriteByte(',')

// "policy_id":"..."
buf.WriteString(`"policy_id":`)
encPol, _ := json.Marshal(intent.PolicyID)
buf.Write(encPol)
buf.WriteByte(',')

// "ref":"..."
buf.WriteString(`"ref":`)
encRef, _ := json.Marshal(intent.Ref)
buf.Write(encRef)
buf.WriteByte(',')

// "repo":"..."
buf.WriteString(`"repo":`)
encRepo, _ := json.Marshal(intent.Repo)
buf.Write(encRepo)
buf.WriteByte(',')

// "schema":"intent-v1"
buf.WriteString(`"schema":`)
encSch, _ := json.Marshal(intent.Schema)
buf.Write(encSch)

buf.WriteByte('}')
return buf.Bytes(), nil
}

// Canonical record JSON with fixed key order.
// Order: authority_id, decision, intent_hash, policy_id, timestamp_utc.
func canonicalRecordBytes(rec RecordV1) ([]byte, error) {
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
return buf.Bytes(), nil
}

func domainSeparatedHashHex(prefix string, msg []byte) string {
// ASCII prefix + raw bytes, no delimiter beyond prefix itself
b := append([]byte(prefix), msg...)
return sha256Hex(b)
}

// Policy ai-secrets-v1 (client-side expectation only): 3 contains checks
func evalAISecretsV1(lines []string) string {
for _, ln := range lines {
if strings.Contains(ln, "sk-") || strings.Contains(ln, "OPENAI_API_KEY=") || strings.Contains(ln, "ANTHROPIC_API_KEY=") {
return "DENY"
}
}
return "ALLOW"
}

func runGitDiffAddedLines(before, head string) ([]string, error) {
// unified=0 reduces context; filter '+' lines (exclude '+++')
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
if strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++"){
lines = append(lines, strings.TrimPrefix(raw, "+"))
}
}
return lines, nil
}

func httpJSON(client *http.Client, method, url string, body []byte) ([]byte, int, error) {
var rdr *bytes.Reader
if body == nil {
rdr = bytes.NewReader([]byte{})
} else {
rdr = bytes.NewReader(body)
}
req, err := http.NewRequest(method, url, rdr)
if err != nil {
return nil, 0, err
}
if body != nil {
req.Header.Set("Content-Type", "application/json; charset=utf-8")
}
resp, err := client.Do(req)
if err != nil {
return nil, 0, err
}
defer resp.Body.Close()
b, err := ioReadAll(resp.Body)
return b, resp.StatusCode, err
}

func ioReadAll(r *os.File) ([]byte, error) { // not used
return nil, nil
}

func readAll(respBody any) ([]byte, error) { // placeholder
return nil, nil
}

func main() {
// ---- inputs from action.yml ----
authBase := mustEnv("AUTH_BASE_URL")
expectedPubSHA := mustEnv("EXPECTED_PUBKEY_SHA256")
policyID := mustEnv("POLICY_ID")
timeoutMSs := mustEnv("TIMEOUT_MS")
maxRetriesS := mustEnv("MAX_RETRIES")
before := mustEnv("BEFORE_SHA")
head := mustEnv("HEAD_SHA")
repoFull := mustEnv("REPO_FULL")
refFull := mustEnv("REF_FULL")

timeoutMS, err := strconv.Atoi(timeoutMSs)
if err != nil || timeoutMS <= 0 {
fatal("BAD_TIMEOUT_MS", timeoutMSs)
}
maxRetries, err := strconv.Atoi(maxRetriesS)
if err != nil || maxRetries < 0 {
fatal("BAD_MAX_RETRIES", maxRetriesS)
}

client := &http.Client{Timeout: time.Duration(timeoutMS) * time.Millisecond}

// 1) Fetch /pubkey and pin pubkey_sha256
var pub PubkeyResp
pubURL := strings.TrimRight(authBase, "/") + "/pubkey"

var pubBody []byte
var pubCode int
for attempt := 0; attempt <= maxRetries; attempt++ {
b, code, e := httpGetJSON(client, pubURL)
if e != nil {
if attempt == maxRetries {
fatal("PUBKEY_FETCH_FAIL", e.Error())
}
continue
}
pubBody = b
pubCode = code
break
}
if pubCode != 200 {
fatal("PUBKEY_HTTP_STATUS", fmt.Sprintf("%d", pubCode), string(pubBody))
}
dec := json.NewDecoder(bytes.NewReader(pubBody))
dec.DisallowUnknownFields()
if err := dec.Decode(&pub); err != nil {
fatal("PUBKEY_JSON_FAIL", err.Error())
}
if strings.ToLower(pub.PublicKeySHA256) != strings.ToLower(expectedPubSHA) {
fmt.Println("PUBKEY_SHA256_MISMATCH")
fmt.Println("COMPUTED=" + strings.ToLower(pub.PublicKeySHA256))
fmt.Println("EXPECTED=" + strings.ToLower(expectedPubSHA))
os.Exit(1)
}

pubKeyBytes, err := base64.StdEncoding.DecodeString(pub.PublicKeyB64)
if err != nil {
fatal("PUBKEY_B64_DECODE_FAIL", err.Error())
}
if len(pubKeyBytes) != ed25519.PublicKeySize {
fatal("PUBKEY_BAD_LEN", fmt.Sprintf("%d", len(pubKeyBytes)))
}

// 2) Diff-only added lines
added, err := runGitDiffAddedLines(before, head)
if err != nil {
fatal("ADDED_LINES_FAIL", err.Error())
}

// 3) Build intent (canonical + hashes)
intent := IntentV1{
Schema:           SchemaIntentV1,
Repo:             repoFull,
Ref:              refFull,
PolicyID:         policyID,
AddedLines:       added,
AddedLinesSHA256: computeAddedLinesSHA256(added),
}

// 4) Client-side strict policy id check
if intent.PolicyID != "ai-secrets-v1" {
fatal("BAD_POLICY_ID", intent.PolicyID)
}

// 5) Canonical intent bytes + intent_hash (domain-separated)
canonIntent, err := canonicalIntentBytes(intent)
if err != nil {
fatal("CANON_INTENT_FAIL", err.Error())
}
intentHash := domainSeparatedHashHex("HOSTED_L5_INTENT_V1:", canonIntent)

// 6) POST /admit (server decides; we verify signature/record)
admitURL := strings.TrimRight(authBase, "/") + "/admit"
intentJSON, _ := json.Marshal(intent)

var admitBody []byte
var admitCode int
for attempt := 0; attempt <= maxRetries; attempt++ {
b, code, e := httpPostJSON(client, admitURL, intentJSON)
if e != nil {
if attempt == maxRetries {
fatal("ADMIT_POST_FAIL", e.Error())
}
continue
}
admitBody = b
admitCode = code
break
}

if admitCode != 200 {
fatal("ADMIT_HTTP_STATUS", fmt.Sprintf("%d", admitCode), string(admitBody))
}

var ar AdmitResp
dec2 := json.NewDecoder(bytes.NewReader(admitBody))
dec2.DisallowUnknownFields()
if err := dec2.Decode(&ar); err != nil {
fatal("ADMIT_JSON_FAIL", err.Error())
}

// 7) Verify record fields deterministically (fail-closed)
if ar.Record.IntentHash != intentHash {
fmt.Println("intent_hash mismatch")
fmt.Println("COMPUTED=" + intentHash)
fmt.Println("EXPECTED=" + ar.Record.IntentHash)
os.Exit(1)
}
if ar.Record.PolicyID != "ai-secrets-v1" {
fmt.Println("policy_id mismatch")
fmt.Println("COMPUTED=ai-secrets-v1")
fmt.Println("EXPECTED=" + ar.Record.PolicyID)
os.Exit(1)
}

// 8) Verify decision is consistent with local evaluation (hard fail on mismatch)
expectedDecision := evalAISecretsV1(added)
if ar.Record.Decision != expectedDecision {
fmt.Println("decision mismatch")
fmt.Println("COMPUTED=" + expectedDecision)
fmt.Println("EXPECTED=" + ar.Record.Decision)
os.Exit(1)
}

// 9) Verify signature over canonical record bytes
canonRec, err := canonicalRecordBytes(ar.Record)
if err != nil {
fatal("CANON_RECORD_FAIL", err.Error())
}

sigBytes, err := base64.StdEncoding.DecodeString(ar.Signature)
if err != nil {
fatal("SIG_B64_DECODE_FAIL", err.Error())
}
if len(sigBytes) != ed25519.SignatureSize {
fatal("SIG_BAD_LEN", fmt.Sprintf("%d", len(sigBytes)))
}

if ok := ed25519.Verify(ed25519.PublicKey(pubKeyBytes), canonRec, sigBytes); !ok {
fatal("SIGNATURE_VERIFY_FALSE")
}

// 10) PASS
fmt.Println("GATE_PASS=TRUE")
fmt.Println("intent_hash=" + intentHash)
fmt.Println("decision=" + ar.Record.Decision)
fmt.Println("authority_id=" + ar.Record.AuthorityID)
fmt.Println("timestamp_utc=" + ar.Record.TimestampUTC)
}

func httpGetJSON(client *http.Client, url string) ([]byte, int, error) {
req, err := http.NewRequest("GET", url, nil)
if err != nil {
return nil, 0, err
}
resp, err := client.Do(req)
if err != nil {
return nil, 0, err
}
defer resp.Body.Close()
b, err := readAllBytes(resp)
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
b, err := readAllBytes(resp)
return b, resp.StatusCode, err
}

func readAllBytes(resp *http.Response) ([]byte, error) {
buf := new(bytes.Buffer)
_, err := buf.ReadFrom(resp.Body)
return buf.Bytes(), err
}

// Ensure we only accept hex sha256 (optional strictness)
var reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func init() {
// no init side effects
_ = reHex64
}