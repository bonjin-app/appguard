// Package appguard implements the experimental appguard-request-v0 protocol.
// Successful request verification is neither authentication, authorization nor
// platform attestation. Applications explicitly supply trusted identity and keys.
package appguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const Algorithm = "ecdsa-p256-sha256"
const Tag = "appguard-request-v0"
const MaxBodyBytes = 1048576
const maxTime int64 = 999999999999999
const covered = `"@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id"`

var components = [...]string{"@method", "@target-uri", "content-type", "content-digest", "authorization", "appguard-app-id"}
var tokenRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var identifierRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
var originRE = regexp.MustCompile(`^https://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?$`)
var labelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var targetRE = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/?%\-]*$`)
var bearerRE = regexp.MustCompile(`(?i)^Bearer [A-Za-z0-9._~+/-]+=*$`)
var digestRE = regexp.MustCompile(`^sha-256=:[A-Za-z0-9+/]{43}=:$`)
var inputRE = regexp.MustCompile(`^appguard=\(` + regexp.QuoteMeta(covered) + `\);created=(0|-?[1-9][0-9]{0,14});expires=(0|-?[1-9][0-9]{0,14});nonce="([A-Za-z0-9_-]{22})";keyid="([A-Za-z0-9._:-]{1,128})";alg="([A-Za-z0-9._:-]{1,64})";tag="([A-Za-z0-9._:-]{1,64})"$`)
var signatureRE = regexp.MustCompile(`^appguard=:([A-Za-z0-9+/]{86}==):$`)
var lengthRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// Error contains only a fixed protocol code and HTTP status, with no input data.
type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string { return e.Code }
func failure(code string) *Error {
	status := 403
	switch code {
	case "INVALID_REQUEST":
		status = 400
	case "AUTHENTICATION_REQUIRED":
		status = 401
	case "IDENTITY_UNAVAILABLE", "KEY_RESOLVER_UNAVAILABLE", "VERIFICATION_UNAVAILABLE", "REPLAY_STORE_UNAVAILABLE":
		status = 503
	}
	return &Error{Code: code, Status: status}
}
func invalid() *Error        { return failure("INVALID_REQUEST") }
func validTime(t int64) bool { return t >= 0 && t <= maxTime }
func validNonce(n string) bool {
	if !nonceRE.MatchString(n) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(n)
	return err == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == n
}
func validOrigin(origin string) bool {
	if len(origin) > 512 {
		return false
	}
	m := originRE.FindStringSubmatch(origin)
	if m == nil || len(m[1]) > 253 {
		return false
	}
	for _, label := range strings.Split(m[1], ".") {
		if !labelRE.MatchString(label) {
			return false
		}
	}
	if m[2] != "" {
		p, _ := strconv.Atoi(m[2])
		if p > 65535 || p == 443 {
			return false
		}
	}
	return true
}
func hex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}
func validTarget(target string) bool {
	if len(target) > 8192 || strings.HasPrefix(target, "//") || !targetRE.MatchString(target) {
		return false
	}
	decoded := make([]byte, 0, len(target))
	pathEnd := strings.IndexByte(target, '?')
	if pathEnd < 0 {
		pathEnd = len(target)
	}
	decodedPathEnd := 0
	for i := 0; i < len(target); i++ {
		if i == pathEnd {
			decodedPathEnd = len(decoded)
		}
		b := target[i]
		if b == '%' {
			if i+2 >= len(target) {
				return false
			}
			a, ok := hex(target[i+1])
			z, ok2 := hex(target[i+2])
			if !ok || !ok2 {
				return false
			}
			b = a*16 + z
			i += 2
		}
		if b < 32 || b == 127 || b == '\\' {
			return false
		}
		decoded = append(decoded, b)
	}
	if pathEnd == len(target) {
		decodedPathEnd = len(decoded)
	}
	for _, s := range strings.Split(string(decoded[:decodedPathEnd]), "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}

// Header retains each original field occurrence, including unrelated fields.
type Header [2]string

// UnmarshalJSON rejects short/extra/non-string elements instead of accepting
// encoding/json's normal fixed-array truncation or null-to-zero conversion.
func (h *Header) UnmarshalJSON(data []byte) error {
	var pair []any
	if json.Unmarshal(data, &pair) != nil || len(pair) != 2 {
		return invalid()
	}
	name, ok := pair[0].(string)
	value, ok2 := pair[1].(string)
	if !ok || !ok2 {
		return invalid()
	}
	*h = Header{name, value}
	return nil
}

// Request contains the original origin-form target and exact content bytes.
type Request struct {
	Method  string
	Target  string
	Headers []Header
	Body    []byte
}
type Parameters struct {
	Created   int64  `json:"created"`
	Expires   int64  `json:"expires"`
	Nonce     string `json:"nonce"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Tag       string `json:"tag"`
}
type KeyRecord struct {
	AppID        string `json:"app_id"`
	KeyID        string `json:"key_id"`
	Subject      string `json:"subject"`
	PublicKeyPEM string `json:"public_key_pem"`
	Algorithm    string `json:"algorithm"`
	Revoked      bool   `json:"revoked"`
}
type Verification struct {
	AppID   string `json:"app_id"`
	KeyID   string `json:"key_id"`
	Expires int64  `json:"expires"`
	Code    string `json:"code"`
}
type VerifyOptions struct {
	Origin  string
	AppID   string
	Subject string
	Key     *KeyRecord
	Now     int64
	Replay  ReplayStore
}

func headerMap(headers []Header, wire bool) (map[string]string, error) {
	if len(headers) > 64 {
		return nil, invalid()
	}
	m := make(map[string]string, len(headers))
	size := 0
	for _, h := range headers {
		name, value := h[0], h[1]
		if !tokenRE.MatchString(name) || strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
			return nil, invalid()
		}
		for i := 0; i < len(value); i++ {
			if value[i] < 32 || value[i] > 126 {
				return nil, invalid()
			}
		}
		size += len(name) + len(value)
		if size > 16384 {
			return nil, invalid()
		}
		name = strings.ToLower(name)
		singleton := name == "content-type" || name == "content-digest" || name == "authorization" || name == "appguard-app-id" || name == "content-encoding"
		if wire {
			singleton = singleton || name == "signature-input" || name == "signature" || name == "content-length" || name == "transfer-encoding" || name == "host"
		}
		if _, ok := m[name]; singleton && ok {
			return nil, invalid()
		}
		m[name] = value
	}
	return m, nil
}
func digestBytes(value string) ([]byte, error) {
	if !digestRE.MatchString(value) {
		return nil, invalid()
	}
	b64 := value[9 : len(value)-1]
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != b64 {
		return nil, invalid()
	}
	return b, nil
}
func validateRequest(r Request) (map[string]string, error) {
	if len(r.Body) > MaxBodyBytes || len(r.Method) > 32 || !tokenRE.MatchString(r.Method) || r.Method != strings.ToUpper(r.Method) || !validTarget(r.Target) {
		return nil, invalid()
	}
	h, err := headerMap(r.Headers, false)
	if err != nil {
		return nil, err
	}
	for _, n := range components[2:] {
		if _, ok := h[n]; !ok {
			return nil, invalid()
		}
	}
	if h["content-type"] == "" || !bearerRE.MatchString(h["authorization"]) || !identifierRE.MatchString(h["appguard-app-id"]) {
		return nil, invalid()
	}
	if e, ok := h["content-encoding"]; ok && e != "identity" {
		return nil, invalid()
	}
	if _, err = digestBytes(h["content-digest"]); err != nil {
		return nil, err
	}
	return h, nil
}
func validateParameters(p Parameters) error {
	if p.Algorithm != Algorithm || p.Tag != Tag {
		return failure("UNSUPPORTED_PROFILE")
	}
	if !identifierRE.MatchString(p.KeyID) || !validNonce(p.Nonce) {
		return invalid()
	}
	if !validTime(p.Created) || !validTime(p.Expires) {
		return failure("INVALID_TIME")
	}
	return nil
}
func SerializeParameters(p Parameters) string {
	return fmt.Sprintf(`(%s);created=%d;expires=%d;nonce="%s";keyid="%s";alg="%s";tag="%s"`, covered, p.Created, p.Expires, p.Nonce, p.KeyID, p.Algorithm, p.Tag)
}
func BuildSignatureBase(r Request, p Parameters, origin string) ([]byte, error) {
	h, err := validateRequest(r)
	if err != nil {
		return nil, err
	}
	if !validOrigin(origin) {
		return nil, invalid()
	}
	if err = validateParameters(p); err != nil {
		return nil, err
	}
	values := []string{r.Method, origin + r.Target, h["content-type"], h["content-digest"], h["authorization"], h["appguard-app-id"]}
	lines := make([]string, 0, 7)
	for i, n := range components {
		lines = append(lines, `"`+n+`": `+values[i])
	}
	lines = append(lines, `"@signature-params": `+SerializeParameters(p))
	return []byte(strings.Join(lines, "\n")), nil
}

// ValidateFraming checks the strict wire envelope. A non-nil bodyLength also
// validates Content-Length against captured bytes. It never interprets a body.
func ValidateFraming(headers []Header, bodyLength *int) (map[string]string, error) {
	h, err := headerMap(headers, true)
	if err != nil {
		return nil, err
	}
	length, hasLength := h["content-length"]
	encoding, hasEncoding := h["transfer-encoding"]
	if hasLength && hasEncoding || hasEncoding && encoding != "chunked" {
		return nil, invalid()
	}
	if e, ok := h["content-encoding"]; ok && e != "identity" {
		return nil, invalid()
	}
	if hasLength {
		if !lengthRE.MatchString(length) {
			return nil, invalid()
		}
		n, err := strconv.ParseUint(length, 10, 64)
		if err != nil || n > MaxBodyBytes {
			return nil, &Error{Code: "INVALID_REQUEST", Status: 413}
		}
		if bodyLength != nil && (*bodyLength < 0 || n != uint64(*bodyLength)) {
			return nil, invalid()
		}
	}
	return h, nil
}
func ParseSignatures(headers []Header) (Parameters, []byte, error) {
	var p Parameters
	h, err := ValidateFraming(headers, nil)
	if err != nil {
		return p, nil, err
	}
	m := inputRE.FindStringSubmatch(h["signature-input"])
	s := signatureRE.FindStringSubmatch(h["signature"])
	if m == nil || s == nil || !validNonce(m[3]) {
		return p, nil, invalid()
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(s[1])
	if err != nil || len(sig) != 64 || base64.StdEncoding.EncodeToString(sig) != s[1] {
		return p, nil, invalid()
	}
	p.Created, _ = strconv.ParseInt(m[1], 10, 64)
	p.Expires, _ = strconv.ParseInt(m[2], 10, 64)
	p.Nonce = m[3]
	p.KeyID = m[4]
	p.Algorithm = m[5]
	p.Tag = m[6]
	if p.Algorithm != Algorithm || p.Tag != Tag {
		return p, nil, failure("UNSUPPORTED_PROFILE")
	}
	return p, sig, nil
}
func publicKey(text string) (*ecdsa.PublicKey, error) {
	// pem.Decode scans past malformed blocks. Never let a later PUBLIC KEY
	// replace the single registry envelope supplied by the caller.
	if len(text) == 0 || len(text) > 4096 || !strings.HasPrefix(text, "-----BEGIN PUBLIC KEY-----") || strings.Count(text, "-----BEGIN PUBLIC KEY-----") != 1 {
		return nil, failure("KEY_REJECTED")
	}
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, failure("KEY_REJECTED")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, failure("KEY_REJECTED")
	}
	k, ok := key.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil || !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, failure("KEY_REJECTED")
	}
	return k, nil
}

// VerifyRequest checks syntax, time, binding, digest, signature, then claims the
// nonce atomically. No replay store or identity is silently installed.
func VerifyRequest(ctx context.Context, r Request, p Parameters, signature []byte, o VerifyOptions) (Verification, error) {
	var result Verification
	if !identifierRE.MatchString(o.AppID) || !identifierRE.MatchString(o.Subject) {
		return result, invalid()
	}
	base, err := BuildSignatureBase(r, p, o.Origin)
	if err != nil {
		return result, err
	}
	if !validTime(o.Now) || p.Created >= p.Expires || p.Expires-p.Created > 120 || p.Created > o.Now+30 || o.Now >= p.Expires {
		return result, failure("INVALID_TIME")
	}
	h, _ := headerMap(r.Headers, false)
	k := o.Key
	if k == nil || k.Revoked || k.AppID != o.AppID || h["appguard-app-id"] != o.AppID || k.Subject != o.Subject || k.KeyID != p.KeyID || k.Algorithm != Algorithm {
		return result, failure("KEY_REJECTED")
	}
	key, err := publicKey(k.PublicKeyPEM)
	if err != nil {
		return result, err
	}
	expected, _ := digestBytes(h["content-digest"])
	actual := sha256.Sum256(r.Body)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return result, failure("DIGEST_MISMATCH")
	}
	if len(signature) != 64 {
		return result, failure("INVALID_SIGNATURE")
	}
	hash := sha256.Sum256(base)
	if !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return result, failure("INVALID_SIGNATURE")
	}
	if ctx == nil || ctx.Err() != nil || nilInterface(o.Replay) {
		return result, failure("REPLAY_STORE_UNAVAILABLE")
	}
	claimed, err := claim(ctx, o.Replay, ReplayScope{o.AppID, k.KeyID, p.Nonce}, p.Expires, o.Now)
	if err != nil || ctx.Err() != nil {
		return result, failure("REPLAY_STORE_UNAVAILABLE")
	}
	if !claimed {
		return result, failure("REPLAY_DETECTED")
	}
	return Verification{AppID: o.AppID, KeyID: k.KeyID, Expires: p.Expires, Code: "VERIFIED"}, nil
}
