package appguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func baseline(t *testing.T) (Request, Parameters, []byte, VerifyOptions) {
	t.Helper()
	v := loadVectors[requestVector](t, "requests")[0]
	s, _ := NewLocalReplayStore(100)
	return v.request(t), v.Parameters, bytes64(t, v.SignatureB64), VerifyOptions{Origin: v.Context.Origin, AppID: v.Context.AppID, Subject: v.Context.Subject, Now: v.Context.Now, Key: &v.Key, Replay: s}
}
func TestStrictBoundaries(t *testing.T) {
	type input struct {
		r Request
		p Parameters
		s []byte
		o VerifyOptions
	}
	cases := []struct {
		name, want string
		mutate     func(*input)
	}{
		{"lowercase-method", "INVALID_REQUEST", func(v *input) { v.r.Method = "post" }},
		{"method-newline", "INVALID_REQUEST", func(v *input) { v.r.Method += "\n" }},
		{"method-size", "INVALID_REQUEST", func(v *input) { v.r.Method = strings.Repeat("A", 33) }},
		{"target-newline", "INVALID_REQUEST", func(v *input) { v.r.Target += "\n" }},
		{"target-size", "INVALID_REQUEST", func(v *input) { v.r.Target = "/" + strings.Repeat("a", 8192) }},
		{"dot-encoded-slash", "INVALID_REQUEST", func(v *input) { v.r.Target = "/safe%2f..%2fa" }},
		{"encoded-control", "INVALID_REQUEST", func(v *input) { v.r.Target = "/%00" }},
		{"encoded-backslash", "INVALID_REQUEST", func(v *input) { v.r.Target = "/%5c" }},
		{"encoded-dot", "INVALID_REQUEST", func(v *input) { v.r.Target = "/%2e%2e/x" }},
		{"header-count", "INVALID_REQUEST", func(v *input) {
			for i := 0; i < 61; i++ {
				v.r.Headers = append(v.r.Headers, Header{"X-Pad", "v"})
			}
		}},
		{"header-size", "INVALID_REQUEST", func(v *input) { v.r.Headers = append(v.r.Headers, Header{"X-Pad", strings.Repeat("a", 16385)}) }},
		{"header-tab", "INVALID_REQUEST", func(v *input) { v.r.Headers = append(v.r.Headers, Header{"X-Pad", "\tv"}) }},
		{"header-name-newline", "INVALID_REQUEST", func(v *input) { v.r.Headers = append(v.r.Headers, Header{"X-Pad\n", "v"}) }},
		{"body-size", "INVALID_REQUEST", func(v *input) { v.r.Body = make([]byte, 1048577) }},
		{"origin-upper", "INVALID_REQUEST", func(v *input) { v.o.Origin = "https://API.example.test" }},
		{"origin-443", "INVALID_REQUEST", func(v *input) { v.o.Origin += ":443" }},
		{"origin-port-overflow", "INVALID_REQUEST", func(v *input) { v.o.Origin += ":65536" }},
		{"origin-http", "INVALID_REQUEST", func(v *input) { v.o.Origin = "http://api.example.test" }},
		{"invalid-app", "INVALID_REQUEST", func(v *input) { v.o.AppID += "\n" }},
		{"invalid-subject", "INVALID_REQUEST", func(v *input) { v.o.Subject = "" }},
		{"negative-created", "INVALID_TIME", func(v *input) { v.p.Created = -1 }},
		{"oversized-clock", "INVALID_TIME", func(v *input) { v.o.Now = 1000000000000000 }},
		{"long-lifetime", "INVALID_TIME", func(v *input) { v.p.Expires = v.p.Created + 121 }},
		{"zero-lifetime", "INVALID_TIME", func(v *input) { v.p.Expires = v.p.Created }},
		{"future-skew", "INVALID_TIME", func(v *input) { v.p.Created = v.o.Now + 31; v.p.Expires = v.p.Created + 1 }},
		{"bad-pem", "KEY_REJECTED", func(v *input) { v.o.Key.PublicKeyPEM = "SECRET" }},
		{"oversized-pem", "KEY_REJECTED", func(v *input) { v.o.Key.PublicKeyPEM = strings.Repeat("x", 4097) }},
		{"key-prefix", "KEY_REJECTED", func(v *input) { v.o.Key.PublicKeyPEM = "SECRET" + v.o.Key.PublicKeyPEM }},
		{"key-trailing-block", "KEY_REJECTED", func(v *input) { v.o.Key.PublicKeyPEM += v.o.Key.PublicKeyPEM }},
		{"zero-scalars", "INVALID_SIGNATURE", func(v *input) { v.s = make([]byte, 64) }},
		{"nil-store", "REPLAY_STORE_UNAVAILABLE", func(v *input) { v.o.Replay = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p, s, o := baseline(t)
			v := input{r, p, s, o}
			tc.mutate(&v)
			claims := 0
			if tc.name != "nil-store" {
				v.o.Replay = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) { claims++; return true, nil })
			}
			_, err := VerifyRequest(context.Background(), v.r, v.p, v.s, v.o)
			if code(err) != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
			if claims != 0 {
				t.Fatal("failure consumed nonce")
			}
		})
	}
}
func TestNativeKeyAndSignature(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			r, p, _, o := baseline(t)
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			o.Key.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			base, err := BuildSignatureBase(r, p, o.Origin)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(base)
			a, b, err := ecdsa.Sign(rand.Reader, key, hash[:])
			if err != nil {
				t.Fatal(err)
			}
			sig := append(a.FillBytes(make([]byte, (curve.Params().BitSize+7)/8)), b.FillBytes(make([]byte, (curve.Params().BitSize+7)/8))...)
			_, err = VerifyRequest(context.Background(), r, p, sig, o)
			want := "VERIFIED"
			if curve != elliptic.P256() {
				want = "KEY_REJECTED"
			}
			if code(err) != want {
				t.Fatal(err)
			}
		})
	}
}
func TestReplayAtomicCapacityExpiryAndCancellation(t *testing.T) {
	store, err := NewLocalReplayStore(1)
	if err != nil {
		t.Fatal(err)
	}
	scope := ReplayScope{"a", "k", "AAECAwQFBgcICQoLDA0ODw"}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.Claim(context.Background(), scope, 120, 0)
			if err != nil {
				t.Error(err)
			}
			if ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal(accepted.Load())
	}
	other := scope
	other.KeyID = "other"
	if _, err := store.Claim(context.Background(), other, 120, 0); err == nil {
		t.Fatal("capacity did not reject")
	}
	if ok, err := store.Claim(context.Background(), other, 121, 120); err != nil || !ok {
		t.Fatal(ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Claim(ctx, scope, 122, 121); err == nil {
		t.Fatal("cancelled claim allowed")
	}
	if ok, err := store.Claim(context.Background(), scope, 122, 121); err != nil || !ok {
		t.Fatal(ok, err)
	}
	for _, c := range []int{-1, 0} {
		if _, err := NewLocalReplayStore(c); err == nil {
			t.Fatal("invalid capacity")
		}
	}
}
func TestReplayVerifierConcurrency(t *testing.T) {
	r, p, s, o := baseline(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := VerifyRequest(context.Background(), r, p, s, o)
			if err == nil {
				accepted.Add(1)
			} else if code(err) != "REPLAY_DETECTED" {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal(accepted.Load())
	}
}
func TestPolicyDefaultsAndAuditRedaction(t *testing.T) {
	for _, profile := range []string{"basic", "balanced", "strict"} {
		d, err := EvaluatePolicy(Policy{Profile: profile}, PolicyContext{}, 100)
		if err != nil || d.Code != "AUTHENTICATION_REQUIRED" || d.PermitsProcessing() {
			t.Fatal(d, err)
		}
	}
	no := false
	for _, profile := range []string{"balanced", "strict"} {
		if _, err := EvaluatePolicy(Policy{Profile: profile, RequireSignature: &no}, PolicyContext{}, 0); code(err) != "INVALID_POLICY" {
			t.Fatal(err)
		}
	}
	fresh := int64(101)
	ctx := PolicyContext{Authentication: "authenticated", Verification: "verified", Attestation: "verified", AttestationExpires: &fresh, RiskSignals: []string{"private_hint"}}
	d, err := EvaluatePolicy(Policy{}, ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	event, err := AuditEvent(d, AuditOptions{EventID: "event-1", AppID: "app-1", Now: 100, Context: &ctx})
	if err != nil {
		t.Fatal(err)
	}
	line, err := event.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), "private_hint") || strings.Contains(string(line), "subject") || !strings.Contains(string(line), `"risk_count":1`) {
		t.Fatal(string(line))
	}
	sink, err := NewJSONAuditSink(func(context.Context, []byte) error { return errors.New("SECRET") })
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.Emit(context.Background(), d, AuditOptions{EventID: "event", AppID: "app", Now: 100}); code(err) != "AUDIT_UNAVAILABLE" || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
	d = PolicyDecision{Action: "allow", Code: "RATE_LIMITED", Profile: "basic"}
	if _, err := AuditEvent(d, AuditOptions{EventID: "event", AppID: "app", Now: 100}); code(err) != "INVALID_AUDIT_EVENT" {
		t.Fatal(err)
	}
	d, err = EvaluatePolicy(Policy{Profile: "balanced"}, PolicyContext{Authentication: "authenticated", Verification: "verified"}, 100)
	if err != nil || d.Action != "step_up" || d.PermitsProcessing() {
		t.Fatal(d, err)
	}
}
func TestPolicyValidation(t *testing.T) {
	for _, signals := range [][]string{{"root", "root"}, {"SECRET token"}, make([]string, 33)} {
		if _, err := EvaluatePolicy(Policy{SuspiciousSignals: signals}, PolicyContext{}, 0); code(err) != "INVALID_POLICY" {
			t.Fatal(err)
		}
	}
	for _, ctx := range []PolicyContext{{Authentication: "SECRET"}, {Verification: "SECRET"}, {Attestation: "SECRET"}, {RiskSignals: []string{"root", "root"}}} {
		if _, err := EvaluatePolicy(Policy{}, ctx, 0); code(err) != "INVALID_POLICY_CONTEXT" {
			t.Fatal(err)
		}
	}
	if _, err := EvaluatePolicy(Policy{}, PolicyContext{}, -1); code(err) != "INVALID_POLICY_CONTEXT" {
		t.Fatal(err)
	}
}

// independent signature helper intentionally constructs the protocol lines itself.
func signed(t *testing.T, target string, body []byte) (Request, Parameters, []byte, *KeyRecord) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	r := Request{Method: "POST", Target: target, Body: body, Headers: []Header{{"Content-Type", "application/octet-stream"}, {"Content-Digest", digest}, {"Authorization", "Bearer TEST_ONLY_TOKEN"}, {"AppGuard-App-Id", "test-app"}}}
	p := Parameters{Created: 100, Expires: 120, Nonce: "AAECAwQFBgcICQoLDA0ODw", KeyID: "test-key", Algorithm: Algorithm, Tag: Tag}
	params := `("@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id");created=100;expires=120;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="test-key";alg="ecdsa-p256-sha256";tag="appguard-request-v0"`
	base := fmt.Sprintf("\"@method\": POST\n\"@target-uri\": https://api.example.test%s\n\"content-type\": application/octet-stream\n\"content-digest\": %s\n\"authorization\": Bearer TEST_ONLY_TOKEN\n\"appguard-app-id\": test-app\n\"@signature-params\": %s", target, digest, params)
	h := sha256.Sum256([]byte(base))
	a, b, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(a.FillBytes(make([]byte, 32)), b.FillBytes(make([]byte, 32))...)
	r.Headers = append(r.Headers, Header{"Signature-Input", "appguard=" + params}, Header{"Signature", "appguard=:" + base64.StdEncoding.EncodeToString(sig) + ":"})
	return r, p, sig, &KeyRecord{AppID: "test-app", KeyID: "test-key", Subject: "test-user", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Algorithm: Algorithm}
}
