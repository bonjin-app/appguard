package appguard_test

import (
	"bytes"
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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	ag "github.com/bonjin-app/appguard/sdk/go"
)

type releaseWriter struct {
	*httptest.ResponseRecorder
	initial, reset string
	deadlines      []time.Time
}

func (w *releaseWriter) SetReadDeadline(d time.Time) error {
	w.deadlines = append(w.deadlines, d)
	mode := w.initial
	if d.IsZero() {
		mode = w.reset
	}
	switch mode {
	case "error":
		return errors.New("TEST_ONLY_PRIVATE_DEADLINE")
	case "typed":
		return &ag.Error{Code: "TEST_ONLY_PRIVATE_REASON", Status: 200}
	case "panic":
		panic("TEST_ONLY_PRIVATE_DEADLINE")
	}
	return nil
}

type releaseUnwrapper struct{ http.ResponseWriter }

func (w releaseUnwrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type releaseBody struct {
	*bytes.Reader
	mode          string
	reads, closes int
}

func (b *releaseBody) Read(p []byte) (int, error) {
	b.reads++
	if b.mode == "panic" {
		panic("TEST_ONLY_PRIVATE_READ")
	}
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.mode == "error" {
		return n, errors.New("TEST_ONLY_PRIVATE_READ")
	}
	return n, err
}
func (b *releaseBody) Close() error { b.closes++; return nil }

type releaseStore func(context.Context, ag.ReplayScope, int64, int64) (bool, error)

func (f releaseStore) Claim(c context.Context, s ag.ReplayScope, e, n int64) (bool, error) {
	return f(c, s, e, n)
}

type releaseIdentity struct{}

// The signed base is independent of SDK builders and preserves duplicate query encoding.
func releaseFixture(t *testing.T, body []byte) (*http.Request, ag.HTTPOptions, *[5]int) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	target := "/release?x=%2f&x=%2F&empty"
	params := `("@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id");created=100;expires=120;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="test-key";alg="ecdsa-p256-sha256";tag="appguard-request-v0"`
	base := fmt.Sprintf("\"@method\": POST\n\"@target-uri\": https://api.example.test%s\n\"content-type\": application/octet-stream\n\"content-digest\": %s\n\"authorization\": Bearer TEST_ONLY_TOKEN\n\"appguard-app-id\": test-app\n\"@signature-params\": %s", target, digest, params)
	hash := sha256.Sum256([]byte(base))
	a, b, err := ecdsa.Sign(rand.Reader, private, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(a.FillBytes(make([]byte, 32)), b.FillBytes(make([]byte, 32))...)
	raw := &ag.RawEvidence{Method: "POST", Target: target, Headers: []ag.Header{{"Content-Type", "application/octet-stream"}, {"Content-Digest", digest}, {"Authorization", "Bearer TEST_ONLY_TOKEN"}, {"AppGuard-App-Id", "test-app"}, {"Signature-Input", "appguard=" + params}, {"Signature", "appguard=:" + base64.StdEncoding.EncodeToString(sig) + ":"}, {"Host", "ignored.example"}, {"Content-Length", strconv.Itoa(len(body))}}}
	r, err := http.NewRequest("POST", "http://ignored.example"+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.RequestURI = target
	r = r.WithContext(context.WithValue(r.Context(), releaseIdentity{}, "existing"))
	for _, h := range raw.Headers {
		if h[0] != "Host" {
			r.Header.Add(h[0], h[1])
		}
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := &ag.KeyRecord{AppID: "test-app", KeyID: "test-key", Subject: "test-user", Algorithm: ag.Algorithm, PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	store, err := ag.NewLocalReplayStore(10)
	if err != nil {
		t.Fatal(err)
	}
	counts := &[5]int{}
	o := ag.HTTPOptions{AppID: "test-app", Origin: "https://api.example.test", AllowInsecureTransport: true,
		Evidence:      func(context.Context, *http.Request) (*ag.RawEvidence, error) { return raw, nil },
		Authenticator: ag.AuthenticatorFunc(func(context.Context, ag.AuthenticationContext) (string, error) { counts[0]++; return "test-user", nil }),
		KeyResolver:   ag.KeyResolverFunc(func(context.Context, ag.KeyContext) (*ag.KeyRecord, error) { counts[1]++; return key, nil }),
		Clock:         func() int64 { counts[2]++; return 100 }, Replay: releaseStore(func(c context.Context, s ag.ReplayScope, e, n int64) (bool, error) {
			counts[3]++
			return store.Claim(c, s, e, n)
		})}
	return r, o, counts
}
func releaseHandler(t *testing.T, o ag.HTTPOptions, counts *[5]int, body []byte) http.Handler {
	t.Helper()
	h, err := ag.NewMiddleware(o, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counts[4]++
		got, err := io.ReadAll(r.Body)
		proof, ok := ag.VerificationFromContext(r.Context())
		if err != nil || !bytes.Equal(got, body) || !ok || proof.Code != "VERIFIED" || r.Context().Value(releaseIdentity{}) != "existing" || r.RequestURI != "/release?x=%2f&x=%2F&empty" {
			t.Error("healthy signed body, target, identity or proof changed")
		}
		w.WriteHeader(204)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func releaseResponse(t *testing.T, w *releaseWriter, status int, code string) {
	t.Helper()
	want := ""
	if code != "" {
		want = `{"code":"` + code + `"}`
	}
	if w.Code != status || w.Body.String() != want {
		t.Errorf("got HTTP%d %s; want HTTP%d %s", w.Code, w.Body.String(), status, want)
	}
	if code != "" && (w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Connection") != "close") {
		t.Error("failure headers changed")
	}
}
func TestHTTPDeadlineRelease(t *testing.T) {
	for _, tc := range []struct {
		name, read, initial, reset string
		status                     int
		code                       string
	}{
		{"read-ok-reset-error", "", "", "error", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-ok-reset-typed", "", "", "typed", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-ok-reset-panic", "", "", "panic", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-error-reset-error", "error", "", "error", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-oversize-reset-error", "oversize", "", "error", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-panic-reset-ok", "panic", "", "", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-panic-reset-error", "panic", "", "error", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-panic-reset-panic", "panic", "", "panic", 503, "VERIFICATION_UNAVAILABLE"},
		{"read-error-reset-ok", "error", "", "", 400, "INVALID_REQUEST"},
		{"read-oversize-reset-ok", "oversize", "", "", 413, "INVALID_REQUEST"},
		{"initial-error", "", "error", "", 503, "VERIFICATION_UNAVAILABLE"},
		{"initial-panic", "", "panic", "", 503, "VERIFICATION_UNAVAILABLE"},
		{"healthy-binary", "", "", "", 204, ""},
		{"healthy-empty", "empty", "", "", 204, ""},
		{"healthy-maximum", "maximum", "", "", 204, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte{0, 255, 128, 13, 10, 0}
			if tc.read == "empty" {
				body = nil
			}
			if tc.read == "maximum" {
				body = bytes.Repeat([]byte{0xa5}, ag.MaxBodyBytes)
			}
			r, o, counts := releaseFixture(t, body)
			input := body
			if tc.read == "oversize" {
				input = bytes.Repeat([]byte{'x'}, ag.MaxBodyBytes+1)
				r.Header.Del("Content-Length")
				r.TransferEncoding = []string{"chunked"}
				r.ContentLength = -1
				old := o.Evidence
				o.Evidence = func(c context.Context, r *http.Request) (*ag.RawEvidence, error) {
					raw, err := old(c, r)
					copy := *raw
					copy.Headers = append([]ag.Header(nil), raw.Headers[:len(raw.Headers)-1]...)
					copy.Headers = append(copy.Headers, ag.Header{"Transfer-Encoding", "chunked"})
					return &copy, err
				}
			}
			reader := &releaseBody{Reader: bytes.NewReader(input), mode: tc.read}
			r.Body = reader
			w := &releaseWriter{ResponseRecorder: httptest.NewRecorder(), initial: tc.initial, reset: tc.reset}
			releaseHandler(t, o, counts, body).ServeHTTP(w, r)
			releaseResponse(t, w, tc.status, tc.code)
			wantCalls := 2
			if tc.initial != "" {
				wantCalls = 1
			}
			if len(w.deadlines) != wantCalls || w.deadlines[0].IsZero() {
				t.Errorf("deadline setup/reset count %d, want%d", len(w.deadlines), wantCalls)
			}
			if len(w.deadlines) == 2 && !w.deadlines[1].IsZero() {
				t.Error("deadline not cleared")
			}
			if tc.initial != "" && reader.reads != 0 {
				t.Error("read started without deadline")
			}
			if reader.closes != 0 {
				t.Error("caller input stream closed")
			}
			if tc.status == 204 {
				if *counts != [5]int{1, 1, 1, 1, 1} {
					t.Errorf("healthy phases: %v", *counts)
				}
			} else {
				if *counts != [5]int{} {
					t.Errorf("failed capture advanced trusted phases: %v", *counts)
				}
				if r.Body != reader {
					t.Error("failed capture replaced input")
				}
				if _, ok := ag.VerificationFromContext(r.Context()); ok {
					t.Error("failed capture attached proof")
				}
			}
		})
	}
}
func TestHTTPDeadlineReleaseUnwrap(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(strconv.FormatBool(fault), func(t *testing.T) {
			body := []byte{0, 255, 128}
			r, o, counts := releaseFixture(t, body)
			w := &releaseWriter{ResponseRecorder: httptest.NewRecorder()}
			if fault {
				w.reset = "error"
			}
			releaseHandler(t, o, counts, body).ServeHTTP(releaseUnwrapper{releaseUnwrapper{w}}, r)
			if fault {
				releaseResponse(t, w, 503, "VERIFICATION_UNAVAILABLE")
				if *counts != [5]int{} {
					t.Error("unwrapped reset failure advanced")
				}
			} else {
				releaseResponse(t, w, 204, "")
			}
			if len(w.deadlines) != 2 || !w.deadlines[1].IsZero() {
				t.Error("unwrap reset not attempted exactly once")
			}
		})
	}
}
func TestHTTPDeadlineReleaseNonceRetry(t *testing.T) {
	body := []byte{0, 128, 255}
	template, o, counts := releaseFixture(t, body)
	h := releaseHandler(t, o, counts, body)
	for i := 0; i < 3; i++ {
		r := template.Clone(template.Context())
		r.Body = io.NopCloser(bytes.NewReader(body))
		w := &releaseWriter{ResponseRecorder: httptest.NewRecorder()}
		if i == 0 {
			w.reset = "error"
		}
		h.ServeHTTP(w, r)
		switch i {
		case 0:
			releaseResponse(t, w, 503, "VERIFICATION_UNAVAILABLE")
			if *counts != [5]int{} {
				t.Fatal("failed reset claimed nonce")
			}
		case 1:
			releaseResponse(t, w, 204, "")
		case 2:
			releaseResponse(t, w, 403, "REPLAY_DETECTED")
		}
	}
	if *counts != [5]int{2, 2, 2, 2, 1} {
		t.Errorf("retry/replay phases %v", *counts)
	}
}
