package appguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeaderJSONRejectsLostPairEvidence(t *testing.T) {
	for _, input := range []string{`["name"]`, `["name","value","discarded"]`, `[null,"value"]`, `["name",true]`} {
		var h Header
		if err := json.Unmarshal([]byte(input), &h); err == nil {
			t.Fatalf("lost raw pair evidence: %s", input)
		}
	}
	var h Header
	if err := json.Unmarshal([]byte(`["name","value"]`), &h); err != nil || h != (Header{"name", "value"}) {
		t.Fatal(h, err)
	}
}
func TestCancellationAtReplayNeverPermits(t *testing.T) {
	r, p, s, o := baseline(t)
	ctx, cancel := context.WithCancel(context.Background())
	o.Replay = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) { cancel(); return true, nil })
	if _, err := VerifyRequest(ctx, r, p, s, o); code(err) != "REPLAY_STORE_UNAVAILABLE" {
		t.Fatal(err)
	}
}
func TestCryptoRejectsDERPrivateKeysAndInvalidScalarRanges(t *testing.T) {
	r, p, s, o := baseline(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	o.Key.PublicKeyPEM = pemText
	if _, err = VerifyRequest(context.Background(), r, p, s, o); code(err) != "KEY_REJECTED" {
		t.Fatal(err)
	}
	r, p, s, o = baseline(t)
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(s[:32]), new(big.Int).SetBytes(s[32:])})
	if _, err = VerifyRequest(context.Background(), r, p, der, o); code(err) != "INVALID_SIGNATURE" {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	for _, part := range []int{0, 32} {
		r, p, s, o = baseline(t)
		copy(s[part:part+32], n.FillBytes(make([]byte, 32)))
		if _, err = VerifyRequest(context.Background(), r, p, s, o); code(err) != "INVALID_SIGNATURE" {
			t.Fatal(err)
		}
	}
}
func TestWireLexicalAndCanonicalNegativeBoundaries(t *testing.T) {
	vectors := loadVectors[struct{ Headers []Header }](t, "http")
	original := vectors[0].Headers
	for _, tc := range []struct {
		name     string
		field    int
		from, to string
	}{
		{"plus-integer", 4, "created=1700000000", "created=+1700000000"},
		{"leading-zero", 4, "created=1700000000", "created=01700000000"},
		{"negative-zero", 4, "created=1700000000", "created=-0"},
		{"fraction", 4, "created=1700000000", "created=1.1"},
		{"bool", 4, "created=1700000000", "created=true"},
		{"exponent", 4, "created=1700000000", "created=1e5"},
		{"huge-number", 4, "created=1700000000", "created=1000000000000000"},
		{"parameter-order", 4, ";created=1700000000;expires=1700000120", ";expires=1700000120;created=1700000000"},
		{"extra-parameter", 4, `;tag="appguard-request-v0"`, `;tag="appguard-request-v0";extra=1`},
		{"signature-bad-pad-bits", 5, "OK6w==", "OK6x=="},
		{"signature-joined", 5, ":", ":,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := append([]Header(nil), original...)
			headers[tc.field][1] = strings.Replace(headers[tc.field][1], tc.from, tc.to, 1)
			if _, _, err := ParseSignatures(headers); code(err) != "INVALID_REQUEST" {
				t.Fatal(err)
			}
		})
	}
	headers := append([]Header(nil), original...)
	headers[4][1] = strings.Replace(headers[4][1], "created=1700000000", "created=-1", 1)
	p, s, err := ParseSignatures(headers)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, o := baseline(t)
	if _, err = VerifyRequest(context.Background(), r, p, s, o); code(err) != "INVALID_TIME" {
		t.Fatal(err)
	}
}
func TestBodyCaptureTimeoutAndIncompleteStream(t *testing.T) {
	for _, tc := range []struct {
		name      string
		input     string
		halfClose bool
	}{
		{"timeout", "{", false}, {"incomplete", "{", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _, k := signed(t, "/test", []byte("{}"))
			o := httpConfig(k)
			o.BodyReadTimeout = 30 * time.Millisecond
			var called atomic.Bool
			addr := server(t, o, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			var b bytes.Buffer
			b.WriteString("POST /test HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: 2\r\n")
			for _, h := range r.Headers {
				b.WriteString(h[0] + ": " + h[1] + "\r\n")
			}
			b.WriteString("\r\n" + tc.input)
			_, _ = c.Write(b.Bytes())
			if tc.halfClose {
				_ = c.(*net.TCPConn).CloseWrite()
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			expectResponse(t, resp, 400, `{"code":"INVALID_REQUEST"}`)
			if called.Load() {
				t.Fatal("incomplete body processed")
			}
		})
	}
}
func TestHTTPChunkedValidAndCallbackMutationIsolation(t *testing.T) {
	r, _, _, k := signed(t, "/test?x=2&x=1", []byte("{}"))
	o := httpConfig(k)
	o.Authenticator = AuthenticatorFunc(func(_ context.Context, c AuthenticationContext) (string, error) {
		for i, h := range c.Headers {
			if strings.EqualFold(h[0], "content-type") {
				c.Headers[i][1] = "tampered"
			}
		}
		return "test-user", nil
	})
	o.KeyResolver = KeyResolverFunc(func(_ context.Context, c KeyContext) (*KeyRecord, error) {
		for _, h := range c.Headers {
			if strings.EqualFold(h[0], "content-type") && h[1] != "application/octet-stream" {
				t.Error("auth callback mutated verifier/key evidence")
			}
		}
		c.Headers[0][1] = "mutated by resolver"
		return k, nil
	})
	addr := server(t, o, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != "{}" {
			t.Error(string(b))
		}
		w.WriteHeader(204)
	}))
	expectResponse(t, rawSend(t, addr, r, []Header{{"Transfer-Encoding", "chunked"}}, []byte("2\r\n{}\r\n0\r\n\r\n")), 204, "")
}
func TestAuditAllowlistBoundsAndFailurePanic(t *testing.T) {
	fresh := int64(101)
	c := PolicyContext{Authentication: "authenticated", Verification: "verified", Attestation: "verified", AttestationExpires: &fresh}
	d, err := EvaluatePolicy(Policy{}, c, 100)
	if err != nil {
		t.Fatal(err)
	}
	record, err := AuditEvent(d, AuditOptions{EventID: "e", AppID: "a", Now: 100})
	if err != nil {
		t.Fatal(err)
	}
	line, _ := record.JSON()
	var event map[string]any
	if err = json.Unmarshal(line, &event); err != nil || len(event) != 7 {
		t.Fatal(string(line), err)
	}
	for _, o := range []AuditOptions{{EventID: "SECRET token", AppID: "a", Now: 100}, {EventID: "e", AppID: "a", Now: -1}, {EventID: "e", AppID: "a", Now: 100, Context: &PolicyContext{RiskSignals: []string{"bad signal"}}}} {
		if _, err := AuditEvent(d, o); code(err) != "INVALID_AUDIT_EVENT" {
			t.Fatal(err)
		}
	}
	sink, err := NewJSONAuditSink(func(context.Context, []byte) error { panic(errors.New("SECRET")) })
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.Emit(context.Background(), d, AuditOptions{EventID: "e", AppID: "a", Now: 100}); code(err) != "AUDIT_UNAVAILABLE" {
		t.Fatal(err)
	}
	if _, err := NewJSONAuditSink(nil); code(err) != "INVALID_AUDIT_EVENT" {
		t.Fatal(err)
	}
	if _, err := (AuditRecord{}).JSON(); code(err) != "INVALID_AUDIT_EVENT" {
		t.Fatal(err)
	}
}
