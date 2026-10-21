package appguard_test

import (
	"bufio"
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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ag "github.com/bonjin-app/appguard/sdk/go"
)

type cancelGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func newCancelGate() *cancelGate {
	return &cancelGate{entered: make(chan struct{}), release: make(chan struct{})}
}
func (g *cancelGate) wait()   { close(g.entered); <-g.release }
func (g *cancelGate) finish() { g.once.Do(func() { close(g.release) }) }
func waitCancelTest(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("test synchronization timed out")
	}
}

type cancelStore func(context.Context, ag.ReplayScope, int64, int64) (bool, error)

func (s cancelStore) Claim(c context.Context, scope ag.ReplayScope, e, n int64) (bool, error) {
	return s(c, scope, e, n)
}

type cancelCounts struct{ evidence, reads, auth, key, clock, replay, next atomic.Int32 }
type cancelWriter struct{ *httptest.ResponseRecorder }

func (*cancelWriter) SetReadDeadline(time.Time) error { return nil }

type cancelBody struct {
	io.ReadCloser
	calls *atomic.Int32
	eof   *cancelGate
}

func (b *cancelBody) Read(p []byte) (int, error) {
	b.calls.Add(1)
	n, e := b.ReadCloser.Read(p)
	if e == io.EOF && b.eof != nil {
		b.eof.wait()
	}
	return n, e
}

// Independently signed, public-API-only fixture also runs from a downloaded module.
func cancelFixture(t *testing.T) (*http.Request, *ag.RawEvidence, *ag.KeyRecord) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	body := []byte("{}")
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	target := "/cancel?x=2&x=1"
	params := `("@method" "@target-uri" "content-type" "content-digest" "authorization" "appguard-app-id");created=100;expires=120;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="test-key";alg="ecdsa-p256-sha256";tag="appguard-request-v0"`
	base := fmt.Sprintf("\"@method\": POST\n\"@target-uri\": https://api.example.test%s\n\"content-type\": application/octet-stream\n\"content-digest\": %s\n\"authorization\": Bearer TEST_ONLY_TOKEN\n\"appguard-app-id\": test-app\n\"@signature-params\": %s", target, digest, params)
	hash := sha256.Sum256([]byte(base))
	a, b, e := ecdsa.Sign(rand.Reader, key, hash[:])
	if e != nil {
		t.Fatal(e)
	}
	sig := append(a.FillBytes(make([]byte, 32)), b.FillBytes(make([]byte, 32))...)
	headers := []ag.Header{{"Content-Type", "application/octet-stream"}, {"Content-Digest", digest}, {"Authorization", "Bearer TEST_ONLY_TOKEN"}, {"AppGuard-App-Id", "test-app"}, {"Signature-Input", "appguard=" + params}, {"Signature", "appguard=:" + base64.StdEncoding.EncodeToString(sig) + ":"}, {"Host", "ignored.example"}, {"Content-Length", "2"}}
	r, e := http.NewRequest("POST", "http://ignored.example"+target, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.RequestURI = target
	for _, v := range headers {
		if v[0] != "Host" {
			r.Header.Add(v[0], v[1])
		}
	}
	der, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return r, &ag.RawEvidence{Method: "POST", Target: target, Headers: headers}, &ag.KeyRecord{AppID: "test-app", KeyID: "test-key", Subject: "test-user", Algorithm: ag.Algorithm, PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}
func cancelOptions(raw *ag.RawEvidence, key *ag.KeyRecord, c *cancelCounts) ag.HTTPOptions {
	return ag.HTTPOptions{AppID: "test-app", Origin: "https://api.example.test", AllowInsecureTransport: true,
		Evidence: func(context.Context, *http.Request) (*ag.RawEvidence, error) { c.evidence.Add(1); return raw, nil },
		Authenticator: ag.AuthenticatorFunc(func(context.Context, ag.AuthenticationContext) (string, error) {
			c.auth.Add(1)
			return "test-user", nil
		}),
		KeyResolver: ag.KeyResolverFunc(func(context.Context, ag.KeyContext) (*ag.KeyRecord, error) { c.key.Add(1); return key, nil }),
		Clock:       func() int64 { c.clock.Add(1); return 100 }, Replay: cancelStore(func(context.Context, ag.ReplayScope, int64, int64) (bool, error) { c.replay.Add(1); return true, nil })}
}
func cancelHandler(t *testing.T, o ag.HTTPOptions, c *cancelCounts) http.Handler {
	t.Helper()
	h, e := ag.NewMiddleware(o, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.next.Add(1); w.WriteHeader(204) }))
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func cancelResponse(t *testing.T, w *cancelWriter, status int, code string) {
	t.Helper()
	want := `{"code":"` + code + `"}`
	if w.Code != status || w.Body.String() != want {
		t.Fatalf("got HTTP%d %s; want HTTP%d %s", w.Code, w.Body.String(), status, want)
	}
}
func runCancelBlocked(t *testing.T, h http.Handler, r *http.Request, w http.ResponseWriter, g *cancelGate, cancel func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(w, r) }()
	defer func() { g.finish(); waitCancelTest(t, done) }()
	waitCancelTest(t, g.entered)
	cancel()
	g.finish()
	waitCancelTest(t, done)
}

func TestHTTPCancellationHandoffs(t *testing.T) {
	for _, phase := range []string{"entry", "evidence", "body", "identity", "key", "clock", "replay"} {
		t.Run(phase, func(t *testing.T) {
			r, raw, key := cancelFixture(t)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			r = r.WithContext(ctx)
			c := &cancelCounts{}
			o := cancelOptions(raw, key, c)
			g := newCancelGate()
			r.Body = &cancelBody{ReadCloser: r.Body, calls: &c.reads}
			switch phase {
			case "evidence":
				o.Evidence = func(got context.Context, _ *http.Request) (*ag.RawEvidence, error) {
					c.evidence.Add(1)
					if got != ctx {
						t.Error("lost original context")
					}
					g.wait()
					return raw, nil
				}
			case "body":
				r.Body.(*cancelBody).eof = g
			case "identity":
				o.Authenticator = ag.AuthenticatorFunc(func(got context.Context, _ ag.AuthenticationContext) (string, error) {
					c.auth.Add(1)
					if got != ctx {
						t.Error("lost original context")
					}
					g.wait()
					return "test-user", nil
				})
			case "key":
				o.KeyResolver = ag.KeyResolverFunc(func(got context.Context, _ ag.KeyContext) (*ag.KeyRecord, error) {
					c.key.Add(1)
					if got != ctx {
						t.Error("lost original context")
					}
					g.wait()
					return key, nil
				})
			case "clock":
				o.Clock = func() int64 { c.clock.Add(1); g.wait(); return 100 }
			case "replay":
				o.Replay = cancelStore(func(got context.Context, _ ag.ReplayScope, _, _ int64) (bool, error) {
					c.replay.Add(1)
					if got != ctx {
						t.Error("lost original context")
					}
					g.wait()
					return true, nil
				})
			}
			w := &cancelWriter{ResponseRecorder: httptest.NewRecorder()}
			h := cancelHandler(t, o, c)
			if phase == "entry" {
				cancel(errors.New("PRIVATE CAUSE"))
				h.ServeHTTP(w, r)
			} else {
				runCancelBlocked(t, h, r, w, g, func() { cancel(errors.New("PRIVATE CAUSE")) })
			}
			status, code := 400, "INVALID_REQUEST"
			switch phase {
			case "identity":
				status, code = 503, "IDENTITY_UNAVAILABLE"
			case "key":
				status, code = 503, "KEY_RESOLVER_UNAVAILABLE"
			case "clock":
				status, code = 503, "VERIFICATION_UNAVAILABLE"
			case "replay":
				status, code = 503, "REPLAY_STORE_UNAVAILABLE"
			}
			cancelResponse(t, w, status, code)
			wantAuth, wantKey, wantClock, wantReplay := int32(0), int32(0), int32(0), int32(0)
			switch phase {
			case "identity":
				wantAuth = 1
			case "key":
				wantAuth, wantKey = 1, 1
			case "clock":
				wantAuth, wantKey, wantClock = 1, 1, 1
			case "replay":
				wantAuth, wantKey, wantClock, wantReplay = 1, 1, 1, 1
			}
			if c.auth.Load() != wantAuth || c.key.Load() != wantKey || c.clock.Load() != wantClock || c.replay.Load() != wantReplay || c.next.Load() != 0 {
				t.Fatalf("unexpected work auth%d key%d clock%d replay%d next%d", c.auth.Load(), c.key.Load(), c.clock.Load(), c.replay.Load(), c.next.Load())
			}
			if (phase == "evidence" || phase == "entry") && c.reads.Load() != 0 {
				t.Fatal("body read after cancellation")
			}
		})
	}
}
func TestHTTPCancellationContextReplacement(t *testing.T) {
	for _, phase := range []string{"evidence", "identity", "key"} {
		t.Run(phase, func(t *testing.T) {
			r, raw, key := cancelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r = r.WithContext(ctx)
			c := &cancelCounts{}
			o := cancelOptions(raw, key, c)
			g := newCancelGate()
			replace := func() { *r = *r.WithContext(context.Background()); g.wait() }
			switch phase {
			case "evidence":
				o.Evidence = func(context.Context, *http.Request) (*ag.RawEvidence, error) {
					c.evidence.Add(1)
					replace()
					return raw, nil
				}
			case "identity":
				o.Authenticator = ag.AuthenticatorFunc(func(context.Context, ag.AuthenticationContext) (string, error) {
					c.auth.Add(1)
					replace()
					return "test-user", nil
				})
			case "key":
				o.KeyResolver = ag.KeyResolverFunc(func(context.Context, ag.KeyContext) (*ag.KeyRecord, error) { c.key.Add(1); replace(); return key, nil })
			}
			w := &cancelWriter{ResponseRecorder: httptest.NewRecorder()}
			runCancelBlocked(t, cancelHandler(t, o, c), r, w, g, cancel)
			status, code := 400, "INVALID_REQUEST"
			if phase == "identity" {
				status, code = 503, "IDENTITY_UNAVAILABLE"
			}
			if phase == "key" {
				status, code = 503, "KEY_RESOLVER_UNAVAILABLE"
			}
			cancelResponse(t, w, status, code)
			if c.next.Load() != 0 || c.replay.Load() != 0 || c.clock.Load() != 0 {
				t.Fatal("canceled original scope reached later work")
			}
		})
	}
}
func TestHTTPCancellationCallbackFailurePrivacy(t *testing.T) {
	for _, phase := range []string{"identity", "key"} {
		for _, kind := range []string{"error", "panic"} {
			t.Run(phase+"/"+kind, func(t *testing.T) {
				r, raw, key := cancelFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				r = r.WithContext(ctx)
				c := &cancelCounts{}
				o := cancelOptions(raw, key, c)
				g := newCancelGate()
				fail := func() error {
					g.wait()
					if kind == "panic" {
						panic("PRIVATE PANIC")
					}
					return errors.New("PRIVATE CALLBACK")
				}
				code := "IDENTITY_UNAVAILABLE"
				if phase == "identity" {
					o.Authenticator = ag.AuthenticatorFunc(func(context.Context, ag.AuthenticationContext) (string, error) { return "", fail() })
				} else {
					code = "KEY_RESOLVER_UNAVAILABLE"
					o.KeyResolver = ag.KeyResolverFunc(func(context.Context, ag.KeyContext) (*ag.KeyRecord, error) { return nil, fail() })
				}
				w := &cancelWriter{ResponseRecorder: httptest.NewRecorder()}
				runCancelBlocked(t, cancelHandler(t, o, c), r, w, g, cancel)
				cancelResponse(t, w, 503, code)
				if c.clock.Load() != 0 || c.replay.Load() != 0 || c.next.Load() != 0 {
					t.Fatal("failed callback advanced request")
				}
			})
		}
	}
}

type cancellationHostKey struct{}

func TestHTTPCancellationHealthyScopeAndBody(t *testing.T) {
	r, raw, key := cancelFixture(t)
	ctx := context.WithValue(r.Context(), cancellationHostKey{}, "existing-identity")
	r = r.WithContext(ctx)
	c := &cancelCounts{}
	o := cancelOptions(raw, key, c)
	h, e := ag.NewMiddleware(o, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.next.Add(1)
		body, e := io.ReadAll(r.Body)
		proof, ok := ag.VerificationFromContext(r.Context())
		if e != nil || string(body) != "{}" || !ok || proof.Code != "VERIFIED" || r.Context().Value(cancellationHostKey{}) != "existing-identity" {
			t.Error("healthy body/context/proof changed")
		}
		w.WriteHeader(204)
	}))
	if e != nil {
		t.Fatal(e)
	}
	w := &cancelWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	if w.Code != 204 || c.next.Load() != 1 || c.replay.Load() != 1 {
		t.Fatal("healthy request did not dispatch once")
	}
}
func TestHTTPCancellationIndependentRequests(t *testing.T) {
	r, raw, key := cancelFixture(t)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), cancellationHostKey{}, true))
	defer cancel()
	blocked := r.Clone(ctx)
	blocked.Body = io.NopCloser(strings.NewReader("{}"))
	healthy := r.Clone(context.Background())
	healthy.Body = io.NopCloser(strings.NewReader("{}"))
	c := &cancelCounts{}
	o := cancelOptions(raw, key, c)
	g := newCancelGate()
	o.Authenticator = ag.AuthenticatorFunc(func(ctx context.Context, _ ag.AuthenticationContext) (string, error) {
		c.auth.Add(1)
		if ctx.Value(cancellationHostKey{}) == true {
			g.wait()
		}
		return "test-user", nil
	})
	h := cancelHandler(t, o, c)
	bad := &cancelWriter{ResponseRecorder: httptest.NewRecorder()}
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(bad, blocked) }()
	defer func() { g.finish(); waitCancelTest(t, done) }()
	waitCancelTest(t, g.entered)
	cancel()
	good := &cancelWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(good, healthy)
	g.finish()
	waitCancelTest(t, done)
	if good.Code != 204 || c.next.Load() != 1 || c.key.Load() != 1 || c.replay.Load() != 1 {
		t.Fatalf("isolation failed: healthy HTTP%d next%d key%d replay%d", good.Code, c.next.Load(), c.key.Load(), c.replay.Load())
	}
	cancelResponse(t, bad, 503, "IDENTITY_UNAVAILABLE")
}

// Test-only single-request HTTP/1 pre-parser capture, never a production collector.
type cancelConn struct {
	net.Conn
	once   sync.Once
	reader io.Reader
	mu     sync.Mutex
	raw    *ag.RawEvidence
}

func (c *cancelConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		reader := bufio.NewReader(c.Conn)
		var prefix bytes.Buffer
		var lines []string
		for prefix.Len() <= 20000 {
			line, e := reader.ReadString('\n')
			prefix.WriteString(line)
			if e != nil || line == "\r\n" {
				break
			}
			lines = append(lines, strings.TrimSuffix(line, "\r\n"))
		}
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) == 3 {
				raw := &ag.RawEvidence{Method: parts[0], Target: parts[1]}
				for _, line := range lines[1:] {
					name, value, ok := strings.Cut(line, ":")
					if ok {
						raw.Headers = append(raw.Headers, ag.Header{name, strings.TrimPrefix(value, " ")})
					}
				}
				c.mu.Lock()
				c.raw = raw
				c.mu.Unlock()
			}
		}
		c.reader = io.MultiReader(bytes.NewReader(prefix.Bytes()), reader)
	})
	return c.reader.Read(p)
}

type cancelListener struct{ net.Listener }

func (l cancelListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &cancelConn{Conn: c}, nil
}

type cancelConnKey struct{}

func TestHTTPCancellationActualDisconnect(t *testing.T) {
	for _, phase := range []string{"identity", "key"} {
		t.Run(phase, func(t *testing.T) {
			request, _, key := cancelFixture(t)
			c := &cancelCounts{}
			o := cancelOptions(nil, key, c)
			g := newCancelGate()
			seen := make(chan context.Context, 1)
			o.Evidence = func(ctx context.Context, _ *http.Request) (*ag.RawEvidence, error) {
				conn := ctx.Value(cancelConnKey{}).(*cancelConn)
				conn.mu.Lock()
				defer conn.mu.Unlock()
				raw := *conn.raw
				raw.Headers = append([]ag.Header(nil), raw.Headers...)
				return &raw, nil
			}
			if phase == "identity" {
				o.Authenticator = ag.AuthenticatorFunc(func(ctx context.Context, _ ag.AuthenticationContext) (string, error) {
					c.auth.Add(1)
					seen <- ctx
					g.wait()
					return "test-user", nil
				})
			} else {
				o.KeyResolver = ag.KeyResolverFunc(func(ctx context.Context, _ ag.KeyContext) (*ag.KeyRecord, error) {
					c.key.Add(1)
					seen <- ctx
					g.wait()
					return key, nil
				})
			}
			h := cancelHandler(t, o, c)
			finished := make(chan struct{})
			s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); h.ServeHTTP(w, r) }), ReadHeaderTimeout: time.Second, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
				return context.WithValue(ctx, cancelConnKey{}, conn)
			}}
			ln, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			go func() { _ = s.Serve(cancelListener{ln}) }()
			defer s.Close()
			defer g.finish()
			conn, e := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var wire bytes.Buffer
			fmt.Fprintf(&wire, "POST %s HTTP/1.1\r\nHost: ignored.example\r\n", request.RequestURI)
			for name, values := range request.Header {
				for _, v := range values {
					fmt.Fprintf(&wire, "%s: %s\r\n", name, v)
				}
			}
			wire.WriteString("\r\n{}")
			if _, e = conn.Write(wire.Bytes()); e != nil {
				t.Fatal(e)
			}
			var ctx context.Context
			select {
			case ctx = <-seen:
			case <-time.After(5 * time.Second):
				t.Fatal("server callback not reached")
			}
			waitCancelTest(t, g.entered)
			if e = conn.(*net.TCPConn).SetLinger(0); e != nil {
				t.Fatal(e)
			}
			_ = conn.Close()
			waitCancelTest(t, ctx.Done())
			g.finish()
			waitCancelTest(t, finished)
			wantKey := int32(0)
			if phase == "key" {
				wantKey = 1
			}
			if c.key.Load() != wantKey || c.clock.Load() != 0 || c.replay.Load() != 0 || c.next.Load() != 0 {
				t.Fatalf("work after observed disconnect key%d clock%d replay%d next%d", c.key.Load(), c.clock.Load(), c.replay.Load(), c.next.Load())
			}
		})
	}
}
