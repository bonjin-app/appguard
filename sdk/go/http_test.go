package appguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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
)

// A test-only ingestion boundary captures one HTTP/1 request before net/http
// parsing. It deliberately supports only test connections with Connection:close.
// It is not a production keep-alive/TLS/H2 raw-evidence implementation.
type captureConn struct {
	net.Conn
	once     sync.Once
	reader   io.Reader
	mu       sync.Mutex
	evidence *RawEvidence
}

func (c *captureConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		reader := bufio.NewReader(c.Conn)
		var raw bytes.Buffer
		var lines []string
		for raw.Len() <= 20000 {
			line, err := reader.ReadString('\n')
			raw.WriteString(line)
			if err != nil {
				break
			}
			if line == "\r\n" {
				break
			}
			lines = append(lines, strings.TrimSuffix(line, "\r\n"))
		}
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) == 3 {
				e := &RawEvidence{Method: parts[0], Target: parts[1]}
				for _, line := range lines[1:] {
					name, value, ok := strings.Cut(line, ":")
					if !ok {
						continue
					}
					value = strings.TrimPrefix(value, " ")
					e.Headers = append(e.Headers, Header{name, value})
				}
				c.mu.Lock()
				c.evidence = e
				c.mu.Unlock()
			}
		}
		c.reader = io.MultiReader(bytes.NewReader(raw.Bytes()), reader)
	})
	return c.reader.Read(p)
}

type captureListener struct{ net.Listener }

func (l captureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &captureConn{Conn: c}, nil
}

type connContextKey struct{}

func captured(_ context.Context, r *http.Request) (*RawEvidence, error) {
	c, ok := r.Context().Value(connContextKey{}).(*captureConn)
	if !ok {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.evidence == nil {
		return nil, nil
	}
	e := *c.evidence
	e.Headers = append([]Header(nil), e.Headers...)
	return &e, nil
}
func server(t *testing.T, config HTTPOptions, next http.Handler) string {
	t.Helper()
	handler, err := NewMiddleware(config, next)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: handler, ReadTimeout: time.Second, ReadHeaderTimeout: time.Second, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connContextKey{}, c)
	}}
	go func() { _ = s.Serve(captureListener{ln}) }()
	t.Cleanup(func() { _ = s.Close() })
	return ln.Addr().String()
}
func rawSend(t *testing.T, addr string, r Request, extra []Header, body []byte) *http.Response {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: ignored.example\r\nConnection: close\r\n", r.Method, r.Target)
	for _, h := range append(append([]Header(nil), r.Headers...), extra...) {
		fmt.Fprintf(c, "%s: %s\r\n", h[0], h[1])
	}
	fmt.Fprint(c, "\r\n")
	if body != nil {
		_, _ = c.Write(body)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}
func httpConfig(k *KeyRecord) HTTPOptions {
	s, _ := NewLocalReplayStore(100)
	return HTTPOptions{Origin: "https://api.example.test", AppID: "test-app", Replay: s, Evidence: captured, AllowInsecureTransport: true, Clock: func() int64 { return 100 }, Authenticator: AuthenticatorFunc(func(context.Context, AuthenticationContext) (string, error) { return "test-user", nil }), KeyResolver: KeyResolverFunc(func(context.Context, KeyContext) (*KeyRecord, error) { return k, nil })}
}
func expectResponse(t *testing.T, r *http.Response, status int, want string) {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != status || string(b) != want {
		t.Fatalf("HTTP %d %s expected %d %s", r.StatusCode, b, status, want)
	}
}
func TestHTTPPreservesRawTargetBodyAndAuthentication(t *testing.T) {
	for _, target := range []string{"/v1/a%2fb?x=2&x=1", "/empty?"} {
		t.Run(target, func(t *testing.T) {
			body := []byte{'a', 0, 'b', 255}
			r, _, _, key := signed(t, target, body)
			opts := httpConfig(key)
			type identityKey struct{}
			opts.Authenticator = AuthenticatorFunc(func(ctx context.Context, c AuthenticationContext) (string, error) {
				if ctx.Value(identityKey{}) != "existing-user" || c.Target != target {
					t.Error("identity/target changed")
				}
				return "test-user", nil
			})
			var calls atomic.Int32
			next := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				calls.Add(1)
				got, err := io.ReadAll(q.Body)
				if err != nil || !bytes.Equal(got, body) || q.RequestURI != target || q.Context().Value(identityKey{}) != "existing-user" {
					t.Error("downstream bytes/identity changed")
				}
				v, ok := VerificationFromContext(q.Context())
				if !ok || v.Code != "VERIFIED" {
					t.Error("no dedicated verification")
				}
				w.WriteHeader(204)
			})
			wrapped, err := NewMiddleware(opts, next)
			if err != nil {
				t.Fatal(err)
			}
			// Trusted application authentication state is installed before verification.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				wrapped.ServeHTTP(w, q.WithContext(context.WithValue(q.Context(), identityKey{}, "existing-user")))
			}), ReadTimeout: time.Second, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connContextKey{}, c)
			}}
			go func() { _ = s.Serve(captureListener{ln}) }()
			t.Cleanup(func() { _ = s.Close() })
			addr := ln.Addr().String()
			expectResponse(t, rawSend(t, addr, r, []Header{{"Content-Length", fmt.Sprint(len(body))}}, body), 204, "")
			expectResponse(t, rawSend(t, addr, r, []Header{{"Content-Length", fmt.Sprint(len(body))}}, body), 403, `{"code":"REPLAY_DETECTED"}`)
			if calls.Load() != 1 {
				t.Fatal(calls.Load())
			}
		})
	}
}
func TestHTTPFailureBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*HTTPOptions, *Request)
		extra  []Header
		body   func([]byte) []byte
		status int
		code   string
	}{
		{name: "missing-auth", change: func(o *HTTPOptions, _ *Request) {
			o.Authenticator = AuthenticatorFunc(func(context.Context, AuthenticationContext) (string, error) { return "", nil })
		}, status: 401, code: "AUTHENTICATION_REQUIRED"},
		{name: "auth-panic", change: func(o *HTTPOptions, _ *Request) {
			o.Authenticator = AuthenticatorFunc(func(context.Context, AuthenticationContext) (string, error) { panic("SECRET token") })
		}, status: 503, code: "IDENTITY_UNAVAILABLE"},
		{name: "key-panic", change: func(o *HTTPOptions, _ *Request) {
			o.KeyResolver = KeyResolverFunc(func(context.Context, KeyContext) (*KeyRecord, error) { panic("SECRET key") })
		}, status: 503, code: "KEY_RESOLVER_UNAVAILABLE"},
		{name: "source-panic", change: func(o *HTTPOptions, _ *Request) {
			o.Evidence = func(context.Context, *http.Request) (*RawEvidence, error) { panic("SECRET ingress") }
		}, status: 400, code: "INVALID_REQUEST"},
		{name: "clock-panic", change: func(o *HTTPOptions, _ *Request) { o.Clock = func() int64 { panic("SECRET clock") } }, status: 403, code: "INVALID_TIME"},
		{name: "store-panic", change: func(o *HTTPOptions, _ *Request) {
			o.Replay = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) { panic("SECRET store") })
		}, status: 503, code: "REPLAY_STORE_UNAVAILABLE"},
		{name: "auth-error", change: func(o *HTTPOptions, _ *Request) {
			o.Authenticator = AuthenticatorFunc(func(context.Context, AuthenticationContext) (string, error) { return "", errors.New("SECRET token") })
		}, status: 503, code: "IDENTITY_UNAVAILABLE"},
		{name: "auth-malformed", change: func(o *HTTPOptions, _ *Request) {
			o.Authenticator = AuthenticatorFunc(func(context.Context, AuthenticationContext) (string, error) { return "SECRET token", nil })
		}, status: 503, code: "IDENTITY_UNAVAILABLE"},
		{name: "unknown-key", change: func(o *HTTPOptions, _ *Request) {
			o.KeyResolver = KeyResolverFunc(func(context.Context, KeyContext) (*KeyRecord, error) { return nil, nil })
		}, status: 403, code: "KEY_REJECTED"},
		{name: "key-error", change: func(o *HTTPOptions, _ *Request) {
			o.KeyResolver = KeyResolverFunc(func(context.Context, KeyContext) (*KeyRecord, error) { return nil, errors.New("SECRET pem") })
		}, status: 503, code: "KEY_RESOLVER_UNAVAILABLE"},
		{name: "key-contract", change: func(o *HTTPOptions, _ *Request) {
			o.KeyResolver = KeyResolverFunc(func(context.Context, KeyContext) (*KeyRecord, error) { return &KeyRecord{}, nil })
		}, status: 503, code: "KEY_RESOLVER_UNAVAILABLE"},
		{name: "insecure-default", change: func(o *HTTPOptions, _ *Request) { o.AllowInsecureTransport = false }, extra: []Header{{"Forwarded", "proto=https"}, {"X-Forwarded-Proto", "https"}}, status: 400, code: "INVALID_REQUEST"},
		{name: "missing-evidence", change: func(o *HTTPOptions, _ *Request) {
			o.Evidence = func(context.Context, *http.Request) (*RawEvidence, error) { return nil, nil }
		}, status: 400, code: "INVALID_REQUEST"},
		{name: "rewritten-target", change: func(o *HTTPOptions, _ *Request) {
			o.Evidence = func(ctx context.Context, r *http.Request) (*RawEvidence, error) {
				e, _ := captured(ctx, r)
				e.Target = "/rewritten"
				return e, nil
			}
		}, status: 400, code: "INVALID_REQUEST"},
		{name: "raw-whitespace", extra: []Header{{"X-Pad", " trailing "}}, status: 400, code: "INVALID_REQUEST"},
		{name: "duplicate-auth", extra: []Header{{"authorization", "Bearer SECRET"}}, status: 400, code: "INVALID_REQUEST"},
		{name: "duplicate-unrelated-count", change: func(_ *HTTPOptions, r *Request) {
			for i := 0; i < 61; i++ {
				r.Headers = append(r.Headers, Header{"X-Pad", "v"})
			}
		}, status: 400, code: "INVALID_REQUEST"},
		{name: "body-tamper", body: func(_ []byte) []byte { return []byte("zz") }, status: 403, code: "DIGEST_MISMATCH"},
		{name: "clock-after-auth", change: func(o *HTTPOptions, _ *Request) {
			var done atomic.Bool
			o.Authenticator = AuthenticatorFunc(func(context.Context, AuthenticationContext) (string, error) {
				done.Store(true)
				return "test-user", nil
			})
			o.Clock = func() int64 {
				if !done.Load() {
					t.Error("clock read before auth")
				}
				return 120
			}
		}, status: 403, code: "INVALID_TIME"},
		{name: "store-error", change: func(o *HTTPOptions, _ *Request) {
			o.Replay = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) { return false, errors.New("SECRET") })
		}, status: 503, code: "REPLAY_STORE_UNAVAILABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("{}")
			r, _, _, k := signed(t, "/test?", body)
			o := httpConfig(k)
			var claimed atomic.Int32
			if tc.name != "store-error" && tc.name != "store-panic" {
				o.Replay = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) { claimed.Add(1); return true, nil })
			}
			if tc.change != nil {
				tc.change(&o, &r)
			}
			if tc.body != nil {
				body = tc.body(body)
			}
			var next atomic.Bool
			addr := server(t, o, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next.Store(true) }))
			extra := append(append([]Header(nil), tc.extra...), Header{"Content-Length", fmt.Sprint(len(body))})
			expectResponse(t, rawSend(t, addr, r, extra, body), tc.status, `{"code":"`+tc.code+`"}`)
			if next.Load() || claimed.Load() != 0 {
				t.Fatal("failure processed/claimed")
			}
		})
	}
}
func TestHTTPBoundedBodyAndFraming(t *testing.T) {
	r, _, _, k := signed(t, "/test", []byte("{}"))
	for _, tc := range []struct {
		name    string
		headers []Header
		body    []byte
		status  int
	}{
		{"length-overflow", []Header{{"Content-Length", "1048577"}}, nil, 413},
		{"chunked-overflow", []Header{{"Transfer-Encoding", "chunked"}}, append(append([]byte("100001\r\n"), bytes.Repeat([]byte("x"), 1048577)...), []byte("\r\n0\r\n\r\n")...), 413},
		{"chunked-length-conflict", []Header{{"Transfer-Encoding", "chunked"}, {"Content-Length", "2"}}, []byte("2\r\n{}\r\n0\r\n\r\n"), 400},
		{"noncanonical-length", []Header{{"Content-Length", "02"}}, []byte("{}"), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var next atomic.Bool
			addr := server(t, httpConfig(k), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next.Store(true) }))
			expectResponse(t, rawSend(t, addr, r, tc.headers, tc.body), tc.status, `{"code":"INVALID_REQUEST"}`)
			if next.Load() {
				t.Fatal("next called")
			}
		})
	}
}
func TestHTTPConfigurationAndMissingRawEvidence(t *testing.T) {
	r, _, _, k := signed(t, "/test", []byte("{}"))
	for _, mutate := range []func(*HTTPOptions){func(o *HTTPOptions) { o.Replay = nil }, func(o *HTTPOptions) { o.Authenticator = nil }, func(o *HTTPOptions) { o.KeyResolver = nil }, func(o *HTTPOptions) { o.Evidence = nil }, func(o *HTTPOptions) { o.Origin = "http://unsafe" }, func(o *HTTPOptions) { o.AppID = "" }} {
		o := httpConfig(k)
		mutate(&o)
		if _, err := NewMiddleware(o, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
			t.Fatal("missing dependency accepted")
		}
	}
	o := httpConfig(k)
	h, err := NewMiddleware(o, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("next called") }))
	if err != nil {
		t.Fatal(err)
	}
	q := httptest.NewRequest("POST", "https://api.example.test/test", bytes.NewReader([]byte("{}")))
	q.TLS = &tls.ConnectionState{}
	for _, v := range r.Headers {
		q.Header.Add(v[0], v[1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, q)
	expectResponse(t, w.Result(), 400, `{"code":"INVALID_REQUEST"}`)
}
