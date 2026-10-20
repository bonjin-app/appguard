package appguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// RawEvidence must originate at a trusted ingress before HTTP parsing/rewrites.
// net/http.Header is normalized and is not sufficient raw evidence. Headers must
// retain every occurrence, including Host, framing and unrelated fields.
type RawEvidence struct {
	Method  string
	Target  string
	Headers []Header
}
type EvidenceSource func(context.Context, *http.Request) (*RawEvidence, error)

// AuthenticationContext deliberately has no client subject or raw Request pointer.
// Validate the Bearer token against the application's existing authentication.
type AuthenticationContext struct {
	Method     string
	Target     string
	Headers    []Header
	Parameters Parameters
}
type KeyContext struct {
	AuthenticationContext
	AppID   string
	Subject string
	KeyID   string
}
type Authenticator interface {
	Authenticate(context.Context, AuthenticationContext) (string, error)
}
type AuthenticatorFunc func(context.Context, AuthenticationContext) (string, error)

func (f AuthenticatorFunc) Authenticate(ctx context.Context, c AuthenticationContext) (string, error) {
	return f(ctx, c)
}

type KeyResolver interface {
	ResolveKey(context.Context, KeyContext) (*KeyRecord, error)
}
type KeyResolverFunc func(context.Context, KeyContext) (*KeyRecord, error)

func (f KeyResolverFunc) ResolveKey(ctx context.Context, c KeyContext) (*KeyRecord, error) {
	return f(ctx, c)
}

// HTTPOptions requires all trust dependencies explicitly. AllowInsecureTransport
// is only for controlled local tests or explicitly enforced external TLS.
// BodyReadTimeout defaults to 30s and requires native read-deadline support.
type HTTPOptions struct {
	Origin                 string
	AppID                  string
	Replay                 ReplayStore
	Authenticator          Authenticator
	KeyResolver            KeyResolver
	Evidence               EvidenceSource
	Clock                  func() int64
	AllowInsecureTransport bool
	BodyReadTimeout        time.Duration
}
type verificationContextKey struct{}

func VerificationFromContext(ctx context.Context) (Verification, bool) {
	if ctx == nil {
		return Verification{}, false
	}
	v, ok := ctx.Value(verificationContextKey{}).(Verification)
	return v, ok
}

// NewMiddleware protects every request reaching it. Install first, before body
// parsing, routing/URI/header rewriting. Native HTTP/1.1 was tested; other
// transports require their own trusted evidence source and integration validation.
func NewMiddleware(o HTTPOptions, next http.Handler) (http.Handler, error) {
	if !validOrigin(o.Origin) || !identifierRE.MatchString(o.AppID) || nilInterface(o.Replay) || nilInterface(o.Authenticator) || nilInterface(o.KeyResolver) || o.Evidence == nil || nilInterface(next) || o.BodyReadTimeout < 0 {
		return nil, invalid()
	}
	if o.Clock == nil {
		o.Clock = func() int64 { return time.Now().Unix() }
	}
	if o.BodyReadTimeout == 0 {
		o.BodyReadTimeout = 30 * time.Second
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified, body, err := enforceHTTP(w, r, o)
		if err != nil {
			writeFailure(w, err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), verificationContextKey{}, verified))
		next.ServeHTTP(w, r)
	}), nil
}
func writeFailure(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = failure("VERIFICATION_UNAVAILABLE")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	w.WriteHeader(e.Status)
	_, _ = io.WriteString(w, `{"code":"`+e.Code+`"}`)
}
func enforceHTTP(w http.ResponseWriter, r *http.Request, o HTTPOptions) (result Verification, body []byte, err error) {
	defer func() {
		if recover() != nil {
			result = Verification{}
			body = nil
			err = failure("VERIFICATION_UNAVAILABLE")
		}
	}()
	if r == nil || r.Context().Err() != nil || (!o.AllowInsecureTransport && r.TLS == nil) || r.RequestURI == "" || r.Body == nil || r.Form != nil || r.PostForm != nil || r.MultipartForm != nil {
		return result, nil, invalid()
	}
	e, err := evidence(r.Context(), o.Evidence, r)
	if err != nil || e == nil || e.Method != r.Method || e.Target != r.RequestURI {
		return result, nil, invalid()
	}
	headers := append([]Header(nil), e.Headers...)
	p, sig, err := ParseSignatures(headers)
	if err != nil {
		return result, nil, err
	}
	req := Request{Method: r.Method, Target: r.RequestURI, Headers: headers}
	if _, err = validateRequest(req); err != nil {
		return result, nil, err
	}
	if !matchesNativeHeaders(r, headers) {
		return result, nil, invalid()
	}
	controller := http.NewResponseController(w)
	if err = controller.SetReadDeadline(time.Now().Add(o.BodyReadTimeout)); err != nil {
		return result, nil, failure("VERIFICATION_UNAVAILABLE")
	}
	body, err = io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	_ = controller.SetReadDeadline(time.Time{})
	if err != nil || r.Context().Err() != nil {
		return result, nil, invalid()
	}
	if len(body) > MaxBodyBytes {
		return result, nil, &Error{Code: "INVALID_REQUEST", Status: 413}
	}
	n := len(body)
	if _, err = ValidateFraming(headers, &n); err != nil {
		return result, nil, err
	}
	req.Body = body
	authContext := AuthenticationContext{Method: req.Method, Target: req.Target, Headers: append([]Header(nil), headers...), Parameters: p}
	subject, err := authenticate(r.Context(), o.Authenticator, authContext)
	if err != nil {
		return result, nil, failure("IDENTITY_UNAVAILABLE")
	}
	if subject == "" {
		return result, nil, failure("AUTHENTICATION_REQUIRED")
	}
	if !identifierRE.MatchString(subject) {
		return result, nil, failure("IDENTITY_UNAVAILABLE")
	}
	authContext.Headers = append([]Header(nil), headers...)
	key, err := resolveKey(r.Context(), o.KeyResolver, KeyContext{AuthenticationContext: authContext, AppID: o.AppID, Subject: subject, KeyID: p.KeyID})
	if err != nil {
		return result, nil, failure("KEY_RESOLVER_UNAVAILABLE")
	}
	if key != nil {
		if key.AppID == "" || key.KeyID == "" || key.Subject == "" || key.Algorithm == "" || key.PublicKeyPEM == "" {
			return result, nil, failure("KEY_RESOLVER_UNAVAILABLE")
		}
		copy := *key
		key = &copy
	}
	now, err := trustedNow(o.Clock)
	if err != nil {
		return result, nil, failure("INVALID_TIME")
	}
	result, err = VerifyRequest(r.Context(), req, p, sig, VerifyOptions{Origin: o.Origin, AppID: o.AppID, Subject: subject, Key: key, Now: now, Replay: o.Replay})
	return result, body, err
}
func evidence(ctx context.Context, f EvidenceSource, r *http.Request) (e *RawEvidence, err error) {
	defer func() {
		if recover() != nil {
			e = nil
			err = invalid()
		}
	}()
	return f(ctx, r)
}
func authenticate(ctx context.Context, f Authenticator, c AuthenticationContext) (subject string, err error) {
	defer func() {
		if recover() != nil {
			subject = ""
			err = failure("IDENTITY_UNAVAILABLE")
		}
	}()
	return f.Authenticate(ctx, c)
}
func resolveKey(ctx context.Context, f KeyResolver, c KeyContext) (key *KeyRecord, err error) {
	defer func() {
		if recover() != nil {
			key = nil
			err = failure("KEY_RESOLVER_UNAVAILABLE")
		}
	}()
	return f.ResolveKey(ctx, c)
}
func trustedNow(clock func() int64) (now int64, err error) {
	defer func() {
		if recover() != nil {
			err = failure("INVALID_TIME")
		}
	}()
	return clock(), nil
}

// Cross-check observable native fields against the trusted original snapshot.
// Framing removed by net/http is checked through its dedicated request fields.
func matchesNativeHeaders(r *http.Request, raw []Header) bool {
	want := map[string][]string{}
	host := ""
	te := ""
	length := ""
	for _, h := range raw {
		name := strings.ToLower(h[0])
		switch name {
		case "host":
			host = h[1]
		case "transfer-encoding":
			te = h[1]
		case "content-length":
			length = h[1]
			want[name] = append(want[name], h[1])
		case "trailer":
			return false
		default:
			want[name] = append(want[name], h[1])
		}
	}
	got := map[string][]string{}
	for name, values := range r.Header {
		got[strings.ToLower(name)] = values
	}
	if !reflect.DeepEqual(want, got) || host != r.Host || len(r.Trailer) != 0 {
		return false
	}
	if te == "chunked" {
		if !reflect.DeepEqual(r.TransferEncoding, []string{"chunked"}) || r.ContentLength != -1 {
			return false
		}
	} else if len(r.TransferEncoding) != 0 {
		return false
	}
	if length != "" {
		n, err := strconv.ParseInt(length, 10, 64)
		if err != nil || r.ContentLength != n {
			return false
		}
	}
	return true
}
