// Command verify-fixture is a test-only public-API interoperability probe.
// It accepts public conformance-shaped request fixtures, never private keys.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	appguard "github.com/bonjin-app/appguard/sdk/go"
)

var rejected = errors.New("APPGUARD_FIXTURE_REJECTED")

type fixtureInput struct {
	Request struct {
		Method  string            `json:"method"`
		Target  string            `json:"target"`
		Headers []appguard.Header `json:"headers"`
		BodyB64 string            `json:"body_b64"`
	} `json:"request"`
	Parameters   appguard.Parameters `json:"parameters"`
	SignatureB64 string              `json:"signature_b64"`
	Key          appguard.KeyRecord  `json:"key"`
	Context      struct {
		Origin  string `json:"origin"`
		AppID   string `json:"app_id"`
		Subject string `json:"subject"`
		Now     int64  `json:"now"`
	} `json:"context"`
}

func decode64(value string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(b) != value {
		return nil, rejected
	}
	return b, nil
}
func verifyFixture(v fixtureInput) error {
	body, err := decode64(v.Request.BodyB64)
	if err != nil {
		return rejected
	}
	signature, err := decode64(v.SignatureB64)
	if err != nil {
		return rejected
	}
	n := len(body)
	if _, err = appguard.ValidateFraming(v.Request.Headers, &n); err != nil {
		return rejected
	}
	p, sig, err := appguard.ParseSignatures(v.Request.Headers)
	if err != nil || p != v.Parameters || !bytes.Equal(sig, signature) {
		return rejected
	}
	req := appguard.Request{Method: v.Request.Method, Target: v.Request.Target, Headers: append([]appguard.Header(nil), v.Request.Headers...), Body: body}
	fresh := func() (appguard.VerifyOptions, error) {
		store, err := appguard.NewLocalReplayStore(8)
		return appguard.VerifyOptions{Origin: v.Context.Origin, AppID: v.Context.AppID, Subject: v.Context.Subject, Key: &v.Key, Now: v.Context.Now, Replay: store}, err
	}
	o, err := fresh()
	if err != nil {
		return rejected
	}
	result, err := appguard.VerifyRequest(context.Background(), req, p, sig, o)
	if err != nil || result.Code != "VERIFIED" || result.AppID != v.Context.AppID || result.KeyID != p.KeyID || result.Expires != p.Expires {
		return rejected
	}
	_, err = appguard.VerifyRequest(context.Background(), req, p, sig, o)
	var failure *appguard.Error
	if !errors.As(err, &failure) || failure.Code != "REPLAY_DETECTED" {
		return rejected
	}
	for mutation := 0; mutation < 3; mutation++ {
		changed := req
		changed.Headers = append([]appguard.Header(nil), req.Headers...)
		switch mutation {
		case 0:
			changed.Body = append(append([]byte(nil), req.Body...), '!')
		case 1:
			changed.Target = "/appguard-mutated-target"
			if changed.Target == req.Target {
				changed.Target += "/changed"
			}
		case 2:
			for i, h := range changed.Headers {
				if strings.EqualFold(h[0], "authorization") {
					changed.Headers[i][1] = "Bearer APPGUARD_MUTATED_TEST_TOKEN"
					if changed.Headers[i][1] == h[1] {
						changed.Headers[i][1] = "Bearer APPGUARD_OTHER_MUTATED_TOKEN"
					}
				}
			}
		}
		if reflect.DeepEqual(changed, req) {
			return rejected
		}
		freshOptions, err := fresh()
		if err != nil {
			return rejected
		}
		if _, err = appguard.VerifyRequest(context.Background(), changed, p, sig, freshOptions); err == nil {
			return rejected
		}
	}
	return nil
}
func run(reader io.Reader, writer io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(reader, 2097153))
	if err != nil || len(raw) > 2097152 {
		return rejected
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return rejected
	}
	var rows []json.RawMessage
	if raw[0] == '[' {
		if json.Unmarshal(raw, &rows) != nil {
			return rejected
		}
	} else {
		rows = []json.RawMessage{raw}
	}
	if len(rows) < 1 || len(rows) > 100 {
		return rejected
	}
	for _, row := range rows {
		var v fixtureInput
		if json.Unmarshal(row, &v) != nil || verifyFixture(v) != nil {
			return rejected
		}
		if _, err = fmt.Fprintln(writer, "GO_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED"); err != nil {
			return rejected
		}
	}
	return nil
}
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, rejected)
		os.Exit(1)
	}
	for _, path := range os.Args[1:] {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, rejected)
			os.Exit(1)
		}
		err = run(f, os.Stdout)
		_ = f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, rejected)
			os.Exit(1)
		}
	}
}
