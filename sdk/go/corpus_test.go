package appguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

type requestVector struct {
	ID      string `json:"id"`
	Request struct {
		Method, Target string
		Headers        []Header
		BodyB64        string `json:"body_b64"`
	} `json:"request"`
	Parameters   Parameters `json:"parameters"`
	SignatureB64 string     `json:"signature_b64"`
	Key          KeyRecord  `json:"key"`
	Context      struct {
		Origin  string
		AppID   string `json:"app_id"`
		Subject string
		Now     int64
	}
	ReplayStore   string   `json:"replay_store"`
	ExpectedBase  *string  `json:"expected_signature_base"`
	ExpectedCodes []string `json:"expected_codes"`
}

func loadVectors[T any](t *testing.T, name string) []T {
	t.Helper()
	data, err := os.ReadFile("../../conformance/v0/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var result []T
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func code(err error) string {
	if err == nil {
		return "VERIFIED"
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}
func bytes64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func (v requestVector) request(t *testing.T) Request {
	return Request{Method: v.Request.Method, Target: v.Request.Target, Headers: v.Request.Headers, Body: bytes64(t, v.Request.BodyB64)}
}

type storeFunc func(context.Context, ReplayScope, int64, int64) (bool, error)

func (f storeFunc) Claim(c context.Context, s ReplayScope, e, n int64) (bool, error) {
	return f(c, s, e, n)
}
func TestRequestCorpus(t *testing.T) {
	vectors := loadVectors[requestVector](t, "requests")
	if len(vectors) != 40 {
		t.Fatal(len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			req := v.request(t)
			base, err := BuildSignatureBase(req, v.Parameters, v.Context.Origin)
			if v.ExpectedBase == nil {
				if err == nil {
					t.Fatal("expected base rejection")
				}
			} else if err != nil || string(base) != *v.ExpectedBase {
				t.Fatalf("base %s %v", base, err)
			}
			capacity := 10000
			if v.ReplayStore == "full" {
				capacity = 1
			}
			local, _ := NewLocalReplayStore(capacity)
			var store ReplayStore = local
			if v.ReplayStore == "full" {
				_, err = local.Claim(context.Background(), ReplayScope{"occupied", "occupied", "AAECAwQFBgcICQoLDA0ODw"}, maxTime, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			if v.ReplayStore == "unavailable" {
				store = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) {
					return false, errors.New("SECRET backend")
				})
			}
			for _, want := range v.ExpectedCodes {
				result, err := VerifyRequest(context.Background(), req, v.Parameters, bytes64(t, v.SignatureB64), VerifyOptions{Origin: v.Context.Origin, AppID: v.Context.AppID, Subject: v.Context.Subject, Key: &v.Key, Now: v.Context.Now, Replay: store})
				if code(err) != want {
					t.Fatalf("got %s want %s", code(err), want)
				}
				if err == nil && result.Code != "VERIFIED" {
					t.Fatal(result)
				}
			}
		})
	}
}
func TestHTTPCorpus(t *testing.T) {
	type row struct {
		ID           string
		Headers      []Header
		ExpectedCode string `json:"expected_code"`
		Expected     *struct {
			Parameters   Parameters
			SignatureB64 string `json:"signature_b64"`
		}
	}
	vectors := loadVectors[row](t, "http")
	if len(vectors) != 43 {
		t.Fatal(len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			p, s, err := ParseSignatures(v.Headers)
			if v.ExpectedCode != "PARSED" {
				if code(err) != v.ExpectedCode {
					t.Fatalf("got %s want %s", code(err), v.ExpectedCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p, v.Expected.Parameters) || base64.StdEncoding.EncodeToString(s) != v.Expected.SignatureB64 {
				t.Fatal("parse differs")
			}
		})
	}
}
func TestPolicyCorpus(t *testing.T) {
	type row struct {
		ID       string
		Policy   Policy
		Context  PolicyContext
		Now      int64
		Expected PolicyDecision
	}
	vectors := loadVectors[row](t, "policy")
	if len(vectors) != 42 {
		t.Fatal(len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			d, err := EvaluatePolicy(v.Policy, v.Context, v.Now)
			if err != nil {
				t.Fatal(err)
			}
			if d != v.Expected {
				t.Fatalf("%+v != %+v", d, v.Expected)
			}
		})
	}
}
