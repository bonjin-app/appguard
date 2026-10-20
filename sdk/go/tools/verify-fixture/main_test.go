package main

import (
	"bytes"
	"encoding/json"
	appguard "github.com/bonjin-app/appguard/sdk/go"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../../../conformance/v0/requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	v := rows[0]
	var p appguard.Parameters
	b, _ := json.Marshal(v["parameters"])
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	r := v["request"].(map[string]any)
	r["headers"] = append(r["headers"].([]any), []string{"Signature-Input", "appguard=" + appguard.SerializeParameters(p)}, []string{"Signature", "appguard=:" + v["signature_b64"].(string) + ":"})
	return v
}
func TestRunAcceptsObjectAndArrayAndAssertsMutations(t *testing.T) {
	for _, array := range []bool{false, true} {
		v := fixture(t)
		var input any = v
		if array {
			input = []any{v, v}
		}
		raw, _ := json.Marshal(input)
		var out bytes.Buffer
		if err := run(bytes.NewReader(raw), &out); err != nil {
			t.Fatal(err)
		}
		want := 1
		if array {
			want = 2
		}
		if strings.Count(out.String(), "GO_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED") != want {
			t.Fatal(out.String())
		}
	}
}
func TestRunRejectsMalformedAndTamperedFixtures(t *testing.T) {
	for _, raw := range []string{"null", "[]", "{}", "true", "[{}]", strings.Repeat(" ", 2097153), "{} {}"} {
		var out bytes.Buffer
		if err := run(strings.NewReader(raw), &out); err == nil {
			t.Fatalf("accepted malformed input length %d", len(raw))
		}
	}
	for _, field := range []string{"body_b64", "target"} {
		v := fixture(t)
		r := v["request"].(map[string]any)
		if field == "body_b64" {
			r[field] = "IQ=="
		} else {
			r[field] = "/changed"
		}
		raw, _ := json.Marshal(v)
		var out bytes.Buffer
		if err := run(bytes.NewReader(raw), &out); err == nil || out.Len() != 0 {
			t.Fatal("tamper accepted")
		}
	}
	v := fixture(t)
	v["key"].(map[string]any)["public_key_pem"] = "-----BEGIN PRIVATE KEY-----SECRET"
	raw, _ := json.Marshal(v)
	var out bytes.Buffer
	if err := run(bytes.NewReader(raw), &out); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("private key accepted/exposed")
	}
}

func TestRunChecksWireFramingAgainstContent(t *testing.T) {
	v := fixture(t)
	r := v["request"].(map[string]any)
	r["headers"] = append(r["headers"].([]any), []string{"Content-Length", "3"})
	raw, _ := json.Marshal(v)
	if err := run(bytes.NewReader(raw), &bytes.Buffer{}); err == nil {
		t.Fatal("wire Content-Length mismatch accepted")
	}
	v = fixture(t)
	values := make([]any, 101)
	for i := range values {
		values[i] = v
	}
	raw, _ = json.Marshal(values)
	if err := run(bytes.NewReader(raw), &bytes.Buffer{}); err == nil {
		t.Fatal("unbounded fixture count accepted")
	}
}
