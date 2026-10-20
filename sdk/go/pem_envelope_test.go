package appguard

import (
	"context"
	"strings"
	"testing"
)

func TestSinglePublicKeyEnvelopeBeforeReplay(t *testing.T) {
	_, _, _, original := baseline(t)
	pemText := original.Key.PublicKeyPEM
	cases := []struct {
		name, text string
		valid      bool
	}{
		{"lf", pemText, true},
		{"crlf", strings.ReplaceAll(pemText, "\n", "\r\n"), true},
		{"trailing-ascii-space", pemText + " \t\r\n", true},
		{"malformed-first-block", "-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n" + pemText, false},
		{"unclosed-first-block", "-----BEGIN PUBLIC KEY-----\nnot-base64\n" + pemText, false},
		{"nested-valid-block", "-----BEGIN PUBLIC KEY-----\n" + pemText + "-----END PUBLIC KEY-----\n", false},
		{"duplicate-block", pemText + pemText, false},
		{"junk-prefix", "not-a-key\n" + pemText, false},
		{"junk-suffix", pemText + "not-a-key", false},
		{"legacy-headers", strings.Replace(pemText, "-----BEGIN PUBLIC KEY-----\n", "-----BEGIN PUBLIC KEY-----\nProc-Type: 4,ENCRYPTED\n\n", 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p, s, o := baseline(t)
			store, _ := NewLocalReplayStore(10)
			claims := 0
			o.Replay = storeFunc(func(ctx context.Context, scope ReplayScope, expires, now int64) (bool, error) {
				claims++
				return store.Claim(ctx, scope, expires, now)
			})
			o.Key.PublicKeyPEM = tc.text
			_, err := VerifyRequest(context.Background(), r, p, s, o)
			if tc.valid {
				if code(err) != "VERIFIED" || claims != 1 {
					t.Fatalf("valid envelope: code=%s claims=%d", code(err), claims)
				}
			} else {
				if code(err) != "KEY_REJECTED" || claims != 0 {
					t.Fatalf("ambiguous envelope: code=%s claims=%d", code(err), claims)
				}
				o.Key.PublicKeyPEM = pemText
				if _, err = VerifyRequest(context.Background(), r, p, s, o); err != nil {
					t.Fatalf("original rejected after malformed key: %v", err)
				}
				if claims != 1 {
					t.Fatalf("original claims=%d", claims)
				}
			}
		})
	}
}
