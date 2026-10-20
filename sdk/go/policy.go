package appguard

import "regexp"

var signalRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var defaultSignals = []string{"debugger", "root", "hook", "tamper"}

// Policy defaults to Basic with signatures required. Only an explicit false
// RequireSignature on Basic opts out; nil SuspiciousSignals uses the defaults.
type Policy struct {
	Profile           string   `json:"profile"`
	RequireSignature  *bool    `json:"require_signature,omitempty"`
	SuspiciousSignals []string `json:"suspicious_signals,omitempty"`
}

// PolicyContext contains trusted server verdicts and bounded untrusted hints.
// Empty states mean missing, so the zero value always denies authentication.
type PolicyContext struct {
	Authentication     string   `json:"authentication"`
	Verification       string   `json:"verification"`
	Attestation        string   `json:"attestation"`
	AttestationExpires *int64   `json:"attestation_expires"`
	RiskSignals        []string `json:"risk_signals"`
	RateLimited        bool     `json:"rate_limited"`
}
type PolicyDecision struct {
	Action  string `json:"action"`
	Code    string `json:"code"`
	Profile string `json:"profile"`
}

func (d PolicyDecision) PermitsProcessing() bool {
	return validDecision(d) && (d.Action == "allow" || d.Action == "observe")
}
func in(value string, choices ...string) bool {
	for _, v := range choices {
		if value == v {
			return true
		}
	}
	return false
}
func validSignals(signals []string) bool {
	if len(signals) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range signals {
		if !signalRE.MatchString(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func normalizeContext(c PolicyContext) PolicyContext {
	if c.Authentication == "" {
		c.Authentication = "missing"
	}
	if c.Verification == "" {
		c.Verification = "missing"
	}
	if c.Attestation == "" {
		c.Attestation = "missing"
	}
	return c
}
func validContext(c PolicyContext) bool {
	c = normalizeContext(c)
	return in(c.Authentication, "authenticated", "missing", "invalid") && in(c.Verification, "verified", "missing", "rejected", "unavailable") && in(c.Attestation, "verified", "missing", "unsupported", "rejected", "unavailable") && (c.AttestationExpires == nil || validTime(*c.AttestationExpires)) && validSignals(c.RiskSignals)
}
func observation(profile string) string {
	switch profile {
	case "basic":
		return "observe"
	case "balanced":
		return "step_up"
	default:
		return "deny"
	}
}
func validDecision(d PolicyDecision) bool {
	if !in(d.Profile, "basic", "balanced", "strict") {
		return false
	}
	if in(d.Code, "AUTHENTICATION_REQUIRED", "AUTHENTICATION_INVALID", "REQUEST_REJECTED", "VERIFICATION_UNAVAILABLE", "SIGNATURE_REQUIRED", "ATTESTATION_REJECTED", "RATE_LIMITED") {
		return d.Action == "deny"
	}
	if in(d.Code, "ATTESTATION_MISSING", "ATTESTATION_UNSUPPORTED", "ATTESTATION_UNAVAILABLE", "ATTESTATION_EXPIRED", "RISK_DETECTED") {
		return d.Action == observation(d.Profile)
	}
	return d.Code == "ALLOWED" && d.Action == "allow"
}

// EvaluatePolicy performs no I/O or AI/provider calls. step_up requires a
// separate trusted verification flow and never permits processing by itself.
func EvaluatePolicy(p Policy, c PolicyContext, now int64) (PolicyDecision, error) {
	if p.Profile == "" {
		p.Profile = "basic"
	}
	require := p.RequireSignature == nil || *p.RequireSignature
	if !in(p.Profile, "basic", "balanced", "strict") || !require && p.Profile != "basic" || !validSignals(p.SuspiciousSignals) {
		return PolicyDecision{}, failure("INVALID_POLICY")
	}
	if !validTime(now) || !validContext(c) {
		return PolicyDecision{}, failure("INVALID_POLICY_CONTEXT")
	}
	c = normalizeContext(c)
	deny := func(code string) (PolicyDecision, error) {
		return PolicyDecision{Action: "deny", Code: code, Profile: p.Profile}, nil
	}
	observe := func(code string) (PolicyDecision, error) {
		return PolicyDecision{Action: observation(p.Profile), Code: code, Profile: p.Profile}, nil
	}
	if c.Authentication == "missing" {
		return deny("AUTHENTICATION_REQUIRED")
	}
	if c.Authentication == "invalid" {
		return deny("AUTHENTICATION_INVALID")
	}
	if c.Verification == "rejected" {
		return deny("REQUEST_REJECTED")
	}
	if c.Verification == "unavailable" {
		return deny("VERIFICATION_UNAVAILABLE")
	}
	if c.Attestation == "rejected" {
		return deny("ATTESTATION_REJECTED")
	}
	if c.Verification == "missing" && require {
		return deny("SIGNATURE_REQUIRED")
	}
	if c.RateLimited {
		return deny("RATE_LIMITED")
	}
	switch c.Attestation {
	case "missing":
		return observe("ATTESTATION_MISSING")
	case "unsupported":
		return observe("ATTESTATION_UNSUPPORTED")
	case "unavailable":
		return observe("ATTESTATION_UNAVAILABLE")
	}
	if c.AttestationExpires == nil || now >= *c.AttestationExpires {
		return observe("ATTESTATION_EXPIRED")
	}
	signals := p.SuspiciousSignals
	if signals == nil {
		signals = defaultSignals
	}
	for _, v := range c.RiskSignals {
		if in(v, signals...) {
			return observe("RISK_DETECTED")
		}
	}
	return PolicyDecision{Action: "allow", Code: "ALLOWED", Profile: p.Profile}, nil
}
