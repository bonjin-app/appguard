package appguard

import (
	"context"
	"encoding/json"
)

type AuditOptions struct {
	EventID string
	AppID   string
	Now     int64
	Context *PolicyContext
}

// AuditRecord has private fields: JSON serialization cannot merge arbitrary data.
// EventID/AppID must be opaque configured identifiers, never credentials/user IDs.
type AuditRecord struct {
	eventID, appID string
	at             int64
	decision       PolicyDecision
	riskCount      *int
	attestation    string
}

func AuditEvent(d PolicyDecision, o AuditOptions) (AuditRecord, error) {
	if !validDecision(d) || !identifierRE.MatchString(o.EventID) || !identifierRE.MatchString(o.AppID) || !validTime(o.Now) || o.Context != nil && !validContext(*o.Context) {
		return AuditRecord{}, failure("INVALID_AUDIT_EVENT")
	}
	r := AuditRecord{eventID: o.EventID, appID: o.AppID, at: o.Now, decision: d}
	if o.Context != nil {
		n := len(o.Context.RiskSignals)
		r.riskCount = &n
		r.attestation = normalizeContext(*o.Context).Attestation
	}
	return r, nil
}
func (r AuditRecord) JSON() ([]byte, error) {
	if !validDecision(r.decision) || !identifierRE.MatchString(r.eventID) || !identifierRE.MatchString(r.appID) || !validTime(r.at) {
		return nil, failure("INVALID_AUDIT_EVENT")
	}
	event := struct {
		SchemaVersion    string `json:"schema_version"`
		EventID          string `json:"event_id"`
		AppID            string `json:"app_id"`
		At               int64  `json:"at"`
		Action           string `json:"action"`
		Code             string `json:"code"`
		Profile          string `json:"profile"`
		RiskCount        *int   `json:"risk_count,omitempty"`
		AttestationState string `json:"attestation_state,omitempty"`
	}{"appguard-audit-v0", r.eventID, r.appID, r.at, r.decision.Action, r.decision.Code, r.decision.Profile, r.riskCount, r.attestation}
	b, err := json.Marshal(event)
	if err != nil {
		return nil, failure("INVALID_AUDIT_EVENT")
	}
	return b, nil
}

type JSONAuditSink struct {
	callback func(context.Context, []byte) error
}

func NewJSONAuditSink(callback func(context.Context, []byte) error) (*JSONAuditSink, error) {
	if callback == nil {
		return nil, failure("INVALID_AUDIT_EVENT")
	}
	return &JSONAuditSink{callback: callback}, nil
}

// Emit redacts callback errors/panics. The host controls sink availability,
// privacy, retention, and whether audit failure denies processing.
func (s *JSONAuditSink) Emit(ctx context.Context, d PolicyDecision, o AuditOptions) (err error) {
	r, err := AuditEvent(d, o)
	if err != nil {
		return err
	}
	b, err := r.JSON()
	if err != nil {
		return err
	}
	if s == nil || s.callback == nil || ctx == nil || ctx.Err() != nil {
		return failure("AUDIT_UNAVAILABLE")
	}
	defer func() {
		if recover() != nil {
			err = failure("AUDIT_UNAVAILABLE")
		}
	}()
	if s.callback(ctx, b) != nil {
		return failure("AUDIT_UNAVAILABLE")
	}
	return nil
}
