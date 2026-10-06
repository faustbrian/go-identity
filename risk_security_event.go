package identity

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
)

// RiskSecurityDecision is the closed risk classification, not authentication,
// revocation or a database/audit commit outcome. Zero is invalid.
type RiskSecurityDecision string

const (
	RiskSecurityAllow    RiskSecurityDecision = "allow"
	RiskSecurityDeny     RiskSecurityDecision = "deny"
	RiskSecurityThrottle RiskSecurityDecision = "throttle"
	RiskSecurityStepUp   RiskSecurityDecision = "step_up"
)

// SecurityUser identifies a known internal user, never an email, phone number
// or provider subject. Imported canonical IDs remain unchanged.
const SecurityUser SecuritySubject = "user"

// RiskSecurityEventInput is trusted risk-owner attribution for a non-mutating
// decision. Subject is a real authentication_attempt or known user; syntax does
// not establish provenance. ImpersonationGrantID is required exactly when the
// effective Actor has one DelegatedBy. Command/correlation identify the owning
// evaluation; optional causation retains an actual prior command or audit event.
// Caller owns attribution until BuildRiskDecision returns and must not mutate it
// concurrently. No provider facts, network, raw identifier, arbitrary reason,
// counter state or bearer can be attached to this input.
type RiskSecurityEventInput struct {
	Decision                              RiskSecurityDecision
	OccurredAt                            time.Time
	TenantID                              TenantID
	CommandID, CorrelationID, CausationID CommandID
	Actor                                 audit.ActorInput
	Subject                               SecuritySubject
	SubjectID, PolicyID                   string
	PolicyVersion                         uint64
	ImpersonationGrantID                  string
}

// BuildRiskDecision constructs the risk-decision subset of identity.security.v1
// using the existing canonical audit record. Allow maps to succeeded/completed;
// deny, throttle and step-up map to denied with their closed registered reason.
// No provider attribution is fabricated and no structured mutation is asserted.
// Only user and genuine pre-auth attempt subjects are supported in this subset.
// Construction does not deliver audit, grant permission or prove a state commit.
// Nil/zero owners, malformed attribution and unknown decisions reject with
// ErrInvalidSecurityEvent and no record; context errors retain their identity.
// Concurrency and clock ownership follow IdentitySecurityEventV1.
func (b *IdentitySecurityEventV1) BuildRiskDecision(ctx context.Context, i RiskSecurityEventInput) (audit.Record, error) {
	if ctx == nil || b == nil || b.builder == nil || b.redactor == nil {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	if err := ctx.Err(); err != nil {
		return audit.Record{}, err
	}
	if !validRiskSecurityInput(i) {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	outcome, reason := audit.OutcomeDenied, SecurityRiskDenied
	switch i.Decision {
	case RiskSecurityAllow:
		outcome, reason = audit.OutcomeSucceeded, SecurityCompleted
	case RiskSecurityThrottle:
		reason = SecurityRateLimited
	case RiskSecurityStepUp:
		reason = SecurityStepUpRequired
	}
	attrs := map[string]string{"identity.profile": "identity.security.v1", "command.id": string(i.CommandID), "retention.class": "protected"}
	if i.ImpersonationGrantID != "" {
		attrs["scope.impersonation_grant_id"] = i.ImpersonationGrantID
	}
	r, err := b.builder.Build(audit.RecordInput{OccurredAt: i.OccurredAt, Action: "identity.risk.decide", Outcome: outcome, ReasonCode: string(reason),
		Actor: i.Actor, Subject: audit.SubjectInput{Type: string(i.Subject), ID: i.SubjectID},
		Context: audit.ContextInput{TenantID: string(i.TenantID), CorrelationID: string(i.CorrelationID), CausationID: string(i.CausationID)},
		Policy:  audit.PolicyMetadata{PolicyID: i.PolicyID, Version: strconv.FormatUint(i.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{NoChange: true}, Attributes: attrs})
	if err != nil {
		if ctx.Err() != nil {
			return audit.Record{}, ctx.Err()
		}
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	r, err = b.redactor.Redact(ctx, r)
	if err != nil {
		if ctx.Err() != nil {
			return audit.Record{}, ctx.Err()
		}
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	return r, nil
}

func validRiskSecurityInput(i RiskSecurityEventInput) bool {
	switch i.Decision {
	case RiskSecurityAllow, RiskSecurityDeny, RiskSecurityThrottle, RiskSecurityStepUp:
	default:
		return false
	}
	if i.OccurredAt.IsZero() || i.OccurredAt.Location() != time.UTC || !securityOpaqueID(string(i.TenantID)) || !securityCommandID(i.CommandID) || !securityCommandID(i.CorrelationID) ||
		i.CausationID != "" && !securityOpaqueID(string(i.CausationID)) || !securityOpaqueID(i.PolicyID) || i.PolicyVersion == 0 || !securityActor(i.Actor, 0) {
		return false
	}
	switch i.Subject {
	case SecurityAuthenticationAttempt:
		if _, err := ParsePreAuthTransactionID(i.SubjectID); err != nil {
			return false
		}
	case SecurityUser:
		if !securityOpaqueID(i.SubjectID) {
			return false
		}
	default:
		return false
	}
	// A delegated actor without its original grant loses privileged causation;
	// a grant without delegation would falsely assert impersonation.
	if i.Actor.DelegatedBy == nil {
		return i.ImpersonationGrantID == ""
	}
	return securityOpaqueID(i.ImpersonationGrantID)
}
