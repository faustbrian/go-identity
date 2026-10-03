package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	audit "github.com/faustbrian/go-audit"
	clock "github.com/faustbrian/go-clock"
)

// ErrInvalidSecurityEvent rejects unsafe or unsupported profile fields without
// disclosing input. Construction never proves audit delivery or authorization.
var ErrInvalidSecurityEvent = errors.New("identity: invalid security event")

// SecurityAction is a closed implemented subset of the security taxonomy.
// Further package actions require their owned field contract before support.
type SecurityAction string

const (
	SecurityHIBPQueryRange  SecurityAction = "identity.hibp.query_range"
	SecurityHIBPDetectMatch SecurityAction = "identity.hibp.detect_match"
	SecurityHIBPRejectRange SecurityAction = "identity.hibp.reject_range"
)

// SecurityReason is the bounded shared reason catalog, never free text.
type SecurityReason string

const (
	SecurityCompleted           SecurityReason = "completed"
	SecurityInvalidInput        SecurityReason = "invalid_input"
	SecurityNotAuthenticated    SecurityReason = "not_authenticated"
	SecurityNotAuthorized       SecurityReason = "not_authorized"
	SecurityNotFoundHidden      SecurityReason = "not_found_hidden"
	SecurityConflict            SecurityReason = "conflict"
	SecurityExpired             SecurityReason = "expired"
	SecurityReplayed            SecurityReason = "replayed"
	SecurityRateLimited         SecurityReason = "rate_limited"
	SecurityRiskDenied          SecurityReason = "risk_denied"
	SecurityStepUpRequired      SecurityReason = "step_up_required"
	SecurityProviderDenied      SecurityReason = "provider_denied"
	SecurityProviderUnavailable SecurityReason = "provider_unavailable"
	SecurityTimeout             SecurityReason = "timeout"
	SecurityCancelled           SecurityReason = "cancelled"
	SecurityCommitUnknown       SecurityReason = "commit_unknown"
)

// SecuritySubject is a closed safe resource classification. Initial HIBP
// construction uses the real pre-auth attempt, never an identifier or digest.
type SecuritySubject string

const SecurityAuthenticationAttempt SecuritySubject = "authentication_attempt"

// SecurityProviderKind identifies an implemented provider without endpoint data.
type SecurityProviderKind string

const SecurityProviderHIBP SecurityProviderKind = "hibp"

// SecurityProviderProfile is a registered immutable protocol/privacy profile.
type SecurityProviderProfile string

const SecurityHIBPRange SecurityProviderProfile = "hibp.range.padded.v1"

// SecurityProviderResult describes evidence, not password acceptance or storage.
type SecurityProviderResult string

const (
	SecurityProviderAccepted          SecurityProviderResult = "accepted"
	SecurityProviderResultDenied      SecurityProviderResult = "denied"
	SecurityProviderResultUnavailable SecurityProviderResult = "unavailable"
	SecurityProviderResultTimeout     SecurityProviderResult = "timeout"
	SecurityProviderThrottled         SecurityProviderResult = "throttled"
	SecurityProviderMalformed         SecurityProviderResult = "malformed"
	SecurityProviderAmbiguous         SecurityProviderResult = "ambiguous"
	SecurityProviderBindingMismatch   SecurityProviderResult = "binding_mismatch"
	SecurityProviderReplayed          SecurityProviderResult = "replayed"
)

// SecurityProvider contains only registered safe provider attribution. Version
// is positive and encoded once as canonical decimal at the audit boundary.
type SecurityProvider struct {
	Kind    SecurityProviderKind
	Profile SecurityProviderProfile
	Version uint64
	Result  SecurityProviderResult
}

// SecurityEventInput is trusted in-process attribution, not transport input.
// Its fields cannot contain arbitrary attributes, descriptions, network data,
// hashes, breach counts, raw claims or provider diagnostics. IDs must be stable
// canonical internal IDs, never credentials or raw user identifiers. Actor
// delegation is copied synchronously; callers must not mutate it during Build.
// Initial support is the HIBP action contract with a real authentication attempt
// subject and protected retention. Other action contracts fail closed.
// Command and correlation use command IDs. Causation additionally admits a
// canonical existing audit event ID carried unchanged in the named string type.
type SecurityEventInput struct {
	Action                                SecurityAction
	OccurredAt                            time.Time
	Outcome                               audit.Outcome
	Reason                                SecurityReason
	TenantID                              TenantID
	CommandID, CorrelationID, CausationID CommandID
	Actor                                 audit.ActorInput
	Subject                               SecuritySubject
	SubjectID, PolicyID                   string
	PolicyVersion                         uint64
	Provider                              SecurityProvider
}

// IdentitySecurityEventV1 is the shared immutable profile builder. It owns no
// persistence or goroutine. The borrowed wall clock must be concurrency-safe;
// Build performs no callbacks under locks or database transactions. Copies share
// immutable primitive builders. The zero value is invalid.
type IdentitySecurityEventV1 struct {
	builder  *audit.Builder
	redactor audit.Redactor
}

// NewIdentitySecurityEventV1 selects exact profile limits and secure random
// record identities. A nil wall clock rejects; its panic/zero time is handled by
// the audit primitive. Caller retains clock ownership. No globals are changed.
func NewIdentitySecurityEventV1(wall clock.Clock) (*IdentitySecurityEventV1, error) {
	if wall == nil {
		return nil, ErrInvalidSecurityEvent
	}
	b, e := audit.NewBuilder(audit.BuilderConfig{Clock: wall.Now, Limits: securityLimits()})
	if e != nil {
		return nil, ErrInvalidSecurityEvent
	}
	r, e := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "provider.kind", "provider.profile", "provider.version", "provider.result"}})
	if e != nil {
		return nil, ErrInvalidSecurityEvent
	}
	return &IdentitySecurityEventV1{builder: b, redactor: r}, nil
}

func securityLimits() audit.Limits {
	return audit.Limits{MaxRecordBytes: 16384, MaxFieldBytes: 256, MaxDescriptionBytes: 1, MaxAttributeEntries: 32, MaxAttributeBytes: 8192, MaxChangeEntries: 32, MaxChangeBytes: 8192, MaxIntegrityBytes: 32}
}

// Build returns an immutable, explicitly redacted canonical audit.Record with
// no structured mutation. It does not persist, buffer, retry or grant authority.
// Unsupported fields/actions and unsafe attribution return the stable sentinel;
// cancellation retains its identity and returns no record. RecordedAt belongs
// to the primitive builder clock, separately from trusted OccurredAt.
func (b *IdentitySecurityEventV1) Build(ctx context.Context, input SecurityEventInput) (audit.Record, error) {
	if ctx == nil || b == nil || b.builder == nil || b.redactor == nil {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	if e := ctx.Err(); e != nil {
		return audit.Record{}, e
	}
	if !validSecurityInput(input) {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	record, e := b.builder.Build(audit.RecordInput{OccurredAt: input.OccurredAt, Action: string(input.Action), Outcome: input.Outcome, ReasonCode: string(input.Reason), Actor: input.Actor, Subject: audit.SubjectInput{Type: string(input.Subject), ID: input.SubjectID}, Context: audit.ContextInput{TenantID: string(input.TenantID), CorrelationID: string(input.CorrelationID), CausationID: string(input.CausationID)}, Policy: audit.PolicyMetadata{PolicyID: input.PolicyID, Version: strconv.FormatUint(input.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(input.CommandID), "retention.class": "protected", "provider.kind": string(input.Provider.Kind), "provider.profile": string(input.Provider.Profile), "provider.version": strconv.FormatUint(input.Provider.Version, 10), "provider.result": string(input.Provider.Result)}})
	if e != nil {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	record, e = b.redactor.Redact(ctx, record)
	if e != nil {
		if err := ctx.Err(); err != nil {
			return audit.Record{}, err
		}
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	return record, nil
}

func validSecurityInput(i SecurityEventInput) bool {
	if i.Action != SecurityHIBPQueryRange && i.Action != SecurityHIBPDetectMatch && i.Action != SecurityHIBPRejectRange {
		return false
	}
	// Unknown-identity subjects are actual pre-auth transactions, not a general
	// opaque-ID slot into which an identifier digest could be substituted.
	if _, e := ParsePreAuthTransactionID(i.SubjectID); e != nil {
		return false
	}
	// Causation may reference a prior audit event, whose canonical ID profile
	// belongs to the audit primitive rather than the command-ID parser.
	if i.OccurredAt.IsZero() || i.OccurredAt.Location() != time.UTC || !securityOpaqueID(string(i.TenantID)) || !securityCommandID(i.CommandID) || !securityCommandID(i.CorrelationID) || i.CausationID != "" && !securityOpaqueID(string(i.CausationID)) || i.Subject != SecurityAuthenticationAttempt || !securityOpaqueID(i.SubjectID) || !securityOpaqueID(i.PolicyID) || i.PolicyVersion == 0 || !securityActor(i.Actor, 0) {
		return false
	}
	p := i.Provider
	if p.Kind != SecurityProviderHIBP || p.Profile != SecurityHIBPRange || p.Version == 0 {
		return false
	}
	switch p.Result {
	case SecurityProviderAccepted, SecurityProviderResultDenied, SecurityProviderResultUnavailable, SecurityProviderResultTimeout, SecurityProviderThrottled, SecurityProviderMalformed, SecurityProviderAmbiguous, SecurityProviderBindingMismatch, SecurityProviderReplayed:
	default:
		return false
	}
	switch i.Outcome {
	case audit.OutcomeSucceeded:
		return i.Reason == SecurityCompleted
	case audit.OutcomeUnknown:
		return i.Reason == SecurityCommitUnknown
	case audit.OutcomeFailed:
		return i.Reason == SecurityProviderUnavailable || i.Reason == SecurityTimeout || i.Reason == SecurityCancelled
	case audit.OutcomeDenied:
		switch i.Reason {
		case SecurityInvalidInput, SecurityNotAuthenticated, SecurityNotAuthorized, SecurityNotFoundHidden, SecurityConflict, SecurityExpired, SecurityReplayed, SecurityRateLimited, SecurityRiskDenied, SecurityStepUpRequired, SecurityProviderDenied:
			return true
		}
	}
	return false
}

func securityCommandID(id CommandID) bool { _, e := ParseCommandID(string(id)); return e == nil }

func securityActor(a audit.ActorInput, depth int) bool {
	if depth > 1 {
		return false
	}
	switch a.Kind {
	case audit.ActorAnonymous:
		if a.ID != "" || a.AuthenticationMethod != "" || a.DelegatedBy != nil {
			return false
		}
	case audit.ActorHuman, audit.ActorSystem:
		if !securityOpaqueID(a.ID) {
			return false
		}
	default:
		return false
	}
	if a.DelegatedBy != nil && !securityActor(*a.DelegatedBy, depth+1) {
		return false
	}
	return true // Primitive validates the closed AuthenticationMethod catalog.
}

// Supported imported ID profiles remain byte-for-byte unchanged. This is a
// syntax/privacy check only, not authority, identity resolution or provenance.
func securityOpaqueID(s string) bool {
	if _, ok := decodeID(s); ok {
		return true
	}
	if len(s) == 26 && s[0] >= '0' && s[0] <= '7' {
		for _, c := range s {
			if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
				return false
			}
		}
		return strings.Trim(s, "0") != ""
	}
	raw := s
	if len(s) == 36 {
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return false
		}
		raw = s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	}
	if len(raw) != 32 || raw != strings.ToLower(raw) {
		return false
	}
	decoded, e := hex.DecodeString(raw)
	if e != nil {
		return false
	}
	var any byte
	for _, b := range decoded {
		any |= b
	}
	return any != 0
}
