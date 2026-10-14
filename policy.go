package identity

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization"
)

// RiskLevel classifies risk; the empty value is invalid, never implicitly low.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// RiskAction is a policy decision, not an authentication or consumption proof.
type RiskAction string

const (
	RiskAllow  RiskAction = "allow"
	RiskDeny   RiskAction = "deny"
	RiskStepUp RiskAction = "step-up"
)

// RiskSignal is one bounded typed observation. Values must not contain secrets.
// Strings are at most 512 bytes; ObservedAt is required and normalized to UTC.
type RiskSignal struct {
	Name       string
	Value      AttributeScalar
	ObservedAt time.Time
}

// RiskPolicyInput binds a pure risk decision to its exact operation and actor.
// SubjectID may be absent before registration; Signals must be explicit (a
// nonnil empty slice is valid). Deadline is narrowed to the bounded context.
type RiskPolicyInput struct {
	TenantID      TenantID
	ActorID       ActorID
	SubjectID     UserID
	OperationID   string
	PolicyVersion uint64
	Deadline      time.Time
	Signals       []RiskSignal
}

// RiskPolicyDecision has closed enums and 1..32 registered unique reasons.
// Deny and StepUp are valid decisions but never permission to perform a mutation.
type RiskPolicyDecision struct {
	Level         RiskLevel
	Action        RiskAction
	PolicyID      string
	PolicyVersion uint64
	Reasons       []PolicyReason
}

// TypedClaim is a lossless scalar with explicit sensitivity. Secret values are
// forbidden in mapped claims; credentials are never policy inputs or outputs.
type TypedClaim struct {
	Name        string
	Value       AttributeScalar
	Sensitivity Sensitivity
}

// ClaimsPolicyInput binds verified provider data to trusted tenant/actor and
// exact operation/version. Issuer is a bounded absolute HTTPS URI without
// credentials, query or fragment; Subject is at most 512 bytes. It proves no
// provider authentication by itself. Claims must be an explicit bounded slice.
type ClaimsPolicyInput struct {
	TenantID      TenantID
	ActorID       ActorID
	OperationID   string
	PolicyVersion uint64
	Deadline      time.Time
	Issuer        string
	Subject       string
	Claims        []TypedClaim
}

// ClaimsPolicyDecision is a bounded copied mapping, not authenticated authority.
// Reason is mandatory even for an explicitly empty mapped claim set.
type ClaimsPolicyDecision struct {
	Claims        []TypedClaim
	PolicyID      string
	PolicyVersion uint64
	Reason        PolicyReason
}

// RetentionAction identifies the protected privacy operation; zero is invalid.
type RetentionAction string

const (
	RetentionExport    RetentionAction = "export"
	RetentionAnonymize RetentionAction = "anonymize"
	RetentionDelete    RetentionAction = "delete"
)

// RetentionDisposition never represents completed deletion or export.
type RetentionDisposition string

const (
	RetentionAllow          RetentionDisposition = "allow"
	RetentionBlockLegalHold RetentionDisposition = "block-legal-hold"
	RetentionRetainUntil    RetentionDisposition = "retain-until"
)

// RetentionResource identifies one owned resource, with an optional bounded ID.
type RetentionResource struct {
	Kind string
	ID   string
}

// RetentionPolicyInput binds a privacy decision to trusted subject/actor, action,
// operation and policy version. LegalHold=false is an explicit valid input; it
// must come from authoritative composition, not a client assertion. RequestedAt
// is a required trusted timestamp, normalized to UTC without sampling a clock.
type RetentionPolicyInput struct {
	TenantID      TenantID
	ActorID       ActorID
	SubjectID     UserID
	OperationID   string
	PolicyVersion uint64
	Deadline      time.Time
	Resource      RetentionResource
	Action        RetentionAction
	LegalHold     bool
	RequestedAt   time.Time
}

// RetentionPolicyDecision carries registered reasons and optional UTC expiry.
// RetainUntil requires an instant after RequestedAt; other variants omit it.
type RetentionPolicyDecision struct {
	Disposition   RetentionDisposition
	RetainUntil   time.Time
	PolicyID      string
	PolicyVersion uint64
	Reasons       []PolicyReason
}

// AssessRiskFunc is a concurrent-safe bounded pure risk callback.
type AssessRiskFunc func(context.Context, RiskPolicyInput) (RiskPolicyDecision, error)

// MapClaimsFunc is a concurrent-safe bounded pure verified-claim mapping.
type MapClaimsFunc func(context.Context, ClaimsPolicyInput) (ClaimsPolicyDecision, error)

// DecideRetentionFunc is a concurrent-safe bounded pure retention callback.
type DecideRetentionFunc func(context.Context, RetentionPolicyInput) (RetentionPolicyDecision, error)

// PolicySet has exactly the five owned composition members. Configure before
// concurrent use; NewPolicyEvaluator snapshots the callbacks. Authorize remains
// the exact upstream service, not an identity facade. Callbacks own no stores,
// transactions, routing or continuation. They must honor context deadlines;
// no detached goroutine attempts to preempt a misbehaving callback.
type PolicySet struct {
	Authorize       authorization.Service
	AssessRisk      AssessRiskFunc
	MapClaims       MapClaimsFunc
	DecideRetention DecideRetentionFunc
	Redact          RedactFunc
}

// PolicyEvaluatorConfig registers one immutable policy identity/version and
// 1..32 distinct safe reason codes (at most 64 bytes). MaximumDuration must be
// positive and no more than a minute. There are no implicit defaults.
type PolicyEvaluatorConfig struct {
	PolicyID        string
	PolicyVersion   uint64
	Reasons         []PolicyReason
	MaximumDuration time.Duration
}

// PolicyEvaluator validates copied typed input and output around the existing
// pure callbacks. It owns no authority, state, clock, locks or goroutines.
// Invalid input never reaches a callback. Errors/panics/cancellation/malformed
// decisions yield zero output; the evaluator never retries or substitutes policy.
type PolicyEvaluator struct {
	set    PolicySet
	config PolicyEvaluatorConfig
}

// NewPolicyEvaluator freezes composition without I/O, rejecting missing members.
func NewPolicyEvaluator(set PolicySet, cfg PolicyEvaluatorConfig) (*PolicyEvaluator, error) {
	if nilDependency(set.Authorize) || set.AssessRisk == nil || set.MapClaims == nil || set.DecideRetention == nil || set.Redact == nil || !validDirectoryID(cfg.PolicyID) || cfg.PolicyVersion == 0 || cfg.MaximumDuration <= 0 || cfg.MaximumDuration > time.Minute || len(cfg.Reasons) == 0 || len(cfg.Reasons) > 32 {
		return nil, InvalidInputError{Field: "policy_configuration"}
	}
	for i, r := range cfg.Reasons {
		if len(r) > 64 || !validDirectoryID(string(r)) || slices.Contains(cfg.Reasons[:i], r) {
			return nil, InvalidInputError{Field: "policy_reasons"}
		}
	}
	cfg.Reasons = slices.Clone(cfg.Reasons)
	return &PolicyEvaluator{set: set, config: cfg}, nil
}

// AssessRisk validates the exact bound operation and returns no partial decision
// after failure. The valid RiskDeny/StepUp variants remain explicit outcomes.
func (e *PolicyEvaluator) AssessRisk(ctx context.Context, in RiskPolicyInput) (RiskPolicyDecision, error) {
	if e == nil || !e.binding(in.TenantID, in.ActorID, in.OperationID, in.PolicyVersion) || in.SubjectID != "" && !validDirectoryID(string(in.SubjectID)) || in.Signals == nil || len(in.Signals) > 64 {
		return RiskPolicyDecision{}, InvalidInputError{Field: "risk_policy_input"}
	}
	in.Signals = slices.Clone(in.Signals)
	for i, s := range in.Signals {
		n, ok := scalarSize(s.Value)
		if !validDirectoryID(s.Name) || !ok || n > 512 || s.ObservedAt.IsZero() {
			return RiskPolicyDecision{}, InvalidInputError{Field: "risk_signal"}
		}
		for _, prior := range in.Signals[:i] {
			if prior.Name == s.Name {
				return RiskPolicyDecision{}, InvalidInputError{Field: "risk_signal"}
			}
		}
		in.Signals[i].ObservedAt = s.ObservedAt.UTC()
		in.Signals[i].Value = utcScalar(s.Value)
	}
	return callPolicy(ctx, e.config.MaximumDuration, in.Deadline, func(ctx context.Context, deadline time.Time) (RiskPolicyDecision, error) {
		in.Deadline = deadline
		return e.set.AssessRisk(ctx, in)
	}, func(d RiskPolicyDecision) (RiskPolicyDecision, bool) {
		if !e.decision(d.PolicyID, d.PolicyVersion) || !e.reasons(d.Reasons) || (d.Level != RiskLow && d.Level != RiskMedium && d.Level != RiskHigh) || (d.Action != RiskAllow && d.Action != RiskDeny && d.Action != RiskStepUp) {
			return RiskPolicyDecision{}, false
		}
		d.Reasons = slices.Clone(d.Reasons)
		return d, true
	})
}

// MapClaims returns only a bounded lossless mapping with current policy identity.
// It does not verify provider signatures or grant any identity authority.
func (e *PolicyEvaluator) MapClaims(ctx context.Context, in ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
	if e == nil || !e.binding(in.TenantID, in.ActorID, in.OperationID, in.PolicyVersion) || !validPolicyText(in.Subject, 512) || !validClaimIssuer(in.Issuer) || !validClaims(in.Claims) {
		return ClaimsPolicyDecision{}, InvalidInputError{Field: "claims_policy_input"}
	}
	in.Claims = copyClaims(in.Claims)
	return callPolicy(ctx, e.config.MaximumDuration, in.Deadline, func(ctx context.Context, deadline time.Time) (ClaimsPolicyDecision, error) {
		in.Deadline = deadline
		return e.set.MapClaims(ctx, in)
	}, func(d ClaimsPolicyDecision) (ClaimsPolicyDecision, bool) {
		if !e.decision(d.PolicyID, d.PolicyVersion) || !e.reason(d.Reason) || !validClaims(d.Claims) {
			return ClaimsPolicyDecision{}, false
		}
		d.Claims = copyClaims(d.Claims)
		return d, true
	})
}

// DecideRetention prevents a destructive allow under a legal hold. Blocking or
// deferral is a policy observation, never a terminal lifecycle acknowledgement.
func (e *PolicyEvaluator) DecideRetention(ctx context.Context, in RetentionPolicyInput) (RetentionPolicyDecision, error) {
	if e == nil || !e.binding(in.TenantID, in.ActorID, in.OperationID, in.PolicyVersion) || !validDirectoryID(string(in.SubjectID)) || !validDirectoryID(in.Resource.Kind) || (in.Resource.ID != "" && !validPolicyText(in.Resource.ID, 512)) || in.RequestedAt.IsZero() || (in.Action != RetentionExport && in.Action != RetentionAnonymize && in.Action != RetentionDelete) {
		return RetentionPolicyDecision{}, InvalidInputError{Field: "retention_policy_input"}
	}
	in.RequestedAt = in.RequestedAt.UTC()
	return callPolicy(ctx, e.config.MaximumDuration, in.Deadline, func(ctx context.Context, deadline time.Time) (RetentionPolicyDecision, error) {
		in.Deadline = deadline
		return e.set.DecideRetention(ctx, in)
	}, func(d RetentionPolicyDecision) (RetentionPolicyDecision, bool) {
		if !e.decision(d.PolicyID, d.PolicyVersion) || !e.reasons(d.Reasons) {
			return RetentionPolicyDecision{}, false
		}
		switch d.Disposition {
		case RetentionAllow:
			if !d.RetainUntil.IsZero() || in.LegalHold && in.Action != RetentionExport {
				return RetentionPolicyDecision{}, false
			}
		case RetentionBlockLegalHold:
			if !in.LegalHold || !d.RetainUntil.IsZero() {
				return RetentionPolicyDecision{}, false
			}
		case RetentionRetainUntil:
			if !d.RetainUntil.After(in.RequestedAt) {
				return RetentionPolicyDecision{}, false
			}
			d.RetainUntil = d.RetainUntil.UTC()
		default:
			return RetentionPolicyDecision{}, false
		}
		d.Reasons = slices.Clone(d.Reasons)
		return d, true
	})
}

// Redact requires an exact partition of requested fields. Explicit full denial
// is valid (all fields redacted); missing/duplicate/unrequested fields are not.
func (e *PolicyEvaluator) Redact(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
	if e == nil || !e.binding(in.TenantID, in.ViewerID, in.OperationID, in.PolicyVersion) || !validDirectoryID(in.Resource.Kind) || !validPolicyText(in.Resource.ID, 512) || len(in.Fields) == 0 || len(in.Fields) > 128 {
		return RedactionPolicyDecision{}, InvalidInputError{Field: "redaction_policy_input"}
	}
	for i, f := range in.Fields {
		if !validFieldName(f.Value) || slices.Contains(in.Fields[:i], f) {
			return RedactionPolicyDecision{}, InvalidInputError{Field: "redaction_fields"}
		}
	}
	fields := slices.Clone(in.Fields)
	in.Fields = slices.Clone(fields)
	return callPolicy(ctx, e.config.MaximumDuration, in.Deadline, func(ctx context.Context, deadline time.Time) (RedactionPolicyDecision, error) {
		in.Deadline = deadline
		return e.set.Redact(ctx, in)
	}, func(d RedactionPolicyDecision) (RedactionPolicyDecision, bool) {
		if !e.decision(d.PolicyID, d.PolicyVersion) || !e.reason(d.Reason) || len(d.VisibleFields) > len(fields) || len(d.RedactedFields) > len(fields) || len(d.VisibleFields)+len(d.RedactedFields) != len(fields) {
			return RedactionPolicyDecision{}, false
		}
		seen := make(map[FieldName]bool, len(fields))
		for _, group := range [][]FieldName{d.VisibleFields, d.RedactedFields} {
			for _, f := range group {
				if seen[f] || !slices.Contains(fields, f) {
					return RedactionPolicyDecision{}, false
				}
				seen[f] = true
			}
		}
		d.VisibleFields = slices.Clone(d.VisibleFields)
		d.RedactedFields = slices.Clone(d.RedactedFields)
		return d, true
	})
}

func (e *PolicyEvaluator) binding(tenant TenantID, actor ActorID, operation string, version uint64) bool {
	return validDirectoryID(string(tenant)) && validDirectoryID(string(actor)) && validDirectoryID(operation) && version == e.config.PolicyVersion
}
func (e *PolicyEvaluator) decision(id string, version uint64) bool {
	return id == e.config.PolicyID && version == e.config.PolicyVersion
}
func (e *PolicyEvaluator) reason(reason PolicyReason) bool {
	return slices.Contains(e.config.Reasons, reason)
}
func (e *PolicyEvaluator) reasons(reasons []PolicyReason) bool {
	if len(reasons) == 0 || len(reasons) > 32 {
		return false
	}
	for i, r := range reasons {
		if !e.reason(r) || slices.Contains(reasons[:i], r) {
			return false
		}
	}
	return true
}

// callPolicy has one synchronous owner; callbacks must cooperate with ctx.
// Retaining the tighter input deadline never renews another operation's budget.
func callPolicy[T any](ctx context.Context, maximum time.Duration, requested time.Time, call func(context.Context, time.Time) (T, error), validate func(T) (T, bool)) (result T, err error) {
	defer func() {
		if recover() != nil {
			var zero T
			result = zero
			err = UnavailableError{}
		}
	}()
	if ctx == nil {
		return result, InvalidInputError{Field: "policy_context"}
	}
	ctx, cancel := context.WithTimeout(ctx, maximum)
	defer cancel()
	if !requested.IsZero() {
		var narrow context.CancelFunc
		ctx, narrow = context.WithDeadline(ctx, requested)
		defer narrow()
	}
	if err = readContextError(ctx); err != nil {
		return result, err
	}
	deadline, _ := ctx.Deadline()
	out, dependencyErr := call(ctx, deadline.UTC())
	if err = readContextError(ctx); err != nil {
		return result, err
	}
	if dependencyErr != nil {
		return result, UnavailableError{}
	}
	if accepted, ok := validate(out); ok {
		return accepted, nil
	}
	return result, ForbiddenError{}
}
func validPolicyText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func validClaimIssuer(s string) bool {
	if !validPolicyText(s, 2048) || strings.Contains(s, "#") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == ""
}
func validClaims(claims []TypedClaim) bool {
	if claims == nil || len(claims) > 128 {
		return false
	}
	for i, c := range claims {
		if !validDirectoryID(c.Name) || !validSensitivity(c.Sensitivity) || c.Sensitivity == SensitivitySecret {
			return false
		}
		if _, ok := scalarSize(c.Value); !ok {
			return false
		}
		for _, prior := range claims[:i] {
			if prior.Name == c.Name {
				return false
			}
		}
	}
	return true
}
func utcScalar(s AttributeScalar) AttributeScalar {
	if s.Kind == AttributeTime {
		s.Time = s.Time.UTC()
	}
	return s
}
func copyClaims(claims []TypedClaim) []TypedClaim {
	claims = slices.Clone(claims)
	for i := range claims {
		claims[i].Value = utcScalar(claims[i].Value)
	}
	return claims
}
