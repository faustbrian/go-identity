package identity

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability/v2"
)

// PrivacyExportConfig freezes trusted policy, proof trust and retained snapshot
// keys. Keep historical keys through receipt retention; rotation never renews
// proof freshness or rewrites snapshot evidence. One to 32 unique keys are
// required. MaximumProofAge is positive and at most five minutes.
type PrivacyExportConfig struct {
	Query                      UserQueryConfig
	ProofIssuer, ProofAudience string
	MaximumProofAge            time.Duration
	EvidenceKeys               []PrivacyExportEvidenceKey
}

// PrivacyExportRequest carries unsigned exact intent, the original opaque proof
// and authenticated upstream actor context. Intent.Proof must be zero. Binding
// policy/actor/schema must already match this service, so the signed digest is
// never silently rewritten. Do not mutate input concurrently during a call.
type PrivacyExportRequest struct {
	Intent     PrivacyExportRequestCommand
	Proof      capability.Proof
	ActorScope authorization.DecisionContext
}

// PrivacyExportRecoveryRequest retains exact unsigned request intent and current
// authenticated human context. No expired proof is required or consumed.
type PrivacyExportRecoveryRequest struct {
	Intent     PrivacyExportRequestCommand
	ActorScope authorization.DecisionContext
}

// PrivacyExportResult reports command observation, not publication. Job metadata
// is returned only for a validated queued admission and authorized disclosure.
// Known CommitOutcome survives transport, cancellation and disclosure failures.
type PrivacyExportResult struct {
	CommandID     CommandID
	CommitOutcome CommitOutcome
	ExportID      PrivacyExportJobID
	Status        PrivacyExportStatus
}

// Format prevents identifiers from entering diagnostics.
func (PrivacyExportResult) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.PrivacyExportResult(redacted)")
}

// PrivacyExportService admits exact proofs and validates request observations.
// It owns no storage, locks or goroutines. The platform PostgreSQL UnitOfWork
// remains the sole durable owner and must check current user/status/authority,
// real fresh session, legal/destruction eligibility, original proof and all cuts
// under its locks, atomically consume proof and persist queued admission. Replay
// and recovery must recheck current observation eligibility. This service cannot
// make a metadata-only or unimplemented owner safe. Dependencies must honor the
// bounded context and be concurrent-safe; construction performs no IO.
type PrivacyExportService struct {
	uow    UnitOfWork
	caps   capability.Service
	policy *AccountService
	config PrivacyExportConfig
}

// Format redacts runtime dependencies and retained integrity-key configuration.
func (PrivacyExportService) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.PrivacyExportService(redacted)")
}

// MarshalJSON rejects serialization of runtime composition and retained keys.
func (PrivacyExportService) MarshalJSON() ([]byte, error) {
	return nil, InvalidInputError{Field: "privacy_export_service"}
}

// NewPrivacyExportService validates and copies trusted configuration. It rejects
// typed-nil dependencies, missing/duplicate retained keys and unbounded policy.
func NewPrivacyExportService(uow UnitOfWork, caps capability.Service, authorize authorization.Service, redact RedactFunc, c PrivacyExportConfig) (*PrivacyExportService, error) {
	if nilDependency(uow) || nilDependency(caps) || !validClaimIssuer(c.ProofIssuer) || len(c.ProofIssuer) > 256 || !validDirectoryID(c.ProofAudience) || c.MaximumProofAge <= 0 || c.MaximumProofAge > 5*time.Minute || len(c.EvidenceKeys) == 0 || len(c.EvidenceKeys) > 32 {
		return nil, InvalidInputError{Field: "privacy_export_configuration"}
	}
	for i, k := range c.EvidenceKeys {
		if !k.valid() {
			return nil, InvalidInputError{Field: "privacy_export_configuration"}
		}
		for _, before := range c.EvidenceKeys[:i] {
			if before.version == k.version {
				return nil, InvalidInputError{Field: "privacy_export_configuration"}
			}
		}
	}
	p, err := newQueryPolicy(authorize, redact, c.Query)
	if err != nil {
		return nil, err
	}
	c.Query = p.config
	c.EvidenceKeys = slices.Clone(c.EvidenceKeys)
	return &PrivacyExportService{uow: uow, caps: caps, policy: &AccountService{policy: p}, config: c}, nil
}

// PrivacyExportProof returns request-memory custody attached only by the
// configured service. Presence is not authority: the durable owner must reverify
// and reserve/consume atomically. Copies share the original one-transfer lifetime.
// Neither this accessor nor service admission consumes/transfers bearer material;
// never persist it. The metadata constructor attaches no original proof.
func (c Command) PrivacyExportProof() (capability.Proof, bool) {
	if _, ok := c.RequestPrivacyExport(); !ok || c.privacyProof == nil {
		return capability.Proof{}, false
	}
	return *c.privacyProof, true
}

// Request authorizes the current self-service human before cryptographic work,
// verifies configured purpose/issuer/audience/age and hands the frozen original
// proof to the existing durable owner. Invalid owner observations are unknown,
// never invented rollback. Returned status is queued, never completed/ready.
func (s *PrivacyExportService) Request(ctx context.Context, r PrivacyExportRequest) (out PrivacyExportResult, err error) {
	out.CommitOutcome = CommitOutcomeNotCommitted
	defer func() {
		if recover() != nil {
			out.ExportID, out.Status = "", ""
			if out.CommitOutcome == CommitOutcomeUnknown {
				err = unknownError(ctx, out.CommandID)
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "privacy_export_context"}
	}
	if !validPrivacyExportRequest(r.Intent) {
		return out, InvalidInputError{Field: "privacy_export_intent"}
	}
	r.Intent.Projections = slices.Clone(r.Intent.Projections)
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, decisionTime, e := s.admit(ctx, r.Intent, r.ActorScope, false)
	if e != nil {
		return out, e
	}
	out.CommandID = r.Intent.Binding.CommandID
	grant, e := s.caps.Verify(ctx, r.Proof, capability.Purpose(privacyExportRequestOperation), s.config.ProofAudience)
	if ce := readContextError(ctx); ce != nil {
		return out, ce
	}
	if e != nil {
		return out, ForbiddenError{}
	}
	p := grant.Payload()
	now := decisionTime.instant
	if p.Issuer != s.config.ProofIssuer || len(p.Audiences) != 1 || p.Audiences[0] != s.config.ProofAudience || now.Before(p.IssuedAt) || now.Before(p.NotBefore) || !now.Before(p.ExpiresAt) || p.ExpiresAt.Sub(p.IssuedAt) > s.config.MaximumProofAge || now.Sub(p.IssuedAt) >= s.config.MaximumProofAge {
		return out, ForbiddenError{}
	}
	intent := r.Intent
	intent.Proof = grant
	command, e := NewPrivacyExportRequestCommand(intent)
	if e != nil {
		return out, ForbiddenError{}
	}
	command.privacyProof = &r.Proof
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Execute(ctx, command)
	return s.observe(ctx, out, r.Intent, receipt, e, dc, decisionTime)
}

// Recover queries the same scoped command under current authorization, matching
// retained unsigned intent and recorded evidence-key version. It never verifies
// an expired bearer, executes a mutation or allocates a replacement export ID.
func (s *PrivacyExportService) Recover(ctx context.Context, r PrivacyExportRecoveryRequest) (out PrivacyExportResult, err error) {
	// A denied observation cannot assert that a prior command rolled back.
	out.CommitOutcome = CommitOutcomeUnknown
	defer func() {
		if recover() != nil {
			out.ExportID, out.Status = "", ""
			if out.CommitOutcome == CommitOutcomeUnknown {
				err = unknownError(ctx, out.CommandID)
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "privacy_export_context"}
	}
	if !validPrivacyExportRequest(r.Intent) {
		return out, InvalidInputError{Field: "privacy_export_intent"}
	}
	r.Intent.Projections = slices.Clone(r.Intent.Projections)
	ctx, cancel := context.WithTimeout(ctx, s.config.Query.MaximumDuration)
	defer cancel()
	dc, decisionTime, e := s.admit(ctx, r.Intent, r.ActorScope, true)
	if e != nil {
		return out, e
	}
	b := r.Intent.Binding
	out.CommandID = b.CommandID
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, e := s.uow.Recover(ctx, RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID})
	return s.observe(ctx, out, r.Intent, receipt, e, dc, decisionTime)
}

// Keep the trusted clock sample separate from process-local elapsed time.
// Re-evaluating disclosure advances decision time, never proof or snapshot age.
type privacyDecisionTime struct{ instant, started time.Time }

func (s *PrivacyExportService) admit(ctx context.Context, c PrivacyExportRequestCommand, scope authorization.DecisionContext, recovery bool) (authorization.DecisionContext, privacyDecisionTime, error) {
	zero := authorization.DecisionContext{}
	if !validPrivacyExportRequest(c) || c.Proof.Payload().ID != "" || c.Binding.PolicyID != s.config.Query.PolicyID || c.Binding.PolicyVersion != s.config.Query.PolicyVersion {
		return zero, privacyDecisionTime{}, InvalidInputError{Field: "privacy_export_intent"}
	}
	b := c.Binding
	if scope.Request.Subject.Kind != authorization.SubjectUser || string(scope.Request.Subject.ID) != string(b.UserID) {
		return zero, privacyDecisionTime{}, ForbiddenError{}
	}
	if e := validateQueryContext(scope, b.TenantID, string(b.UserID), b.OperationID, "identity.user", s.config.Query.PolicyVersion); e != nil {
		return zero, privacyDecisionTime{}, e
	}
	if e := readContextError(ctx); e != nil {
		return zero, privacyDecisionTime{}, e
	}
	if e := s.config.Query.ValidateCanonicalUserID(ctx, b.UserID); e != nil {
		if ce := readContextError(ctx); ce != nil {
			return zero, privacyDecisionTime{}, ce
		}
		return zero, privacyDecisionTime{}, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return zero, privacyDecisionTime{}, e
	}
	now := s.config.Query.Clock.Now()
	started := time.Now()
	if now.IsZero() {
		return zero, privacyDecisionTime{}, UnavailableError{}
	}
	dc := scope.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for k := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(k), "identity.") {
			delete(dc.Request.Resource.Attributes, k)
		}
	}
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(recovery)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(!recovery)
	if e := s.policy.allow(ctx, dc); e != nil {
		return zero, privacyDecisionTime{}, e
	}
	return dc, privacyDecisionTime{instant: now, started: started}, nil
}

func (s *PrivacyExportService) observe(ctx context.Context, out PrivacyExportResult, intent PrivacyExportRequestCommand, r CommandResult, dependencyErr error, dc authorization.DecisionContext, decisionTime privacyDecisionTime) (result PrivacyExportResult, err error) {
	defer func() {
		if recover() != nil {
			result = out
			result.ExportID, result.Status = "", ""
			if out.CommitOutcome == CommitOutcomeUnknown {
				err = unknownError(ctx, out.CommandID)
			} else {
				err = UnavailableError{}
			}
		}
	}()
	var key PrivacyExportEvidenceKey
	if r.PrivacyExport != nil {
		for _, k := range s.config.EvidenceKeys {
			if k.version == r.PrivacyExport.Snapshot.EvidenceKeyVersion {
				key = k
				break
			}
		}
	}
	snapshot, e := r.ValidatePrivacyExportRequest(intent, key)
	if e != nil {
		return out, unknownError(ctx, out.CommandID)
	}
	out.CommitOutcome = r.Outcome
	if r.Outcome == CommitOutcomeUnknown {
		return out, unknownError(ctx, out.CommandID)
	}
	if e := readContextError(ctx); e != nil {
		return out, e
	}
	if dependencyErr != nil {
		return out, UnavailableError{}
	}
	switch r.Outcome {
	case CommitOutcomeNotCommitted:
		return out, NotCommittedError{out.CommandID}
	case CommitOutcomeConflict:
		return out, ConflictError{out.CommandID}
	case CommitOutcomeInProgress:
		return out, InProgressError{out.CommandID, r.RetryAfter}
	}
	deadline, _ := ctx.Deadline()
	fields := []FieldName{{"export_id"}, {"status"}}
	decision, e := s.policy.policy.redact(ctx, RedactionPolicyInput{TenantID: intent.Binding.TenantID, ViewerID: intent.Binding.ActorID, Resource: RedactionResource{Kind: "identity.privacy-export", ID: string(snapshot.Record().ExportID)}, Fields: slices.Clone(fields), OperationID: privacyExportRequestOperation, PolicyVersion: s.config.Query.PolicyVersion, Deadline: deadline.UTC()})
	if ce := readContextError(ctx); ce != nil {
		return out, ce
	}
	if e != nil || decision.PolicyID != s.config.Query.PolicyID || decision.PolicyVersion != s.config.Query.PolicyVersion || !slices.Contains(s.config.Query.RedactionReasons, decision.Reason) || len(decision.RedactedFields) != 0 || len(decision.VisibleFields) != 2 || !slices.Contains(decision.VisibleFields, fields[0]) || !slices.Contains(decision.VisibleFields, fields[1]) {
		return out, ForbiddenError{}
	}
	// Include both durable-owner and redaction work before final disclosure.
	// The owner separately enforces current durable observation eligibility;
	// receipt metadata never supplies caller-asserted status/authority attributes.
	dc.Request.Environment.Time = decisionTime.instant.Add(time.Since(decisionTime.started)).UTC()
	if e := s.policy.allow(ctx, dc); e != nil {
		return out, e
	}
	out.ExportID = snapshot.Record().ExportID
	out.Status = PrivacyExportQueued
	return out, nil
}
