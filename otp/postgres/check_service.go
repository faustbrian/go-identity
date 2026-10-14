package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// CheckConfig opts into metered non-consuming checks over a native SendService.
// CurrentAttemptKeyVersion selects a retained Send codec attempt key for new
// submissions only. Coordinator must enable QueryPolicy; its current policy
// separately authorizes original Send custody and check receipt disclosure.
// Neither this config nor Check accepts caller-selected attempt identities.
type CheckConfig struct {
	Coordinator              kernel.CoordinatorConfig
	CurrentAttemptKeyVersion uint32
}

// CheckService owns public Send-to-Check orchestration and recovery. It borrows
// the sender's pool and immutable custody/configuration; no caller domain glue,
// new store, journal, migration, background goroutine or resource owner is added.
// Distinct coordinators select the original Send owner and metering owner over
// the SAME kernel journal, preserving exact participant identity. Concurrent
// calls are supported. Initialize the sender before use; zero/nil is invalid.
type CheckService struct {
	sender              *SendService
	source, coordinator *kernel.Coordinator
	registry            *kernel.ContributorRegistry
	issuer              otp.AttemptIssuer
	policyVersion       uint64
	admissionVersion    uint64
}

// NewCheckService validates pure startup composition without SQL, entropy or
// callbacks. Existing Send-only service/registry behavior is unchanged. The
// original sender must be fully configured; missing retained keys or query
// policy fail closed. The borrowed dependencies remain caller-owned.
func NewCheckService(sender *SendService, c CheckConfig) (*CheckService, error) {
	if sender == nil || sender.owner == nil || sender.owner.store == nil || sender.registry == nil || sender.pool == nil || c.Coordinator.QueryPolicy == nil {
		return nil, ErrInvalidConfiguration
	}
	issuer, ok := sender.owner.store.codec.issuers[c.CurrentAttemptKeyVersion]
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	if c.Coordinator.AdmissionPolicy == nil {
		policy := *c.Coordinator.QueryPolicy
		c.Coordinator.AdmissionPolicy = &policy
	}
	repo, err := kernel.NewRepository(sender.pool, kernel.Config{MaximumDuration: sender.timeout})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, audits, lifecycle, sender.owner.store})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	coordinator, err := kernel.NewCoordinator(sender.pool, registry, c.Coordinator)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	source, err := kernel.NewCoordinatorWithRequestKeys(sender.pool, sender.registry, c.Coordinator, sender.requestKeys)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &CheckService{sender: sender, source: source, coordinator: coordinator, registry: registry, issuer: issuer, policyVersion: c.Coordinator.QueryPolicy.PolicyVersion, admissionVersion: c.Coordinator.AdmissionPolicy.PolicyVersion}, nil
}

// Check prepares exactly one server-owned attempt and invokes the kernel's
// atomic metering/audit/receipt transaction. Correct and wrong comparisons both
// charge their configured budgets. No consuming phase, workflow, delivery or
// session effect is reachable. Every call is a NEW submission; recover ambiguity
// with returned Recovery, never call Check again as a retry of that submission.
// Current primary authority is checked before attempt preparation and within
// the native transaction after locks. Earlier deadlines win; panic/error after
// entering execution conservatively preserves Unknown and original recovery.
func (s *CheckService) Check(ctx context.Context, r otp.CheckRequest) (result otp.CheckResult, err error) {
	if ctx == nil || s == nil || s.sender == nil {
		return result, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return result, err
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	entered := false
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
			if entered {
				result.Outcome = identity.CommitOutcomeUnknown
				result.Valid = false
				err = identity.UnknownCommitError{CommandID: result.CommandID}
			}
		}
	}()
	command, custody, flow, err := s.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return result, err
	}
	spec, _ := command.Feature()
	if err = s.requireCurrent(ctx, spec.Binding, custody.authority, flow); err != nil {
		return result, err
	}
	issued, _ := custody.challenge.Bindings()
	digestScope, _ := issued.Continuation.DigestScope()
	scope, err := s.sender.owner.store.codec.verifier.ScopeDigest(digestScope, issued.Digest.KeyVersion)
	if err != nil {
		return result, ErrInvalidCommand
	}
	var versionText string
	schema := pgx.Identifier{s.sender.owner.store.schema}.Sanitize()
	if err = s.sender.pool.Raw().QueryRow(ctx, `SELECT version::text FROM `+schema+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4`, string(r.TenantID), string(r.SendCommandID), int64(issued.Digest.KeyVersion), scope.Value[:]).Scan(&versionText); err != nil {
		return result, custodyFailure(ctx)
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != versionText {
		return result, ErrUnavailable
	}
	spec.Operation = checkOperation(spec.Operation.SubjectRequirement)
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	spec.Binding.RecordID = ""
	spec.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		return result, ErrUnavailable
	}
	spec.Binding.CorrelationID = string(spec.Binding.CommandID)
	spec.Fields = nil
	// Reading original Send custody is not permission to submit a Check. The
	// existing kernel's separate admission boundary evaluates the actual Check
	// operation without introducing another policy service or durable claim.
	query := checkQuery(spec.Binding, spec.Binding.CommandID, "identity.otp.check", false)
	caller := s.planCaller(r.Caller, query)
	caller.PolicyRevision = authorization.Revision(s.admissionVersion)
	admission, err := s.coordinator.ObserveCommandAdmission(ctx, query, caller)
	if err != nil {
		return result, err
	}
	if !admission.Absent {
		return result, identity.ForbiddenError{}
	}
	attempt, err := s.issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, issued.Continuation, otp.AttemptModeCheck, version, r.Code)
	if err != nil {
		return result, err
	}
	_, _, bearer, _ := r.Flow.Bindings()
	var check identity.Command
	var otpPlan kernel.OTPAttemptPlan
	if _, ok := command.SessionToken(); ok {
		check, otpPlan, err = s.sender.owner.store.codec.MapSessionWithAuthority(ctx, attempt, issued.Digest.KeyVersion, spec, bearer, custody.authority)
	} else {
		check, otpPlan, err = s.sender.owner.store.codec.MapPreAuthWithAuthority(ctx, attempt, issued.Digest.KeyVersion, spec, bearer, custody.authority)
	}
	if err != nil {
		return result, err
	}
	recovery, _ := attempt.Recovery()
	result.Recovery, err = otp.NewCheckRecovery(otp.CheckRecoveryBindings{SendCommandID: r.SendCommandID, Attempt: recovery, ExpectedVersion: version, DigestKeyVersion: otpPlan.DigestKeyVersion, ScopeDigest: otpPlan.ScopeDigest})
	if err != nil {
		return otp.CheckResult{}, err
	}
	result.CommandID = spec.Binding.CommandID
	plan, err := s.checkPlan(check, otpPlan)
	if err != nil {
		return result, err
	}
	prepared, err := s.coordinator.PrepareOTPAttemptPlan(spec.Binding, check, plan)
	if err != nil {
		return result, err
	}
	result.Outcome = identity.CommitOutcomeUnknown
	entered = true
	outcome, err := s.coordinator.RecordOTPMeteredCheck(ctx, spec.Binding, check, prepared)
	if outcome.Outcome != 0 {
		result.Outcome, result.RetryAfter = outcome.Outcome, outcome.RetryAfter
	}
	result.Valid = result.Outcome == identity.CommitOutcomeCommitted
	return result, err
}

// RecoverCheck authenticates original Send envelopes and actual bearer anew,
// checks current primary authority before AND after receipt lookup, then returns
// the exact frozen original metered outcome. It accepts no code, performs no
// comparison, charge, mutation or takeover, and ignores current challenge state.
// Changed recovery metadata or caller/flow scope denies without disclosing a
// command/result. Pending remains InProgress; absence is not rollback proof.
func (s *CheckService) RecoverCheck(ctx context.Context, r otp.CheckRecoveryRequest) (result otp.CheckResult, err error) {
	if ctx == nil || s == nil || s.sender == nil {
		return result, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return result, err
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			result = otp.CheckResult{}
			err = ErrUnavailable
		}
	}()
	b, _ := r.Recovery.Bindings()
	command, custody, flow, err := s.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, b.SendCommandID)
	if err != nil {
		return result, err
	}
	spec, _ := command.Feature()
	if err = s.requireCurrent(ctx, spec.Binding, custody.authority, flow); err != nil {
		return result, err
	}
	fingerprint, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.Attempt.Fingerprint))
	defer clear(fingerprint)
	plan := kernel.OTPAttemptPlan{AttemptID: string(b.Attempt.AttemptID), AttemptFingerprint: [32]byte(fingerprint), FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion, ChallengeID: string(b.SendCommandID), ScopeDigest: b.ScopeDigest, DigestKeyVersion: b.DigestKeyVersion, ExpectedVersion: b.ExpectedVersion, Mode: kernel.OTPCheck}
	q := checkQuery(spec.Binding, b.Attempt.CommandID, "identity.otp.check", false)
	outcome, err := s.coordinator.RecoverOTPMeteredCheck(ctx, q, plan, s.planCaller(r.Caller, q))
	if outcome.Outcome == 0 {
		return result, err
	}
	if freshErr := s.requireCurrent(ctx, spec.Binding, custody.authority, flow); freshErr != nil {
		return result, freshErr
	}
	return otp.CheckResult{CommandID: b.Attempt.CommandID, Outcome: outcome.Outcome, Valid: outcome.Outcome == identity.CommitOutcomeCommitted, Recovery: r.Recovery, RetryAfter: outcome.RetryAfter}, err
}

func checkQuery(b identity.CommandBinding, id identity.CommandID, operation string, send bool) identity.RecoveryQuery {
	q := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: operation}
	if send {
		q.RecordID = string(id)
	}
	return q
}

func (s *CheckService) planCaller(c authorization.DecisionContext, q identity.RecoveryQuery) authorization.DecisionContext {
	c = c.Clone()
	c.PolicyRevision = authorization.Revision(s.policyVersion)
	c.Request.Action = authorization.Action(q.OperationID)
	c.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}
	if q.UserID == "" {
		c.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	}
	return c
}

func (s *CheckService) restoreSource(ctx context.Context, tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow otp.SendFlow, id identity.CommandID) (identity.Command, issuanceCustody, nativeFlow, error) {
	bad := func(err error) (identity.Command, issuanceCustody, nativeFlow, error) {
		return identity.Command{}, issuanceCustody{}, nativeFlow{}, err
	}
	kind, flowID, bearer, err := flow.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	b := identity.CommandBinding{TenantID: tenant, UserID: user, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind}
	subject := identity.FeatureSubjectUser
	if user == "" {
		subject = identity.FeatureSubjectAnonymousFlow
		b.AnonymousFlowID = flowID
	}
	q := checkQuery(b, id, "identity.otp.send", true)
	record, err := s.source.QueryPreparedFeature(ctx, q, s.planCaller(caller, q), kernel.FeatureRegistration{Contributor: s.sender.owner.Descriptor(), Operation: issuanceOperation(subject)}, s.sender.owner)
	if err != nil {
		return bad(err)
	}
	defer clear(record.InputCiphertext)
	defer clear(record.OutputCiphertext)
	input, err := s.sender.owner.store.restoreSendInitiation(ctx, record.InputBinding, record.InputCiphertext, bearer)
	if err != nil || input.suppressed {
		if err == nil {
			err = identity.ForbiddenError{}
		}
		return bad(err)
	}
	// Actual possession does not authorize selecting another original flow that
	// happens to share a token representation. Check the explicit variant and ID.
	continuation, _ := input.request.continuation.Bindings()
	if kind == otp.FlowAuthorizationAuthenticatedSession {
		original, ok := continuation.Authorization.AuthenticatedSession()
		if !ok {
			return bad(identity.ForbiddenError{})
		}
		v, e := original.Bindings()
		if e != nil || v.SessionID != flowID {
			return bad(identity.ForbiddenError{})
		}
	} else {
		original, ok := continuation.Authorization.PreAuthTransaction()
		if !ok {
			return bad(identity.ForbiddenError{})
		}
		v, e := original.Bindings()
		if e != nil || string(v.Binding.ID) != flowID {
			return bad(identity.ForbiddenError{})
		}
	}
	original, err := s.sender.owner.mapInitiatedSend(ctx, input)
	if err != nil {
		return bad(err)
	}
	generated, _, err := s.sender.owner.RestoreFeaturePreparation(ctx, original, record.OutputGeneration, record.OutputCiphertext)
	if err != nil {
		return bad(err)
	}
	custody, native, err := s.sender.owner.store.authenticateIssuance(ctx, generated)
	if err != nil {
		return bad(err)
	}
	return generated, custody, native, nil
}

func (s *CheckService) requireCurrent(ctx context.Context, b identity.CommandBinding, expected AttemptAuthority, flow nativeFlow) error {
	p := s.sender.owner.store
	current, err := p.readInitiatingAuthority(ctx, b)
	if err != nil {
		return err
	}
	// The initiating reader intentionally selects no credential. Compare every
	// user/directory epoch first, then check the exact original optional reference.
	withoutCredential := expected
	withoutCredential.Credential = identity.CredentialRef{}
	if current != withoutCredential {
		return identity.ForbiddenError{}
	}
	if err := requireNativeFlow(ctx, s.sender.pool.Raw(), p, flow, nil); err != nil {
		return err
	}
	var now time.Time
	if err := s.sender.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return custodyFailure(ctx)
	}
	if expected.Credential != (identity.CredentialRef{}) {
		credential, err := p.initiation.kernel.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: b.UserID, CredentialID: expected.Credential.ID})
		if err != nil {
			return err
		}
		// Sample after the read; a slow read cannot extend credential validity.
		if err := s.sender.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return custodyFailure(ctx)
		}
		if identity.CheckCredentialAuthority(credential, expected.Credential, expected.CredentialAuthorityVersion, now) != nil {
			return identity.ForbiddenError{}
		}
	}
	if p.flowTime(flow, now) != nil {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (s *CheckService) checkPlan(command identity.Command, attempt kernel.OTPAttemptPlan) (kernel.CommandPlan, error) {
	return otpFeaturePlan(s.registry, s.sender.owner.store, command, attempt, "otp_check", "otp.check", "otp.checked.v1")
}

func otpFeaturePlan(registry *kernel.ContributorRegistry, owner *Contributor, command identity.Command, attempt kernel.OTPAttemptPlan, subject, action, event string) (kernel.CommandPlan, error) {
	spec, ok := command.Feature()
	if !ok {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	b := spec.Binding
	target := string(b.UserID)
	if target == "" {
		target = b.AnonymousFlowID
	}
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	// Only structural audit binding is computed here. The kernel materializes
	// actual audit time/identity/outcome inside its sole counted transaction.
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	builder, err := audit.NewBuilder(audit.BuilderConfig{Clock: func() time.Time { return when }, IDGenerator: func() (string, error) { return "otp-check-binding", nil }})
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: when, Action: action, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, subject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: spec.Operation}, SubjectType: subject, OTP: &attempt, Lifecycle: &kernel.LifecyclePlan{EventType: event}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected"}}}, nil
}

func (CheckConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.CheckConfig(redacted)"))
}
func (CheckConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (CheckConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (CheckConfig) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.CheckConfig(redacted)")
}
func (CheckService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.CheckService(redacted)"))
}
func (CheckService) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (CheckService) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (CheckService) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.CheckService(redacted)")
}

var _ otp.CheckService = (*CheckService)(nil)
