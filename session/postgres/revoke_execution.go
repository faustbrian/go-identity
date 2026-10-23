package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// RevokeOneExecutorConfig selects the owned current single-factor execution
// profile and exact trusted session reader used for caller admission. Execution
// retains the existing policy, clock, audit and coordinator configuration; final
// signin proof composition is optional because revocation uses session custody.
// Install the kernel, authorization, session, revocation, audit and outbox
// migrations first. Dependencies are borrowed and must outlive calls.
type RevokeOneExecutorConfig struct {
	Execution IssueExecutorConfig
	Sessions  *session.SessionService
	// Admission explicitly enables native single-factor methods for caller and
	// target revocation. Nil retains the existing verified-only profile. Selected
	// deployment, namespace and audience must match Execution.Profile. The same
	// frozen selection must construct Sessions; configuration grants no authority.
	Admission *SingleFactorSessionAdmissionConfig
	// MFAMagicLink explicitly selects current confirmed TOTP authority for
	// magic-link source and target sessions. It never enables single-factor
	// fallback; the same profile must be selected by Sessions.
	MFAMagicLink *MagicLinkAdmissionConfig
	// MFAPassword retains current password credential and confirmed TOTP
	// authority for both caller and target. Select the identical native reader
	// profile; nil never downgrades an MFA session to single-factor admission.
	MFAPassword *IdentifierAdmissionConfig
	// Passkey selects the same trusted RP/current-authority port as the source
	// session reader. Nil keeps passkey callers/targets disabled; it never
	// converts their original factor/passkey dimensions into password authority.
	Passkey *PasskeySessionAdmission
}

// RevokeOneExecutor owns kernel/native/audit/outbox composition. It accepts no
// application stores, callbacks, transactions or command journals, starts no
// goroutines and is concurrency-safe. It authenticates original opaque caller
// custody and current policy before reservation. Historical receipts do not
// authenticate a caller. Public idempotent signout/absent handling is separate.
type RevokeOneExecutor struct {
	owned    *IssueExecutor
	sessions *session.SessionService
}

// NewRevokeOneExecutor validates trusted composition without IO. Sessions must
// be the exact configured reader that prepared each request, not a request-
// supplied substitute. It grants no permission to a structural mapped command.
func NewRevokeOneExecutor(pool *database.Pool, c RevokeOneExecutorConfig) (*RevokeOneExecutor, error) {
	if c.Sessions == nil {
		return nil, session.ErrInvalidInput
	}
	owned, err := newOwnedSessionExecution(pool, c.Execution, false)
	if err != nil {
		return nil, err
	}
	if c.Admission != nil {
		if _, _, err := singleFactorAdmission(*c.Admission); err != nil {
			return nil, err
		}
		selected := copySingleFactorAdmission(*c.Admission)
		profiles := []OTPAdmissionConfig{}
		if p := selected.Verified; p != nil {
			profiles = append(profiles, OTPAdmissionConfig{p.GlobalAuthorityID, p.PolicyNamespace, p.Audience})
		}
		if p := selected.OTP; p != nil {
			profiles = append(profiles, *p)
		}
		if p := selected.MagicLink; p != nil {
			profiles = append(profiles, OTPAdmissionConfig(*p))
		}
		base := c.Execution.Profile
		for _, p := range profiles {
			if p.GlobalAuthorityID != base.GlobalAuthorityID || p.PolicyNamespace != base.PolicyNamespace || p.Audience != base.Audience {
				return nil, session.ErrInvalidInput
			}
		}
		owned.native.revokeAdmission = &selected
	}
	if p := c.MFAMagicLink; p != nil {
		base := c.Execution.Profile
		if !OTPAdmissionConfig(*p).valid() || p.GlobalAuthorityID != base.GlobalAuthorityID || p.PolicyNamespace != base.PolicyNamespace || p.Audience != base.Audience {
			return nil, session.ErrInvalidInput
		}
		copied := *p
		owned.native.revokeMFAMagicLink = &copied
		if owned.native.revokeAdmission == nil {
			verified := IdentifierAdmissionConfig(base)
			owned.native.revokeAdmission = &SingleFactorSessionAdmissionConfig{Verified: &verified}
		}
	}
	if p := c.MFAPassword; p != nil {
		base := c.Execution.Profile
		if !p.valid() || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" || p.GlobalAuthorityID != base.GlobalAuthorityID || p.PolicyNamespace != base.PolicyNamespace || p.Audience != base.Audience {
			return nil, session.ErrInvalidInput
		}
		copied := *p
		owned.native.revokeMFAPassword = &copied
	}
	if p := c.Passkey; p != nil {
		base := c.Execution.Profile
		if !p.Profile.valid() || nilIssueDependency(p.Authority) || p.Profile.GlobalAuthorityID != base.GlobalAuthorityID || p.Profile.PolicyNamespace != base.PolicyNamespace || p.Profile.Audience != base.Audience {
			return nil, session.ErrInvalidInput
		}
		owned.native.revokePasskey = &passkeySessionSelection{freezePasskeyProfile(p.Profile), p.Authority}
	}
	return &RevokeOneExecutor{owned, c.Sessions}, nil
}

// ExecuteRevokeOne binds original source and target into one existing command.
// It checks opaque admission and current policy before reservation, then native
// primary source/target owner locks before mutation. The earlier caller budget,
// configured duration and original admission expiry bound the original Work and
// commit. Admission is checked again before Commit; audit/lifecycle failures
// roll back the same transaction. Replays return the retained original outcome,
// never a new transition. Panic, cancellation or lost commit acknowledgement do
// not prove rollback. Detached coordinator cleanup has its own bounded budget.
func (e *RevokeOneExecutor) ExecuteRevokeOne(ctx context.Context, request session.RevokeOneRequest) (result identity.CommandResult, err error) {
	return e.executeRevokeOne(ctx, request, nil)
}

// Eligible keys are supplied only by the strict owned factory on a fresh,
// invocation-private repository. The shared legacy executor cannot acquire
// token custody or silently turn a browser request into direct execution.
func (e *RevokeOneExecutor) executeRevokeOne(ctx context.Context, request session.RevokeOneRequest, keys []session.CSRFKey) (result identity.CommandResult, err error) {
	entered := false
	var b identity.CommandBinding
	defer func() {
		if recover() != nil {
			if entered {
				result = unknownRevokeResult(b)
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			} else {
				result = identity.CommandResult{}
				err = session.ErrUnavailable
			}
		}
	}()
	if ctx == nil || e == nil || e.owned == nil || e.sessions == nil {
		return result, session.ErrInvalidInput
	}
	token, csrf := request.CSRFToken()
	if csrf != (len(keys) > 0) {
		return result, session.ErrCSRFDenied
	}
	now := e.owned.clock.Now()
	if err = request.Validate(e.sessions, now); err != nil {
		return result, err
	}
	if csrf {
		key, err := selectRevokeCSRFKey(request.Caller(), token, keys)
		if err != nil {
			return result, err
		}
		e.owned.native.cookieRevoke = &revokeCSRFInput{token: token, key: key}
	}
	remaining := request.ValidUntil().Sub(now)
	budget := e.owned.maximumDuration
	if remaining < budget {
		budget = remaining
	}
	bounded, stop := context.WithTimeout(ctx, budget)
	defer stop()
	if bounded.Err() != nil {
		return result, readError(bounded, bounded.Err())
	}
	bounded, stopPrimary, err := e.primaryDeadline(bounded, request.ValidUntil())
	if err != nil {
		return result, err
	}
	defer stopPrimary()
	b, command, plan, caller, err := e.prepare(request)
	if err != nil {
		return result, err
	}
	if err = e.owned.allow(bounded, caller); err != nil {
		return result, err
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		return result, err
	}
	entered = true
	reservation, result, err := e.owned.coordinator.ReserveCommand(bounded, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	work, err := e.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		return unknownRevokeResult(b), err
	}
	defer e.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		return e.owned.coordinator.Abort(work, err)
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		return e.owned.coordinator.Abort(work, identity.ForbiddenError{})
	}
	return e.owned.coordinator.Commit(work, provisional)
}

// Convert the unchanged absolute caller deadline using primary time, not an
// application-clock offset. Anchor the timer before the bounded clock query so
// query/transport delay cannot add remaining validity. This child reaches the
// original coordinator Work and commit, including later audit/outbox phases.
// It only narrows the caller/configured budget; it does not refresh authority.
func (e *RevokeOneExecutor) primaryDeadline(ctx context.Context, until time.Time) (context.Context, context.CancelFunc, error) {
	read, cancelRead := context.WithTimeout(ctx, e.owned.native.maximumDuration)
	defer cancelRead()
	started := time.Now()
	var now time.Time
	if err := e.owned.native.pool.Raw().QueryRow(read, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, nil, readError(read, err)
	}
	if !sessionReadTime(now) {
		return nil, nil, session.ErrUnavailable
	}
	remaining := until.Sub(now)
	if remaining <= 0 {
		return nil, nil, session.ErrUnauthenticated
	}
	if remaining > e.owned.maximumDuration {
		remaining = e.owned.maximumDuration
	}
	bounded, stop := context.WithDeadline(ctx, started.Add(remaining))
	if bounded.Err() != nil {
		stop()
		return nil, nil, readError(bounded, bounded.Err())
	}
	return bounded, stop, nil
}

func unknownRevokeResult(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: session.RevokeOneOperation()}}
}

func (e *RevokeOneExecutor) prepare(request session.RevokeOneRequest) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
	fail := func(err error) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
		return identity.CommandBinding{}, identity.Command{}, kernel.CommandPlan{}, authorization.DecisionContext{}, err
	}
	native, ok := request.Command()
	one, targeted := native.RevokeOne()
	if !ok || !targeted {
		return fail(session.ErrInvalidSessionCommand)
	}
	b := one.Binding
	if b.PolicyID != e.owned.policyID || b.PolicyVersion != e.owned.policyVersion {
		return fail(identity.ForbiddenError{})
	}
	command, err := MapRevokeOneRequest(request)
	if err != nil {
		return fail(err)
	}
	spec, _ := one.Session.Bindings()
	op := session.RevokeOneOperation()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return fail(session.ErrUnavailable)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: e.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session", "aggregate.before_version": strconv.FormatUint(spec.Version, 10), "aggregate.after_version": strconv.FormatUint(spec.Version+1, 10), "retention.class": "standard"}})
	if err != nil {
		return fail(session.ErrUnavailable)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", record)
	if err != nil {
		return fail(err)
	}
	declaration := kernel.CommandPlan{Contributors: e.owned.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: e.owned.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: e.owned.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	plan, err := e.owned.coordinator.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		return fail(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(e.owned.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	return b, command, plan, caller, nil
}

// RecoverRevokeOneCommand observes the original command under current trusted
// result-access policy after restart, without original bearer/admission memory.
// Query must retain every original safe scope field; caller comes from current
// trusted authentication, never decoded client identity. Missing/denied results
// do not reserve commands. Recovery returns historical metadata only, never
// execution permission, a renewed validity lease or a reconstructed session.
func (e *RevokeOneExecutor) RecoverRevokeOneCommand(ctx context.Context, query identity.RecoveryQuery, caller authorization.DecisionContext) (kernel.CommandRecord, error) {
	if ctx == nil || e == nil || e.owned == nil {
		return kernel.CommandRecord{}, session.ErrInvalidInput
	}
	if query.OperationID != session.RevokeOneOperation().OperationID || !scopeID(query.RecordID) || query.LinkMode != 0 || query.ActorKind != authorization.SubjectUser || string(query.ActorID) != string(query.UserID) {
		return kernel.CommandRecord{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	result, err := e.owned.coordinator.RecoverCommand(bounded, query, caller)
	if result.Binding.CommandID != "" && (result.Feature == nil || *result.Feature != session.RevokeOneOperation()) {
		return kernel.CommandRecord{}, session.ErrUnavailable
	}
	return result, err
}

// Format prevents traversal of runtime dependency/credential configuration.
func (RevokeOneExecutor) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.RevokeOneExecutor(redacted)"))
}

// MarshalJSON rejects implicit runtime export.
func (RevokeOneExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts runtime profile and key configuration.
func (RevokeOneExecutorConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.RevokeOneExecutorConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (RevokeOneExecutorConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
