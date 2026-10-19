package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// SigninConfig explicitly composes single-factor OTP login over an initialized
// SendService. Session selects the installed session namespace. Profile fixes
// its audience and authority owners; Issuer owns lookup, clock and cookie policy.
// CSRFKey is required and independent of both lookup and pre-auth keys.
// Coordinator requires current QueryPolicy and AdmissionPolicy (the latter
// defaults to QueryPolicy). Its authorizer MUST authoritatively deny the proposed
// single-factor profile when additional factors apply. Reserved authentication
// attributes are service-owned, never caller assertions. No policy engine,
// factor store or application workflow callback is accepted here.
type SigninConfig struct {
	// RequireKnownEmptyFactors selects native MFA-owner admission in addition
	// to authorization policy. Missing/enrolled state denies; the original
	// generation is authenticated in custody and fenced in protected phases.
	// False preserves policy-only consumers, whose policy must enforce factors.
	// Neither mode enables MFA continuation.
	RequireKnownEmptyFactors bool
	Coordinator              kernel.CoordinatorConfig
	CurrentAttemptKeyVersion uint32
	Session                  sessionpg.Config
	Profile                  sessionpg.OTPAdmissionConfig
	Issuer                   session.IssuerConfig
	CSRFKey                  session.CSRFKey
}

// SigninService borrows the sender's primary pool and immutable native owners.
// It owns no goroutines, journal, schema, external store or shutdown resource.
// Calls are concurrent-safe; caller contexts and the sender timeout bound all
// work. Each Signin is a new submission; only RecoverSignin recovers ambiguity.
// MFA continuation is not implemented by this single-factor profile.
type SigninService struct {
	sender        *SendService
	source        *CheckService
	owner         *Contributor
	registry      *kernel.ContributorRegistry
	coordinator   *kernel.Coordinator
	sessions      *sessionpg.Repository
	issuer        *session.SessionIssuer
	attemptIssuer otp.AttemptIssuer
	policy        kernel.CommandQueryPolicy
	queryPolicy   kernel.CommandQueryPolicy
}

// NewSigninService performs structural startup validation without IO or policy
// callbacks. Install consuming OTP, pre-auth release, session revocation/issuance,
// CSRF, OTP record and OTP issuance migrations first. The sender and borrowed
// services must outlive calls; their immutable revision/key contracts survive
// restart. This constructor enables no HTTP route or automatic migration.
func NewSigninService(sender *SendService, c SigninConfig) (*SigninService, error) {
	if sender == nil || sender.owner == nil || sender.owner.store == nil || sender.owner.store.initiation == nil || c.Coordinator.QueryPolicy == nil || c.Issuer.MaximumDuration > sender.timeout || c.Session.MaximumDuration > sender.timeout {
		return nil, ErrInvalidConfiguration
	}
	if c.Coordinator.AdmissionPolicy == nil {
		policy := *c.Coordinator.QueryPolicy
		c.Coordinator.AdmissionPolicy = &policy
	}
	source, err := NewCheckService(sender, CheckConfig{Coordinator: c.Coordinator, CurrentAttemptKeyVersion: c.CurrentAttemptKeyVersion})
	if err != nil {
		return nil, err
	}
	owner, err := newSigninContributor(sender.owner.store, c.Session, c.Profile)
	if err != nil {
		return nil, err
	}
	owner.signin.knownEmptyFactors = c.RequireKnownEmptyFactors
	if owner.signin.phone {
		owner.signin.knownEmptyFactors = true
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
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, audits, lifecycle, owner})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	coordinator, err := kernel.NewCoordinator(sender.pool, registry, c.Coordinator)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	sessions, err := sessionpg.NewRepository(sender.pool, c.Session)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	s := &SigninService{sender: sender, source: source, owner: owner, registry: registry, coordinator: coordinator, sessions: sessions, attemptIssuer: source.issuer, policy: *c.Coordinator.AdmissionPolicy, queryPolicy: *c.Coordinator.QueryPolicy}
	s.issuer, err = session.NewOTPSessionIssuerWithCSRF(signinExecutor{s}, c.Issuer, c.CSRFKey)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	return s, nil
}

// Signin authenticates original public Send possession and current policy,
// allocates server-owned attempt/session identities, then atomically consumes
// OTP/pre-auth with session, audit, outbox and receipt. The session owner alone
// reveals credentials after exact new commitment. Wrong submissions are charged
// once; ambiguous results retain code-free Recovery without any credential.
func (s *SigninService) Signin(ctx context.Context, r otp.SigninRequest) (result otp.SigninResult, err error) {
	if ctx == nil || s == nil || s.sender == nil {
		return result, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.sender.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			result.Issuance.Token = session.Token{}
			result.CSRFToken = session.CSRFToken{}
			result.Issuance.Cookie.Value = ""
			err = ErrUnavailable
		}
	}()
	originalCommand, custody, flow, err := s.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return result, err
	}
	spec, _ := originalCommand.Feature()
	issued, err := custody.challenge.Bindings()
	if err != nil || custody.recipient == nil {
		return result, identity.ForbiddenError{}
	}
	if err := s.owner.requireSigninRecipient(*custody.recipient); err != nil {
		return result, err
	}
	continuation, _ := issued.Continuation.Bindings()
	if continuation.Scope.Purpose != otp.PurposeSignin {
		return result, identity.ForbiddenError{}
	}
	if err := s.source.requireCurrent(ctx, spec.Binding, custody.authority, flow); err != nil {
		return result, err
	}
	spec.Operation = s.owner.signin.operation(spec.Operation.SubjectRequirement)
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.RecordID = spec.Operation.OperationID, spec.Operation.SchemaID, ""
	spec.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		return result, ErrUnavailable
	}
	spec.Binding.CorrelationID = string(spec.Binding.CommandID)
	spec.Fields = nil
	q := checkQuery(spec.Binding, spec.Binding.CommandID, string(spec.Operation.OperationID), false)
	caller := s.source.planCaller(r.Caller, q)
	caller.PolicyRevision = authorization.Revision(s.policy.PolicyVersion)
	admission, err := s.coordinator.ObserveCommandAdmission(ctx, q, caller)
	if err != nil {
		return result, err
	}
	if !admission.Absent {
		return result, identity.ForbiddenError{}
	}
	// Observe the selected user's epoch BEFORE evaluation. A later protected
	// comparison rejects a policy change rather than adopting a newer epoch.
	factorVersion, err := s.readSigninFactors(ctx, *custody.recipient)
	if err != nil {
		return result, err
	}
	authority, err := s.authorizeRecipient(ctx, r.Caller, *custody.recipient, false)
	if err != nil {
		return result, err
	}
	ds, _ := issued.Continuation.DigestScope()
	scope, err := s.owner.codec.verifier.ScopeDigest(ds, issued.Digest.KeyVersion)
	if err != nil {
		return result, ErrInvalidCommand
	}
	var versionText string
	schema := pgx.Identifier{s.owner.schema}.Sanitize()
	if err := s.sender.pool.Raw().QueryRow(ctx, `SELECT version::text FROM `+schema+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4`, string(r.TenantID), string(r.SendCommandID), int64(issued.Digest.KeyVersion), scope.Value[:]).Scan(&versionText); err != nil {
		return result, custodyFailure(ctx)
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != versionText {
		return result, ErrUnavailable
	}
	attempt, err := s.attemptIssuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, issued.Continuation, otp.AttemptModeConsume, version, r.Code)
	if err != nil {
		return result, err
	}
	ab, _ := attempt.Bindings()
	recovery, _ := attempt.Recovery()
	result.Recovery, err = otp.NewSigninRecovery(otp.SigninRecoveryBindings{SendCommandID: r.SendCommandID, Attempt: recovery, ExpectedVersion: version, DigestKeyVersion: issued.Digest.KeyVersion, ScopeDigest: scope.Value})
	if err != nil {
		return otp.SigninResult{}, err
	}
	recordSpec, metadata, err := s.prepareSession(ctx, spec.Binding, custody, ab, authority)
	if err != nil {
		return result, err
	}
	prepared, err := s.issuer.PrepareOTP(spec.Binding, recordSpec, metadata)
	if err != nil {
		return result, err
	}
	record, _ := prepared.Session()
	_, _, cookie, _ := r.Flow.Bindings()
	command, _, err := s.owner.codec.mapSigninCommand(ctx, attempt, issued.Digest.KeyVersion, spec, cookie, custody, record, factorVersion)
	if err != nil {
		return result, err
	}
	prepared, err = s.issuer.BindOTP(prepared, command)
	if err != nil {
		return result, err
	}
	result.Issuance, err = s.issuer.Issue(ctx, prepared)
	if result.Issuance.CommitOutcome == identity.CommitOutcomeCommitted {
		stored, e := result.Issuance.Session.Bindings()
		if e == nil {
			result.SessionID = stored.SessionID
		}
	}
	if err == nil && result.Issuance.CommitOutcome == identity.CommitOutcomeCommitted && !result.Issuance.Replayed {
		result.CSRFToken, err = prepared.CSRFToken()
	}
	return result, err
}

func (s *SigninService) readSigninFactors(ctx context.Context, recipient kernel.RecipientRecord) (uint64, error) {
	if !s.owner.signin.knownEmptyFactors {
		return 0, nil
	}
	state, err := mfapg.ReadOTPSigninFactors(ctx, s.sender.pool, recipient.Query.TenantID, recipient.User.ID, min(s.sender.timeout, 5*time.Second))
	if err != nil {
		return 0, err
	}
	return state.Version(), nil
}

// authorizeRecipient uses the existing policy engine, not a new MFA flag or
// policy service. Its resource is the actual original recipient while Subject
// remains the initiating actor. Authentication attributes describe a PROPOSED
// single-factor session, never a successful check or caller-provided assurance.
func (s *SigninService) authorizeRecipient(ctx context.Context, caller authorization.DecisionContext, recipient kernel.RecipientRecord, history bool) (uint64, error) {
	if recipient.Validate() != nil || recipient.Suppressed {
		return 0, identity.ForbiddenError{}
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(recipient.Query.TenantID), SubjectID: authorization.SubjectID(recipient.User.ID), PolicyNamespace: s.owner.namespace}
	observed, err := s.owner.initiation.authorization.Get(ctx, scope)
	if err != nil {
		return 0, custodyFailure(ctx)
	}
	c := caller.Clone()
	policy := s.policy
	if history {
		policy = s.queryPolicy
	}
	c.PolicyRevision = authorization.Revision(policy.PolicyVersion)
	c.Request.Tenant = scope.TenantID
	c.Request.Action = authorization.Action(s.owner.signin.operation(identity.FeatureSubjectAnonymousFlow).OperationID)
	if history {
		c.Request.Action += ".recover"
	}
	c.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(recipient.User.ID)}
	// Strip every reserved namespace from every caller-controlled attribute map.
	for _, attrs := range []authorization.Attributes{c.Request.Attributes, c.Request.Subject.Attributes, c.Request.Environment.Attributes} {
		for key := range attrs {
			if strings.HasPrefix(string(key), "identity.authentication.") {
				delete(attrs, key)
			}
		}
	}
	if c.Request.Attributes == nil {
		c.Request.Attributes = authorization.Attributes{}
	}
	c.Request.Attributes["identity.authentication.method"] = authorization.StringValue("otp")
	c.Request.Attributes["identity.authentication.profile"] = authorization.StringValue("single-factor")
	c.Request.Attributes["identity.authentication.phase"] = authorization.StringValue("proposed")
	c.Request.Attributes["identity.authentication.factor-count"] = authorization.IntValue(1)
	decision, err := policy.Authorization.Decide(ctx, c)
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != c.PolicyRevision {
		return 0, identity.ForbiddenError{}
	}
	return observed.Version, nil
}

func (s *SigninService) prepareSession(ctx context.Context, b identity.CommandBinding, custody issuanceCustody, attempt otp.AttemptBindings, authorizationVersion uint64) (session.SessionSpec, session.OTPAuthentication, error) {
	fail := func() (session.SessionSpec, session.OTPAuthentication, error) {
		return session.SessionSpec{}, session.OTPAuthentication{}, ErrInvalidCommand
	}
	r := *custody.recipient
	issued, _ := custody.challenge.Bindings()
	continuation, _ := issued.Continuation.Bindings()
	preauth, ok := continuation.Authorization.PreAuthTransaction()
	if !ok {
		return fail()
	}
	flow, _ := preauth.Bindings()
	var now time.Time
	if err := s.sender.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return fail()
	}
	until := issued.ExpiresAt
	if flow.Binding.ExpiresAt.Before(until) {
		until = flow.Binding.ExpiresAt
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return fail()
	}
	family, err := identity.NewCommandID()
	if err != nil {
		return fail()
	}
	keys, err := kernel.KernelAuthorityKeys(custody.authority.Directory.Query, r.User.ID)
	if err != nil {
		return fail()
	}
	sk, err := sessionpg.SessionAuthorityKeys(b.TenantID, r.User.ID, string(family), string(id))
	if err != nil {
		return fail()
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: s.owner.namespace, SubjectID: authorization.SubjectID(r.User.ID)}
	key, err := scope.Key()
	if err != nil {
		return fail()
	}
	bind := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	d := custody.authority.Directory
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(keys.Global, d.GlobalVersion), Tenant: bind(keys.Tenant, d.TenantVersion), User: bind(keys.User, r.UserAuthorityVersion), Identifier: bind(keys.Identifier, r.IdentifierAuthorityVersion), Credential: bind(keys.Credential, r.CredentialAuthorityVersion), Session: bind(sk.Session, 1), SessionFamily: bind(sk.Family, 1), Authorization: bind(key, authorizationVersion)})
	if err != nil {
		return fail()
	}
	metadata, err := session.NewOTPAuthentication(session.OTPAuthenticationSpec{CommandID: b.CommandID, SendCommandID: identity.CommandID(continuation.Scope.ChallengeID), ChallengeID: continuation.Scope.ChallengeID, AttemptID: string(attempt.AttemptID), IdentifierID: r.Identifier.ID, IdentifierKind: r.Identifier.Kind, IdentifierVersion: r.Identifier.Version, VerificationVersion: r.Verification.Version, AuthenticatedAt: now, ValidUntil: until})
	if err != nil {
		return fail()
	}
	return session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: b.TenantID, UserID: r.User.ID, Audience: s.owner.signin.profile.Audience, Version: 1, FamilyVersion: 1, Remember: continuation.RememberPolicy, Authority: vector, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationOTP}, IssuedAt: now, LastActivityAt: now}, metadata, nil
}

type signinExecutor struct{ service *SigninService }

func (e signinExecutor) ExecuteIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	s := e.service
	command, record, ok := request.OTPCommand()
	if !ok || s == nil {
		return session.IssueExecution{}, ErrInvalidCommand
	}
	f, _ := command.Feature()
	custody, err := s.owner.codec.restoreCustody(f)
	if err != nil {
		return session.IssueExecution{}, err
	}
	var version uint32
	for _, field := range f.Fields {
		if field.Name == "otp.digest-key-version" {
			version = uint32(field.Value.Uint64)
		}
	}
	attempt, err := s.owner.codec.recordPlan(custody.record, version)
	if err != nil {
		return session.IssueExecution{}, err
	}
	plan, err := otpFeaturePlan(s.registry, s.owner, command, attempt, "otp_signin", s.owner.signin.auditEvent(), s.owner.signin.lifecycleEvent())
	if err != nil {
		return session.IssueExecution{}, err
	}
	plan, err = s.coordinator.PrepareOTPReservationPlan(f.Binding, command, plan)
	if err != nil {
		return session.IssueExecution{}, err
	}
	denial, err := s.coordinator.RecordOTPAttemptDenial(ctx, f.Binding, command, plan)
	var conflict identity.ConflictError
	if denial.Outcome != identity.CommitOutcomeConflict || !errors.As(err, &conflict) {
		return session.IssueExecution{Receipt: denial}, err
	}
	reserved, receipt, err := s.coordinator.ReserveOTPCommand(ctx, f.Binding, command, plan)
	if err != nil || reserved == (kernel.Reservation{}) {
		result := session.IssueExecution{Receipt: receipt, Replayed: true}
		if receipt.Outcome == identity.CommitOutcomeCommitted {
			result.Session = record
		}
		return result, err
	}
	w, err := s.coordinator.Begin(ctx, reserved)
	if err != nil {
		return session.IssueExecution{}, err
	}
	defer s.coordinator.Abort(w, identity.UnavailableError{})
	receipt, err = s.coordinator.ApplyFeature(ctx, w, command)
	if err == nil {
		receipt, err = s.coordinator.Commit(w, receipt)
	} else {
		receipt, err = s.coordinator.Abort(w, err)
	}
	result := session.IssueExecution{Receipt: receipt}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		result.Session = record
	}
	return result, err
}

// OTP issuer recovery is deliberately code-free and belongs to RecoverSignin.
func (signinExecutor) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, ErrInvalidCommand
}

// RecoverSignin authenticates original Send possession and current disclosure
// policy, matches every retained consuming correlation, and reconciles only
// through the sole kernel owner. Expired/consumed pre-auth flows and deleted live
// session payloads do not erase history. No code comparison, attempt charge,
// session creation, token generation or credential delivery occurs here.
func (s *SigninService) RecoverSignin(ctx context.Context, r otp.SigninRecoveryRequest) (result otp.SigninResult, err error) {
	if ctx == nil || s == nil || s.sender == nil {
		return result, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.sender.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			result = otp.SigninResult{}
			err = ErrUnavailable
		}
	}()
	b, _ := r.Recovery.Bindings()
	original, custody, _, err := s.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, b.SendCommandID)
	if err != nil {
		return result, err
	}
	f, _ := original.Feature()
	issued, _ := custody.challenge.Bindings()
	continuation, _ := issued.Continuation.Bindings()
	if custody.recipient == nil || continuation.Scope.Purpose != otp.PurposeSignin {
		return result, identity.ForbiddenError{}
	}
	epoch, err := s.authorizeRecipient(ctx, r.Caller, *custody.recipient, true)
	if err != nil {
		return result, err
	}
	fingerprint, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.Attempt.Fingerprint))
	defer clear(fingerprint)
	plan := kernel.OTPAttemptPlan{AttemptID: string(b.Attempt.AttemptID), AttemptFingerprint: [32]byte(fingerprint), FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion, ChallengeID: string(b.SendCommandID), ScopeDigest: b.ScopeDigest, DigestKeyVersion: b.DigestKeyVersion, ExpectedVersion: b.ExpectedVersion, Mode: kernel.OTPConsume}
	q := checkQuery(f.Binding, b.Attempt.CommandID, string(s.owner.signin.operation(f.Operation.SubjectRequirement).OperationID), false)
	receipt, err := s.coordinator.RecoverOTPFeatureCommand(ctx, q, plan, s.source.planCaller(r.Caller, q))
	if receipt.Feature == nil {
		return result, err
	}
	var sessionID string
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		retained, e := s.sessions.ReadOTPSigninIdentity(ctx, receipt.Binding)
		if e != nil || retained.UserID != custody.recipient.User.ID {
			return result, ErrUnavailable
		}
		sessionID = retained.SessionID
	}
	current, e := s.authorizeRecipient(ctx, r.Caller, *custody.recipient, true)
	if e != nil {
		return result, e
	}
	if current != epoch {
		return result, identity.ForbiddenError{}
	}
	return otp.SigninResult{SessionID: sessionID, Recovery: r.Recovery, Issuance: session.IssueResult{CommandID: b.Attempt.CommandID, CommitOutcome: receipt.Outcome, Replayed: true, RetryAfter: receipt.RetryAfter}}, err
}

func (SigninConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("otp.postgres.SigninConfig(redacted)"))
}
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (SigninConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (SigninConfig) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.SigninConfig(redacted)")
}
func (*SigninService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("otp.postgres.SigninService(redacted)"))
}
func (*SigninService) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (*SigninService) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

var _ otp.SigninService = (*SigninService)(nil)
