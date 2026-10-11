package passwordpostgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// PasswordChangeConfig selects signed-original verification, maximum proof age,
// HIBP screening and the existing native protected counter owner. Audience must
// match an explicitly allowlisted password verification target on Source.
// MaximumAge is positive and at most 15 minutes. Screening uses Source's exact
// primitive and trusted clock. History is disabled; current-password reuse is
// always denied. SessionDisposition and MaximumSessions freeze trusted startup
// policy in each original command; they are not request-selectable. Zero selects
// revoke-all and a whole-set cap of 100000, preserving strict invalidation.
// Explicit preservation supports the source's single-factor password profile.
type PasswordChangeConfig struct {
	Audience           string
	MaximumAge         time.Duration
	Screening          password.HashPreparationConfig
	Counters           *riskpg.Repository
	SessionDisposition sessionpg.PasswordChangeSessionDisposition
	MaximumSessions    uint32
}

// PasswordChangeRequest borrows the original bearer, issued password-specific
// proof and new raw-byte secret. Caller and Network have trusted transport
// provenance. No request-selected user, session version, clock or assurance is
// accepted. Destroy Password after Change returns; it is not retained.
type PasswordChangeRequest struct {
	TenantID identity.TenantID
	Session  auth.BearerCredential
	Proof    auth.ReauthenticationProof
	Password primitive.Secret
	Caller   authorization.DecisionContext
	Network  string
}

// PasswordChangeResult reports the original journal outcome, never hash/proof
// material. A nonzero credential successor and AuthorityInvalidated are exposed
// only after known commit. AuthorityInvalidated refers to the predecessor
// credential authority; eligible sessions may continue against its successor.
// Unknown is not permission to resubmit a password;
// use Recover with the original command's exact non-secret scope.
type PasswordChangeResult struct {
	CommandID            identity.CommandID
	Outcome              identity.CommitOutcome
	CredentialVersion    uint64
	AuthorityInvalidated bool
}

// PasswordChangeService composes native password change over an immutable
// reauthentication source. It borrows its primary pool and owns no goroutines,
// retry loop or private transaction. Calls are concurrent-safe under configured
// dependencies. Install password migration4, native counter migrations and the
// session CSRF/OTP/credential-continuation/password-change histories first.
type PasswordChangeService struct {
	source    *ReauthenticationService
	c         PasswordChangeConfig
	validator *auth.AuthorityAuthenticator
	sessions  *sessionpg.PasswordChangeEffect
}

// NewPasswordChangeService validates trusted composition without IO or crypto.
// Its source must already own a valid password-only native configuration. The
// upstream validator remains the sole signed-proof validation engine. Neither
// structural proof validation nor this constructor grants mutation authority.
func NewPasswordChangeService(source *ReauthenticationService, c PasswordChangeConfig) (*PasswordChangeService, error) {
	if source == nil || !source.repository.configuredWriter() || source.sessions == nil || c.Counters == nil || c.MaximumAge <= 0 || c.MaximumAge > 15*time.Minute || !reauthenticationText(c.Audience, 256) || c.Screening.Primitive != source.c.Verifier.Primitive {
		return nil, password.ErrPasswordWork
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.password.change", Audience: c.Audience}
	if !slices.Contains(source.c.Targets, target) {
		return nil, password.ErrPasswordWork
	}
	c, err := passwordChangeSessionPolicy(c)
	if err != nil {
		return nil, err
	}
	sessions, err := sessionpg.NewPasswordChangeEffect(source.c.Session, source.c.Profile)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	c.Screening.Now = source.c.Verifier.Now
	if _, err := password.NewHashPreparer(c.Screening); err != nil {
		return nil, password.ErrPasswordWork
	}
	var keys []auth.AuthorityKey
	for id, key := range source.c.VerificationKeys {
		keys = append(keys, auth.AuthorityKey{ID: id, PublicKey: key})
	}
	validator, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: source.c.Issuer, Environment: source.c.Environment, Audience: c.Audience, Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: keys, EvidenceKeys: keys, Source: passwordProofSource{source.repository}, Clock: passwordProofClock{source.c.Verifier.Now}, ReadTimeout: min(source.c.Repository.MaximumDuration, 5*time.Second), ClockUncertainty: time.Millisecond, MaximumDelegationDepth: 1})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return &PasswordChangeService{source: source, c: c, validator: validator, sessions: sessions}, nil
}

func passwordChangeSessionPolicy(c PasswordChangeConfig) (PasswordChangeConfig, error) {
	if c.SessionDisposition == 0 {
		c.SessionDisposition = sessionpg.PasswordChangeRevokeAllSessions
	}
	if c.MaximumSessions == 0 {
		c.MaximumSessions = 100000
	}
	if c.SessionDisposition < sessionpg.PasswordChangePreserveSessions || c.SessionDisposition > sessionpg.PasswordChangeRevokeAllSessions || c.MaximumSessions > 100000 {
		return PasswordChangeConfig{}, password.ErrPasswordWork
	}
	return c, nil
}

// Only the existing password source is selectable. Unused authority methods
// fail closed: this private composition cannot validate access/permanent login.
type passwordProofSource struct{ *Repository }

func (passwordProofSource) CurrentValidity(context.Context, auth.ValidityRequest) (auth.SignedValidityEvidence, error) {
	return auth.SignedValidityEvidence{}, auth.ErrInvalidProof
}
func (passwordProofSource) PermanentAuthentication(context.Context, auth.ProofID) (auth.SignedAuthenticationRecord, error) {
	return auth.SignedAuthenticationRecord{}, auth.ErrInvalidProof
}

type passwordProofClock struct{ now func() time.Time }

func (c passwordProofClock) Now() time.Time { return c.now() }

// Change validates the signed original proof and source bearer, denies current
// password reuse, screens HIBP and hashes before opening Work. Original provider
// facts remain frozen and are reassessed under primary time; no network callback
// runs under SQL locks. Counter charging, exact proof consumption, material and
// kernel reference/authority updates, audit/outbox share the sole transaction.
// A rollback leaves proof consumption rolled back; the original charged risk
// attempt is not refunded. Earlier caller deadlines and original proof/signal
// expiry bound the entire operation, including commit. Infrastructure/panics
// redact; cancellation is preserved without rewriting durable outcomes.
func (s *PasswordChangeService) Change(ctx context.Context, r PasswordChangeRequest) (result PasswordChangeResult, err error) {
	if s == nil || s.source == nil || ctx == nil {
		return result, password.ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, s.source.c.Repository.MaximumDuration)
	defer cancel()
	var stopEvidence context.CancelFunc
	defer func() {
		// Inspect the active deadline before our own cleanup cancels it. The
		// original evidence bound can expire while the outer request is live.
		if stopEvidence != nil {
			defer stopEvidence()
		}
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if cause := ctx.Err(); cause != nil {
			err = cause
		}
		if err != nil {
			result.CredentialVersion, result.AuthorityInvalidated = 0, false
		}
	}()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	original, err := s.source.lookup(ctx, r.TenantID, r.Session)
	if err != nil {
		return result, err
	}
	bindings, err := original.Bindings()
	if err != nil {
		return result, password.ErrPasswordWork
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return result, password.ErrPasswordWork
	}
	op := replacementOperation()
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: bindings.UserID, ActorID: identity.ActorID(bindings.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "identity-password", PolicyVersion: s.source.c.Coordinator.AdmissionPolicy.PolicyVersion, RecordID: bindings.Authentication.CredentialID, CorrelationID: string(id)}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: op.OperationID, Audience: s.c.Audience}
	if err = s.source.authorize(ctx, r.Caller, b, target); err != nil {
		return result, err
	}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(b.TenantID), Subject: string(b.UserID), Purpose: target.Purpose, Audience: target.Audience}, SessionID: bindings.SessionID, SessionVersion: bindings.Version, Action: op.OperationID, MaximumAge: s.c.MaximumAge}
	if err = s.validator.ValidateReauthenticationProof(ctx, r.Proof, use); err != nil {
		return result, identity.ForbiddenError{}
	}
	record, err := s.source.repository.Reauthentication(ctx, r.Proof.Proof.ID)
	if err != nil || record.Proof != r.Proof || record.Issuer != s.source.c.Issuer || record.Environment != s.source.c.Environment || record.CredentialID != b.RecordID || record.CredentialVersion != original.EffectiveCredentialVersion() {
		return result, identity.ForbiddenError{}
	}
	material, err := s.source.repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: b.TenantID, SubjectID: b.UserID})
	if err != nil {
		return result, readerFailure(ctx)
	}
	verifierConfig := s.source.c.Verifier
	verifierConfig.Repository = s.source.repository
	verifier, err := password.NewPasswordVerifier(verifierConfig)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	reused, err := verifier.VerifyPassword(ctx, password.VerifyPasswordRequest{TenantID: b.TenantID, SubjectID: b.UserID, Password: r.Password})
	if err != nil {
		return result, err
	}
	if reused.Matched {
		return result, identity.ForbiddenError{}
	}
	now := s.source.c.Verifier.Now().UTC()
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(op.OperationID), Attempt: string(id)}
	var facts []risk.Signal
	screening := s.c.Screening
	collect := screening.Collect
	screening.Collect = func(ctx context.Context, c risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		found, e := collect(ctx, c, candidate)
		if e == nil {
			facts = slices.Clone(found)
		}
		return found, e
	}
	preparer, err := password.NewHashPreparer(screening)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	hash, err := s.prepareChangeHash(ctx, preparer, r.Password, scope)
	if err != nil {
		return result, err
	}
	// The original expiry limits Work and COMMIT as well as native lock-time
	// checks. Repeated reads/preparation cannot restart this remaining interval.
	until := r.Proof.Proof.ExpiresAt
	if maximum := r.Proof.Proof.IssuedAt.Add(s.c.MaximumAge); maximum.Before(until) {
		until = maximum
	}
	for _, f := range facts {
		if f.ExpiresAt.Before(until) {
			until = f.ExpiresAt
		}
	}
	remaining := until.Sub(s.source.c.Verifier.Now())
	if remaining <= 0 {
		return result, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, remaining)
	stopEvidence = stop
	ctx = bounded
	a := material.Authority()
	phase := &passwordChangePhase{service: s, original: original, material: material, record: record, facts: facts, scope: scope, use: use, intent: kernel.CredentialReplacementIntent{Credential: a.Credential, ExpectedUserVersion: a.User.Version, ExpectedAuthorityVersion: a.AuthorityVersion}}
	fields, err := kernel.CredentialReplacementFields(phase.intent)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	sessionFields, err := sessionpg.PasswordChangeSessionFields(original, s.c.SessionDisposition, s.c.MaximumSessions)
	if err != nil {
		return result, err
	}
	fields = append(fields, sessionFields...)
	command, err := identity.NewFeaturePasswordChangeCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, hash.String(), r.Session, r.Proof)
	if err != nil {
		return result, err
	}
	var primary time.Time
	if err = s.source.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&primary); err != nil {
		return result, readerFailure(ctx)
	}
	command, counterPlan, err := s.c.Counters.PrepareCommandCounters(command, risk.Subject{User: string(b.UserID), Session: bindings.SessionID, Network: r.Network}, primary.UTC())
	if err != nil {
		return result, password.ErrPasswordWork
	}
	phase.expected = command
	coordinator, registry, err := s.coordinator(phase)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	plan, err := passwordChangePlan(coordinator, registry, phase, b, command, counterPlan, now)
	if err != nil {
		return result, err
	}
	result.CommandID = id
	reservation, receipt, err := coordinator.ReserveCommand(ctx, b, command, plan)
	result.Outcome = receipt.Outcome
	if cause := ctx.Err(); cause != nil {
		err = cause
	}
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return result, err
	}
	defer coordinator.Abort(w, identity.UnavailableError{})
	receipt, err = coordinator.ApplyFeature(ctx, w, command)
	if err == nil {
		receipt, err = coordinator.Commit(w, receipt)
	} else {
		receipt, err = coordinator.Abort(w, err)
	}
	result.Outcome = receipt.Outcome
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted && receipt.Feature != nil {
		result.CredentialVersion, result.AuthorityInvalidated = receipt.Feature.AfterVersion, true
	}
	return result, err
}

// Only trusted policy composition selects provider-only preparation. Existing
// profiles without a velocity signal retain their complete assessment; both
// paths still require the native counters in the protected command plan.
func (s *PasswordChangeService) prepareChangeHash(ctx context.Context, preparer *password.HashPreparer, candidate primitive.Secret, scope risk.Context) (primitive.EncodedHash, error) {
	admission, err := s.c.Screening.Policy.Admit(scope.Operation)
	if err != nil {
		return primitive.EncodedHash{}, err
	}
	if slices.Contains(admission.Profile.RequiredSignals, "velocity") {
		hash, _, err := preparer.PrepareProtected(ctx, candidate, scope)
		return hash, err
	}
	hash, _, err := preparer.Prepare(ctx, candidate, scope)
	return hash, err
}

func (s *PasswordChangeService) assessChangeProviders(ctx context.Context, scope risk.Context, facts []risk.Signal) (risk.Decision, error) {
	admission, err := s.c.Screening.Policy.Admit(scope.Operation)
	if err != nil {
		return risk.Decision{}, err
	}
	if slices.Contains(admission.Profile.RequiredSignals, "velocity") {
		assessment, err := s.c.Screening.Policy.AssessProtectedProviders(ctx, scope, facts)
		return assessment.Decision, err
	}
	assessment, err := s.c.Screening.Policy.Assess(ctx, scope, facts)
	return assessment.Decision, err
}

func (s *PasswordChangeService) coordinator(phase kernel.FeatureExecutionContributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	domain, err := kernel.NewRepository(s.source.pool, kernel.Config{MaximumDuration: s.source.c.Repository.MaximumDuration})
	if err != nil {
		return nil, nil, err
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle, phase, s.c.Counters})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.source.pool, registry, s.source.c.Coordinator)
	return coordinator, registry, err
}

// Recover resolves only the original exact journal scope under current
// disclosure policy. No password, bearer, new provider evaluation or proof
// resubmission is accepted; original successors come from the committed receipt.
func (s *PasswordChangeService) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (result PasswordChangeResult, err error) {
	if s == nil || s.source == nil || ctx == nil || q.OperationID != "identity.password.change" || q.UserID != identity.UserID(caller.Request.Subject.ID) || q.ActorID != identity.ActorID(caller.Request.Subject.ID) || q.ActorKind != authorization.SubjectUser {
		return result, password.ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, s.source.c.Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			result.CredentialVersion, result.AuthorityInvalidated = 0, false
		}
	}()
	coordinator, _, err := s.coordinator(&passwordChangePhase{service: s})
	if err != nil {
		return result, password.ErrPasswordWork
	}
	caller = caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.source.c.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Tenant, caller.Request.Action = authorization.TenantID(q.TenantID), authorization.Action(q.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}
	receipt, err := coordinator.RecoverCommand(ctx, q, caller)
	if receipt.Feature != nil {
		result.CommandID, result.Outcome = q.CommandID, receipt.Outcome
		if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
			var version string
			id, decodeErr := base64.RawURLEncoding.Strict().DecodeString(string(q.CommandID))
			if decodeErr != nil {
				return result, password.ErrPasswordWork
			}
			if e := s.source.pool.Raw().QueryRow(ctx, `SELECT after_version::text FROM identity_password.replacements WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND command_id=$4 AND purpose=$5`, string(q.TenantID), string(q.UserID), q.RecordID, id, q.OperationID).Scan(&version); e != nil {
				return result, readerFailure(ctx)
			}
			v, e := canonicalVersion(version)
			if e != nil {
				return result, password.ErrPasswordWork
			}
			result.CredentialVersion, result.AuthorityInvalidated = v, true
		}
	}
	return result, err
}

func (PasswordChangeConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.PasswordChangeConfig(redacted)")
}
func (PasswordChangeRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.PasswordChangeRequest(redacted)")
}
func (*PasswordChangeService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.PasswordChangeService(redacted)")
}
func (PasswordChangeConfig) MarshalJSON() ([]byte, error)  { return nil, password.ErrPasswordWork }
func (PasswordChangeRequest) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
