package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// ReauthenticationSigningKey holds immutable signing custody. It exposes no
// signing method or secret projection. Copies share immutable closure custody;
// the deployment owns key rotation and caller-buffer cleanup.
type ReauthenticationSigningKey struct {
	apply  func(auth.SignedReauthenticationRecord) (auth.SignedReauthenticationRecord, error)
	public func() (string, ed25519.PublicKey)
}

// NewReauthenticationSigningKey copies a complete, internally consistent
// Ed25519 private key and bounded key ID without IO. Keys must be independent
// from session lookup, password and risk material. Zero/malformed keys deny.
func NewReauthenticationSigningKey(id string, key ed25519.PrivateKey) (ReauthenticationSigningKey, error) {
	if !reauthenticationText(id, 128) || len(key) != ed25519.PrivateKeySize {
		return ReauthenticationSigningKey{}, password.ErrPasswordWork
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) {
		clear(derived)
		return ReauthenticationSigningKey{}, password.ErrPasswordWork
	}
	id = strings.Clone(id)
	return ReauthenticationSigningKey{public: func() (string, ed25519.PublicKey) {
		return id, ed25519.PublicKey(slices.Clone(derived[ed25519.SeedSize:]))
	}, apply: func(r auth.SignedReauthenticationRecord) (auth.SignedReauthenticationRecord, error) {
		r.KeyID, r.Signature = id, nil
		frame, err := r.SigningBytes()
		if err != nil {
			return auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
		}
		r.Signature = ed25519.Sign(derived, frame)
		return r, nil
	}}, nil
}

func (k ReauthenticationSigningKey) sign(r auth.SignedReauthenticationRecord) (auth.SignedReauthenticationRecord, error) {
	if k.apply == nil {
		return auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	return k.apply(r)
}
func (ReauthenticationSigningKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ReauthenticationSigningKey(redacted)")
}
func (ReauthenticationSigningKey) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (ReauthenticationSigningKey) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// ReauthenticationTarget is a startup allowlist entry. Purpose, Action and
// Audience must match exactly; requests cannot select expiry or assurance.
type ReauthenticationTarget struct {
	Purpose          auth.Purpose
	Action, Audience string
}

// ReauthenticationConfig composes native single-factor password verification.
// Verifier.Repository must be nil: this service supplies the primary adapter.
// Profile must select password/identity-password ownership. Targets are a closed
// allowlist, TTL is positive and at most 15 minutes. IdentifierKey is independent
// 32..64-byte HMAC material for abuse dimensions, not a password or lookup key.
// Coordinator policy, verifier clock, risk callbacks and pool must be safe for
// concurrent use. All configuration is trusted startup input, never HTTP input.
type ReauthenticationConfig struct {
	Repository  Config
	Verifier    password.VerifierConfig
	Session     sessionpg.Config
	Profile     sessionpg.IdentifierAdmissionConfig
	LookupKeys  []session.DigestKey
	Risk        risk.AuthenticationAdmissionCustodyConfig
	Coordinator kernel.CoordinatorConfig
	SigningKey  ReauthenticationSigningKey
	// VerificationKeys retain public keys for original outcome recovery across
	// signing rotation. Include the selected signing key's corresponding public
	// key; retirement must follow the original journal retention policy.
	VerificationKeys    map[string]ed25519.PublicKey
	Issuer, Environment string
	Targets             []ReauthenticationTarget
	TTL                 time.Duration
	IdentifierKey       []byte
}

// ReauthenticationRequest carries caller-owned ephemeral password and bearer
// custody. Tenant and Caller are trusted transport/policy composition. Network
// and Device require trusted proxy/device provenance; the identifier dimension
// is derived by the service. No user/session ID, time, assurance or lifetime is
// request-selectable. Destroy Password after the call; it is never retained.
type ReauthenticationRequest struct {
	TenantID        identity.TenantID
	Session         auth.BearerCredential
	Password        primitive.Secret
	Target          ReauthenticationTarget
	Caller          authorization.DecisionContext
	Network, Device string
}

// ReauthenticationResult reveals the sole upstream proof only after an exact
// new commit and final freshness checks. CommandID and Outcome survive ambiguous
// commit or failed delivery; callers must not automatically resubmit passwords.
// Verification neither consumes the proof nor creates/extends a session.
type ReauthenticationResult struct {
	Proof     auth.ReauthenticationProof
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
}

// ReauthenticationService borrows a primary-only pool and owns no goroutines,
// private transaction, retry loop or durable authority. Calls are concurrent-
// safe under configured dependency contracts. Close the pool after calls stop.
// Unsupported organization/factor/passkey/source-method profiles fail closed.
type ReauthenticationService struct {
	pool       *database.Pool
	repository *Repository
	sessions   *sessionpg.Repository
	c          ReauthenticationConfig
	custody    risk.AuthenticationAdmissionCustody
}

// NewReauthenticationService validates and freezes native composition without
// IO. Install kernel authority/command, authorization authority, session,
// password proof-record, native audit and outbox migrations before use. It
// creates no schema, route, session, credential or provider policy.
func NewReauthenticationService(pool *database.Pool, c ReauthenticationConfig) (*ReauthenticationService, error) {
	if c.Verifier.Repository != nil || c.Verifier.Now == nil || c.Coordinator.QueryPolicy == nil || c.SigningKey.apply == nil || !reauthenticationText(c.Issuer, 256) || !reauthenticationText(c.Environment, 128) || c.TTL <= 0 || c.TTL > 15*time.Minute || len(c.Targets) == 0 || len(c.Targets) > 32 || len(c.IdentifierKey) < 32 || len(c.IdentifierKey) > 64 || len(c.LookupKeys) == 0 || len(c.LookupKeys) > 16 || c.Profile.Validate() != nil || c.Profile.AuthenticationMethod != "password" || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" {
		return nil, password.ErrPasswordWork
	}
	seen := map[ReauthenticationTarget]bool{}
	for _, target := range c.Targets {
		if !reauthenticationText(string(target.Purpose), 128) || !reauthenticationText(target.Action, 128) || !reauthenticationText(target.Audience, 256) || seen[target] {
			return nil, password.ErrPasswordWork
		}
		seen[target] = true
	}
	if c.Coordinator.AdmissionPolicy == nil {
		p := *c.Coordinator.QueryPolicy
		c.Coordinator.AdmissionPolicy = &p
	}
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	c.IdentifierKey, c.Targets, c.LookupKeys = slices.Clone(c.IdentifierKey), slices.Clone(c.Targets), slices.Clone(c.LookupKeys)
	if len(c.VerificationKeys) == 0 || len(c.VerificationKeys) > 16 {
		return nil, password.ErrPasswordWork
	}
	keys := make(map[string]ed25519.PublicKey, len(c.VerificationKeys))
	for id, public := range c.VerificationKeys {
		if !reauthenticationText(id, 128) || len(public) != ed25519.PublicKeySize {
			return nil, password.ErrPasswordWork
		}
		keys[id] = slices.Clone(public)
	}
	c.VerificationKeys = keys
	if c.SigningKey.public == nil {
		return nil, password.ErrPasswordWork
	}
	keyID, public := c.SigningKey.public()
	if !bytes.Equal(public, c.VerificationKeys[keyID]) {
		return nil, password.ErrPasswordWork
	}
	probe, _ := session.ParseToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	versions := map[uint32]bool{}
	for _, key := range c.LookupKeys {
		digest, err := probe.Digest(key, "configuration-probe")
		if err != nil || versions[digest.KeyVersion] {
			return nil, password.ErrPasswordWork
		}
		versions[digest.KeyVersion] = true
	}
	repository, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	verifier := c.Verifier
	verifier.Repository = repository
	if _, err = password.NewPasswordVerifier(verifier); err != nil {
		return nil, password.ErrPasswordWork
	}
	sessions, err := sessionpg.NewRepository(pool, c.Session)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	s := &ReauthenticationService{pool: pool, repository: repository, sessions: sessions, c: c, custody: custody}
	// Validate all native registrations and coordinator bounds now, not after
	// password work. This inert phase has no comparison custody and cannot apply.
	if _, _, err = s.coordinator(&reauthenticationPhase{service: s}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

// Verify charges counted/audited abuse admission before password comparison,
// authenticates original bearer lookup and current policy, then locks and
// rechecks every supported source authority in the sole kernel Work. Wrong or
// absent passwords return the same zero result. Cancellation is preserved;
// infrastructure failure is redacted. Each call is a fresh server command.
func (s *ReauthenticationService) Verify(ctx context.Context, r ReauthenticationRequest) (result ReauthenticationResult, err error) {
	if s == nil || s.repository == nil || ctx == nil {
		return result, password.ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			result.Proof = auth.ReauthenticationProof{}
			err = password.ErrPasswordWork
		}
		// Coordinator cleanup classifies durable outcomes independently from
		// caller cancellation. Preserve that receipt, but expose the caller's
		// deadline rather than its detached cleanup's generic storage error.
		if cause := ctx.Err(); cause != nil {
			result.Proof = auth.ReauthenticationProof{}
			err = cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !slices.Contains(s.c.Targets, r.Target) {
		return result, identity.ForbiddenError{}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return result, password.ErrPasswordWork
	}
	result.CommandID = id
	// Identifier dimensions are stable tenant/account-bound, never supplied by
	// the client to evade an account's abuse counter.
	original, err := s.lookup(ctx, r.TenantID, r.Session)
	if err != nil {
		return result, err
	}
	spec, _ := original.Bindings()
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: string(id), OperationID: "identity.password.verify", PolicyID: "password-reauthentication", PolicyVersion: s.c.Coordinator.AdmissionPolicy.PolicyVersion, SchemaID: "password-verify", SchemaVersion: 1, CorrelationID: string(id)}
	if _, _, _, err = sessionpg.OriginalSessionAdmission(s.c.Profile, original, b); err != nil {
		return result, err
	}
	if err = s.authorize(ctx, r.Caller, b, r.Target); err != nil {
		return result, err
	}
	mac := hmac.New(sha256.New, s.c.IdentifierKey)
	_, _ = io.WriteString(mac, "identity-password-reauthentication-counter-v1\x00"+string(b.TenantID)+"\x00"+string(b.UserID))
	subject := risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(id)}
	evaluated, err := s.c.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}})
	if err != nil {
		return result, readerFailure(ctx)
	}
	admission, err := s.custody.Prepare(ctx, evaluated, scope, subject)
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, identity.ForbiddenError{}
	}
	reader := &reauthenticationObservation{repository: s.repository}
	vc := s.c.Verifier
	vc.Repository = reader
	verifier, err := password.NewPasswordVerifier(vc)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	comparison, err := verifier.VerifyPassword(ctx, password.VerifyPasswordRequest{TenantID: b.TenantID, SubjectID: b.UserID, Password: r.Password, ExpectedVersion: spec.Authentication.CredentialVersion})
	if err != nil {
		return result, err
	}
	if !comparison.Matched {
		return ReauthenticationResult{}, nil
	}
	if err = admission.Check(ctx); err != nil {
		return result, readerFailure(ctx)
	}
	now := s.c.Verifier.Now().UTC()
	lifetime, err := original.Lifetime(now)
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	until := now.Add(s.c.TTL)
	if lifetime.ExpiresAt.Before(until) {
		until = lifetime.ExpiresAt
	}
	credential := reader.last.Authority()
	if !credential.ExpiresAt.IsZero() && credential.ExpiresAt.Before(until) {
		until = credential.ExpiresAt
	}
	record, err := s.c.SigningKey.sign(auth.SignedReauthenticationRecord{Issuer: s.c.Issuer, Environment: s.c.Environment, ProofVersion: 1, CredentialID: string(credential.Credential.ID), CredentialVersion: comparison.CredentialVersion, Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(id), Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: r.Target.Purpose, Audience: r.Target.Audience, IssuedAt: now, ExpiresAt: until}, SessionID: spec.SessionID, SessionVersion: spec.Version, Action: r.Target.Action}})
	if err != nil {
		return result, err
	}
	phase := &reauthenticationPhase{service: s, original: original, material: reader.last, admission: admission, record: record}
	command, err := phase.command(b, r.Session)
	if err != nil {
		return result, err
	}
	phase.expected = command
	coordinator, registry, err := s.coordinator(phase)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	plan, err := reauthenticationPlan(coordinator, registry, phase, b, command, now)
	if err != nil {
		return result, err
	}
	reservation, receipt, err := coordinator.ReserveCommand(ctx, b, command, plan)
	result.Outcome = receipt.Outcome
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
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	final := s.c.Verifier.Now().UTC()
	if final.Before(now) || !final.Before(until) {
		return result, identity.ForbiddenError{}
	}
	if err = admission.Check(ctx); err != nil {
		return result, readerFailure(ctx)
	}
	result.Proof = record.Proof
	return result, nil
}

type reauthenticationObservation struct {
	repository *Repository
	last       password.CredentialSnapshot
}

func (r *reauthenticationObservation) ReadPasswordCredential(ctx context.Context, k password.CredentialKey) (password.CredentialSnapshot, error) {
	snapshot, err := r.repository.ReadPasswordCredential(ctx, k)
	if err == nil {
		r.last = snapshot
	}
	return snapshot, err
}

func (s *ReauthenticationService) lookup(ctx context.Context, tenant identity.TenantID, bearer auth.BearerCredential) (session.Session, error) {
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return session.Session{}, identity.ForbiddenError{}
	}
	var found session.Session
	for _, key := range s.c.LookupKeys {
		digest, err := token.Digest(key, string(tenant))
		if err != nil {
			return session.Session{}, password.ErrPasswordWork
		}
		row, err := s.sessions.Lookup(ctx, tenant, digest)
		if errors.Is(err, sessionpg.ErrRecordAbsent) {
			continue
		}
		if err != nil {
			return session.Session{}, readerFailure(ctx)
		}
		spec, err := row.Session.Bindings()
		if err != nil || row.Revoked || row.FamilyRevoked || row.CurrentFamilyVersion != spec.FamilyVersion {
			return session.Session{}, identity.ForbiddenError{}
		}
		if _, err := found.Bindings(); err == nil {
			return session.Session{}, password.ErrPasswordWork
		}
		found = row.Session
	}
	if _, err = found.Lifetime(s.c.Verifier.Now()); err != nil {
		return session.Session{}, identity.ForbiddenError{}
	}
	return found, nil
}

func (s *ReauthenticationService) authorize(ctx context.Context, caller authorization.DecisionContext, b identity.CommandBinding, target ReauthenticationTarget) error {
	c := caller.Clone()
	if string(c.Request.Subject.ID) != string(b.ActorID) || c.Request.Subject.Kind != authorization.SubjectUser {
		return identity.ForbiddenError{}
	}
	c.PolicyRevision = authorization.Revision(s.c.Coordinator.AdmissionPolicy.PolicyVersion)
	c.Request.Tenant, c.Request.Action = authorization.TenantID(b.TenantID), authorization.Action(b.OperationID)
	c.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
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
	c.Request.Attributes["identity.authentication.method"] = authorization.StringValue("password")
	c.Request.Attributes["identity.authentication.profile"] = authorization.StringValue("single-factor")
	c.Request.Attributes["identity.authentication.phase"] = authorization.StringValue("proposed")
	c.Request.Attributes["identity.authentication.factor-count"] = authorization.IntValue(1)
	c.Request.Attributes["identity.authentication.target-purpose"] = authorization.StringValue(string(target.Purpose))
	c.Request.Attributes["identity.authentication.target-action"] = authorization.StringValue(target.Action)
	c.Request.Attributes["identity.authentication.target-audience"] = authorization.StringValue(target.Audience)
	decision, err := s.c.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, c)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != c.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *ReauthenticationService) coordinator(phase *reauthenticationPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	domain, err := kernel.NewRepository(s.pool, kernel.Config{MaximumDuration: s.c.Repository.MaximumDuration})
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
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle, phase})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, s.c.Coordinator)
	return coordinator, registry, err
}

func reauthenticationText(s string, maximum int) bool {
	if s == "" || len(s) > maximum {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func (ReauthenticationConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ReauthenticationConfig(redacted)")
}
func (ReauthenticationConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (ReauthenticationConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
func (ReauthenticationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ReauthenticationRequest(redacted)")
}
func (ReauthenticationRequest) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (ReauthenticationRequest) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
func (*ReauthenticationService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ReauthenticationService(redacted)")
}

// Recover reconciles the original command through the sole primary coordinator
// under current disclosure policy. It accepts no password or replacement bearer
// and never issues, reconstructs or redelivers a proof. Caller must represent
// the original human actor; administrative recovery is a separate policy scope.
// Missing/wrong-scope/denied history is handled by the kernel's uniform lookup.
func (s *ReauthenticationService) Recover(ctx context.Context, tenant identity.TenantID, id identity.CommandID, caller authorization.DecisionContext) (result ReauthenticationResult, err error) {
	if s == nil || s.repository == nil || ctx == nil || caller.Request.Subject.Kind != authorization.SubjectUser {
		return result, password.ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			result.Proof = auth.ReauthenticationProof{}
			err = password.ErrPasswordWork
		}
		if cause := ctx.Err(); cause != nil {
			err = cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return result, password.ErrPasswordWork
	}
	actor := caller.Request.Subject.ID
	q := identity.RecoveryQuery{CommandID: id, TenantID: tenant, UserID: identity.UserID(actor), ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: "identity.password.verify", RecordID: string(id)}
	coordinator, _, err := s.coordinator(&reauthenticationPhase{service: s})
	if err != nil {
		return result, password.ErrPasswordWork
	}
	caller = caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.c.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Tenant = authorization.TenantID(tenant)
	caller.Request.Action = "identity.password.verify"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(actor)}
	receipt, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Feature != nil {
		result.CommandID, result.Outcome = id, receipt.Outcome
	}
	return result, err
}
