package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// SigninConfig is trusted startup composition for native password login.
// Verifier.Repository must be nil; the service supplies its primary owner.
// Address selects the email owner's fixed comparison policy, not a client
// normalizer. FlowKeys retain original cookie verification versions. Issuance
// has nil Authority: original authentication is created by this transaction.
// PolicyID and admission revision bind original pre-auth intent. Origins and
// CallbackURLs are exact closed HTTPS allowlists; include an empty callback
// explicitly to admit flows with no redirect. Both policies must support the
// selected single-factor profile and deny users requiring additional factors.
// All borrowed dependencies and clocks must be concurrency-safe and bounded.
// Hash upgrades are atomic with original signin. Other-factor continuation
// remains in development and must be denied by the selected single-factor policy.
type SigninConfig struct {
	Repository                    Config
	Verifier                      password.VerifierConfig
	Session                       sessionpg.Config
	Profile                       sessionpg.IdentifierAdmissionConfig
	Address                       email.AddressPolicy
	FlowKeys                      []session.DigestKey
	Issuance                      session.IssuerConfig
	CSRFKey                       session.CSRFKey
	Risk                          risk.AuthenticationAdmissionCustodyConfig
	Coordinator                   kernel.CoordinatorConfig
	SigningKey                    SigninSigningKey
	VerificationKeys              map[string]ed25519.PublicKey
	Issuer, Environment, PolicyID string
	ProofTTL                      time.Duration
	IdentifierKey                 []byte
	Origins, CallbackURLs         []string
}

// SigninService owns primary discovery, raw comparison, original admission and
// commit-gated issuance. It borrows but never closes the pool, owns no goroutine,
// automatic retry, secondary journal or caller-written storage workflow. Calls
// are safe concurrently under the configured dependencies' contracts. Current
// support is verified-email single-factor login, including bounded automatic
// rehash; additional factor profiles remain in development.
type SigninService struct {
	pool            *database.Pool
	repository      *Repository
	domain          *kernel.Repository
	policyAuthority *authoritypg.AuthorityStore
	effect          *sessionpg.PasswordSigninEffect
	sessions        *sessionpg.Repository
	address         email.AddressParser
	custody         risk.AuthenticationAdmissionCustody
	c               SigninConfig
	mfa             *signinMFAComposition
}

var _ password.SigninService = (*SigninService)(nil)

// NewSigninService validates and freezes native composition without IO,
// migration installation, password work or callbacks. Install original kernel,
// authorization, password, pre-auth, session/CSRF, audit and lifecycle histories
// before use. Zero, absent keys and inconsistent profiles return ErrPasswordWork.
func NewSigninService(pool *database.Pool, c SigninConfig) (*SigninService, error) {
	if pool == nil || pool.Raw() == nil || c.Verifier.Repository != nil || c.Verifier.Now == nil || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.SigningKey.apply == nil || c.SigningKey.public == nil || c.Profile.Validate() != nil || c.Profile.AuthenticationMethod != "password" || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" || !reauthenticationText(c.Issuer, 256) || !reauthenticationText(c.Environment, 128) || !reauthenticationText(c.PolicyID, 128) || c.ProofTTL <= 0 || c.ProofTTL > 15*time.Minute || len(c.IdentifierKey) < 32 || len(c.IdentifierKey) > 64 || len(c.FlowKeys) == 0 || len(c.FlowKeys) > 16 || len(c.VerificationKeys) == 0 || len(c.VerificationKeys) > 16 || c.Issuance.Clock == nil || c.Issuance.Authority != nil || !signinURLs(c.Origins, true) || !signinURLs(c.CallbackURLs, false) {
		return nil, password.ErrPasswordWork
	}
	c.IdentifierKey, c.FlowKeys = slices.Clone(c.IdentifierKey), slices.Clone(c.FlowKeys)
	c.Origins, c.CallbackURLs = slices.Clone(c.Origins), slices.Clone(c.CallbackURLs)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	keys := make(map[string]ed25519.PublicKey, len(c.VerificationKeys))
	for id, key := range c.VerificationKeys {
		if !reauthenticationText(id, 128) || len(key) != ed25519.PublicKeySize {
			return nil, password.ErrPasswordWork
		}
		keys[id] = slices.Clone(key)
	}
	c.VerificationKeys = keys
	id, public := c.SigningKey.public()
	if !bytes.Equal(public, keys[id]) {
		return nil, password.ErrPasswordWork
	}
	probe, _ := session.ParseToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	versions := map[uint32]bool{}
	for _, key := range c.FlowKeys {
		d, err := probe.Digest(key, "signin-configuration")
		if err != nil || versions[d.KeyVersion] {
			return nil, password.ErrPasswordWork
		}
		versions[d.KeyVersion] = true
	}
	r, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	vc := c.Verifier
	vc.Repository = r
	if _, err = password.NewPasswordVerifier(vc); err != nil {
		return nil, password.ErrPasswordWork
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	policy, err := authoritypg.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	effect, err := sessionpg.NewPasswordSigninEffect(c.Session, c.Profile)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	sessions, err := sessionpg.NewRepository(pool, c.Session)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	address, err := email.NewAddressParser(c.Address)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, err = session.NewPasswordSessionIssuerWithCSRF(&signinExecution{}, c.Issuance, c.CSRFKey); err != nil {
		return nil, password.ErrPasswordWork
	}
	s := &SigninService{pool: pool, repository: r, domain: domain, policyAuthority: policy, effect: effect, sessions: sessions, address: address, custody: custody, c: c}
	if _, _, err = s.coordinator(&signinPhase{operation: signinOperation()}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func signinURLs(values []string, origin bool) bool {
	if len(values) == 0 || len(values) > 32 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
		if value == "" && !origin {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || !reauthenticationText(value, 2048) || u.Scheme != "https" || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || strings.Contains(value, "#") || origin && (u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery) {
			return false
		}
	}
	return true
}

func signinOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
}

// Signin performs counted/audited risk admission before real raw-byte comparison,
// including current-policy dummy work for unknown identifiers. No request field
// supplies a selected user, session, proof or authority version. The original
// primary flow and configured HTTPS intent must agree. One new non-keyed command
// owns the complete success transaction; callers must never resubmit secrets
// after ambiguity. Errors/cancellation reveal no bearer, cookie or synchronizer,
// including after a known commit. The caller retains password destruction.
func (s *SigninService) Signin(ctx context.Context, r password.SigninRequest) (out password.SigninResult, err error) {
	if s == nil || s.repository == nil || ctx == nil || r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Issuance.Token, out.CSRFToken = session.Token{}, session.CSRFToken{}
			out.Issuance.Cookie = http.Cookie{}
			out.Challenge.Proof = capability.Proof{}
		}
	}()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if !slices.Contains(s.c.Origins, r.Origin) || !slices.Contains(s.c.CallbackURLs, r.CallbackURL) {
		return out, identity.ForbiddenError{}
	}
	flow, key, err := s.flow(ctx, r)
	if err != nil {
		return out, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, password.ErrPasswordWork
	}
	op := signinOperation()
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, PolicyID: s.c.PolicyID, PolicyVersion: s.c.Coordinator.AdmissionPolicy.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: string(id)}
	recovery, err := password.NewSigninRecovery(identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}, r.PreAuthID)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	out = password.SigninResult{State: auth.SignInStateRejected, Recovery: recovery, Issuance: session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeNotCommitted}}
	if err = s.authorize(ctx, r.Caller, b, ""); err != nil {
		return out, err
	}
	address, parseErr := s.address.Parse(email.AddressInput(r.Identifier))
	canonical := string(r.Identifier)
	if parseErr == nil {
		canonical = address.Canonical().Record().Value
	}
	mac := hmac.New(sha256.New, s.c.IdentifierKey)
	_, _ = io.WriteString(mac, "identity-password-signin-counter-v1\x00"+string(r.TenantID)+"\x00"+canonical)
	scope := risk.Context{Tenant: string(r.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(id)}
	subject := risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
	evaluation, err := s.c.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}})
	if err != nil {
		return out, readerFailure(ctx)
	}
	admission, err := s.custody.Prepare(ctx, evaluation, scope, subject)
	if err != nil {
		return out, readerFailure(ctx)
	}
	var recipient kernel.RecipientRecord
	var selected identity.UserID
	if parseErr == nil {
		recipient, err = s.domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
		if err != nil {
			return out, readerFailure(ctx)
		}
		if !recipient.Suppressed {
			selected = recipient.User.ID
		}
	}
	observation := &reauthenticationObservation{repository: s.repository}
	vc := s.c.Verifier
	vc.Repository = observation
	verifier, err := password.NewPasswordVerifier(vc)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	comparison, err := verifier.VerifyPassword(ctx, password.VerifyPasswordRequest{TenantID: r.TenantID, SubjectID: selected, Password: r.Password})
	if err != nil {
		return out, err
	}
	if !comparison.Matched {
		return out, nil
	}
	var factorVersion uint64
	var challengeRequired bool
	if s.mfa != nil {
		factorVersion, challengeRequired, err = mfapg.ReadPasswordSigninFactors(ctx, s.pool, r.TenantID, selected, s.c.Repository.MaximumDuration)
		if err != nil {
			return out, err
		}
	}
	sessionID, err := identity.NewCommandID()
	if err != nil {
		return out, password.ErrPasswordWork
	}
	familyID, err := identity.NewCommandID()
	if err != nil {
		return out, password.ErrPasswordWork
	}
	// Observe policy authority before asking for a selected-user grant. A later
	// policy mutation must invalidate that grant, not attach its newer epoch to
	// the earlier decision. The session effect fences this exact observation.
	authority, err := s.authority(ctx, recipient, string(sessionID), string(familyID))
	if err != nil {
		return out, readerFailure(ctx)
	}
	profile := "single-factor"
	if challengeRequired {
		profile = "multi-factor"
	}
	if err = s.authorizeProfile(ctx, r.Caller, b, selected, profile); err != nil {
		return out, err
	}
	if err = admission.Check(ctx); err != nil {
		return out, readerFailure(ctx)
	}
	var upgrade *kernel.PasswordHashUpgradeIntent
	var replacement primitive.EncodedHash
	credentialVersion := observation.last.Authority().Credential.Version
	if comparison.NeedsRehash {
		replacement, err = s.prepareSigninRehash(ctx, r.Password)
		if err != nil {
			return out, err
		}
		intent := kernel.PasswordHashUpgradeIntent{Admission: kernel.CredentialAdmission{Credential: observation.last.Authority().Credential, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierAuthorityVersion: recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: recipient.CredentialAuthorityVersion}, ExpectedUserVersion: recipient.User.Version}
		if _, err = kernel.PasswordHashUpgradeFields(intent); err != nil {
			return out, password.ErrPasswordWork
		}
		upgrade = &intent
		credentialVersion++
		vector, e := authority.Bindings()
		if e != nil {
			return out, password.ErrPasswordWork
		}
		vector.Credential.Version++
		authority, err = session.NewAuthoritySnapshot(vector)
		if err != nil {
			return out, password.ErrPasswordWork
		}
	}
	if challengeRequired {
		result, e := s.signinMFA(ctx, r, b, recipient, observation.last, flow, key, admission, authority, factorVersion, upgrade, replacement, out)
		if e != nil {
			return result, fmt.Errorf("password MFA: %w", e)
		}
		return result, nil
	}
	now := s.c.Issuance.Clock.Now().UTC()
	until := now.Add(s.c.ProofTTL)
	f, _ := flow.Bindings()
	if f.Binding.ExpiresAt.Before(until) {
		until = f.Binding.ExpiresAt
	}
	m := observation.last.Authority()
	if !m.ExpiresAt.IsZero() && m.ExpiresAt.Before(until) {
		until = m.ExpiresAt
	}
	signed, err := s.c.SigningKey.sign(auth.SignedSignInRecord{Issuer: s.c.Issuer, Environment: s.c.Environment, State: auth.SignInStateAuthenticated, ProofVersion: 1, CredentialID: string(m.Credential.ID), CredentialVersion: credentialVersion, Proof: auth.Proof{ID: auth.ProofID(id), Tenant: string(r.TenantID), Subject: string(selected), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: s.c.Profile.Audience, IssuedAt: now, ExpiresAt: until}})
	if err != nil {
		return out, password.ErrPasswordWork
	}
	executor := &signinExecution{clock: s.c.Issuance.Clock}
	issuer, err := session.NewPasswordSessionIssuerWithCSRF(executor, s.c.Issuance, s.c.CSRFKey)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	prepared, err := issuer.PreparePassword(b, session.SessionSpec{SessionID: string(sessionID), FamilyID: string(familyID), TenantID: r.TenantID, UserID: selected, Audience: s.c.Profile.Audience, Version: 1, FamilyVersion: 1, Remember: r.Remember, Authority: authority, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: signed.Proof, ProofVersion: signed.ProofVersion, CredentialID: signed.CredentialID, CredentialVersion: signed.CredentialVersion}, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		return out, readerFailure(ctx)
	}
	record, ok := prepared.Session()
	if !ok {
		return out, password.ErrPasswordWork
	}
	fields, err := sessionpg.PasswordSigninSessionFields(record)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	if upgrade != nil {
		metadata, e := kernel.PasswordHashUpgradeFields(*upgrade)
		if e != nil {
			return out, password.ErrPasswordWork
		}
		fields = append(fields, metadata...)
		fields = append(fields, signinRehashCommitment(replacement))
	}
	if factorVersion != 0 {
		fields = append(fields, identity.FeatureField{Name: "password.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factorVersion}})
	}
	command, err := identity.NewFeaturePasswordSigninCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, r.Password, r.Cookie)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	prepared, err = issuer.BindPassword(prepared, command)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	phase := &signinPhase{operation: op, expected: command, effect: s.effect, recipient: recipient, material: observation.last, request: r, flow: flow, flowKey: key, record: signed, verificationKeys: s.c.VerificationKeys, admission: admission, maximumHashBytes: int(s.c.Repository.HashPolicy.Limits().EncodedHashBytes), upgrade: upgrade, replacement: replacement, hashPolicy: s.c.Repository.HashPolicy, factorVersion: factorVersion}
	coordinator, registry, err := s.coordinator(phase)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	plan, err := signinPlan(coordinator, registry, phase, command, now)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	executor.coordinator, executor.phase, executor.plan, executor.record = coordinator, phase, plan, record
	out.Issuance, err = issuer.Issue(ctx, prepared)
	if out.Issuance.CommitOutcome == identity.CommitOutcomeCommitted {
		out.State, out.SessionID = auth.SignInStateAuthenticated, string(sessionID)
	}
	if err == nil && !out.Issuance.Replayed && out.Issuance.Token != (session.Token{}) {
		out.CSRFToken, err = prepared.CSRFToken()
	}
	return out, err
}

func (s *SigninService) flow(ctx context.Context, r password.SigninRequest) (session.PreAuthTransaction, session.DigestKey, error) {
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), s.c.Session, r.TenantID, r.PreAuthID)
	if err != nil {
		return session.PreAuthTransaction{}, session.DigestKey{}, readerFailure(ctx)
	}
	spec, _ := flow.Bindings()
	probe, _ := session.ParseToken(r.Cookie.Token())
	for _, key := range s.c.FlowKeys {
		digest, err := probe.PreAuthDigest(key, spec.Binding)
		if err == nil && digest.KeyVersion == spec.Cookie.KeyVersion && admitSigninFlow(r, flow, key, s.c.PolicyID, s.c.Coordinator.AdmissionPolicy.PolicyVersion, s.c.Issuance.Clock.Now()) == nil {
			return flow, key, nil
		}
	}
	return session.PreAuthTransaction{}, session.DigestKey{}, identity.ForbiddenError{}
}

func (s *SigninService) authorize(ctx context.Context, caller authorization.DecisionContext, b identity.CommandBinding, user identity.UserID) error {
	return s.authorizeProfile(ctx, caller, b, user, "single-factor")
}

func (s *SigninService) authorizeProfile(ctx context.Context, caller authorization.DecisionContext, b identity.CommandBinding, user identity.UserID, profile string) error {
	c := caller.Clone()
	c.PolicyRevision = authorization.Revision(s.c.Coordinator.AdmissionPolicy.PolicyVersion)
	c.Request.Tenant, c.Request.Action = authorization.TenantID(b.TenantID), authorization.Action(b.OperationID)
	c.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(b.OperationID)}
	if user != "" {
		c.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	}
	for _, values := range []authorization.Attributes{c.Request.Attributes, c.Request.Subject.Attributes, c.Request.Environment.Attributes} {
		for key := range values {
			if strings.HasPrefix(string(key), "identity.authentication.") {
				delete(values, key)
			}
		}
	}
	if c.Request.Attributes == nil {
		c.Request.Attributes = authorization.Attributes{}
	}
	c.Request.Attributes["identity.authentication.method"] = authorization.StringValue("password")
	c.Request.Attributes["identity.authentication.profile"] = authorization.StringValue(profile)
	c.Request.Attributes["identity.authentication.phase"] = authorization.StringValue("proposed")
	c.Request.Attributes["identity.authentication.factor-count"] = authorization.IntValue(1)
	if profile == "multi-factor" {
		c.Request.Attributes["identity.authentication.factor-count"] = authorization.IntValue(2)
	}
	decision, err := s.c.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, c)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != c.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *SigninService) authority(ctx context.Context, recipient kernel.RecipientRecord, sessionID, familyID string) (session.AuthoritySnapshot, error) {
	q := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.c.Profile.GlobalAuthorityID, TenantID: recipient.User.TenantID}
	directory, err := s.domain.GetDirectoryAuthority(ctx, q)
	if err != nil || !directory.Enabled {
		return session.AuthoritySnapshot{}, readerFailure(ctx)
	}
	keys, err := kernel.KernelAuthorityKeys(q, recipient.User.ID)
	if err != nil {
		return session.AuthoritySnapshot{}, password.ErrPasswordWork
	}
	skeys, err := sessionpg.SessionAuthorityKeys(q.TenantID, recipient.User.ID, familyID, sessionID)
	if err != nil {
		return session.AuthoritySnapshot{}, password.ErrPasswordWork
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), SubjectID: authorization.SubjectID(recipient.User.ID), PolicyNamespace: s.c.Profile.PolicyNamespace}
	policy, err := s.policyAuthority.Get(ctx, scope)
	if err != nil {
		return session.AuthoritySnapshot{}, readerFailure(ctx)
	}
	key, err := scope.Key()
	if err != nil {
		return session.AuthoritySnapshot{}, password.ErrPasswordWork
	}
	bind := func(k string, v uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: v}
	}
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(keys.Global, directory.GlobalVersion), Tenant: bind(keys.Tenant, directory.TenantVersion), User: bind(keys.User, recipient.UserAuthorityVersion), Identifier: bind(keys.Identifier, recipient.IdentifierAuthorityVersion), Credential: bind(keys.Credential, recipient.CredentialAuthorityVersion), SessionFamily: bind(skeys.Family, 1), Session: bind(skeys.Session, 1), Authorization: bind(key, policy.Version)})
}

func (s *SigninService) coordinator(phase *signinPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.domain, audits, lifecycle, phase})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.pool, registry, s.c.Coordinator)
	return c, registry, err
}

// RecoverSignin checks retained original cookie possession and current
// disclosure policy, then reconciles only the sole coordinator's original
// password-free attempt. Consumed/expired pre-auth and deleted live sessions
// do not erase historical identity. No comparison, new attempt charge, session
// creation, bearer generation or freshness renewal occurs. Committed results
// disclose only retained SessionID, not a reconstructed Session or credential.
func (s *SigninService) RecoverSignin(ctx context.Context, r password.SigninRecoveryRequest) (out password.SigninResult, err error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = password.SigninResult{}, password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			out, err = password.SigninResult{}, ctx.Err()
		}
	}()
	q, flowID, _ := r.Recovery.Bindings()
	flow, e := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), s.c.Session, q.TenantID, flowID)
	if e != nil {
		return out, readerFailure(ctx)
	}
	spec, _ := flow.Bindings()
	i := spec.Binding.Intent
	if q.UserID != "" || q.AnonymousFlowID != string(flowID) || i.Action != q.OperationID || i.Action != "identity.password.signin" || i.TenantID != q.TenantID || i.Origin != r.Origin || !slices.Contains(s.c.Origins, i.Origin) || !slices.Contains(s.c.CallbackURLs, i.CallbackURL) || i.PolicyID != s.c.PolicyID {
		return out, identity.ForbiddenError{}
	}
	token, e := session.ParseToken(r.Cookie.Token())
	if e != nil {
		return out, identity.ForbiddenError{}
	}
	possessed := false
	for _, key := range s.c.FlowKeys {
		digest, e := token.PreAuthDigest(key, spec.Binding)
		if e == nil && digest.KeyVersion == spec.Cookie.KeyVersion && hmac.Equal(digest.Sum[:], spec.Cookie.Sum[:]) {
			possessed = true
		}
	}
	if !possessed {
		return out, identity.ForbiddenError{}
	}
	phase := &signinPhase{operation: signinOperation(), effect: s.effect, verificationKeys: s.c.VerificationKeys}
	coordinator, _, e := s.coordinator(phase)
	if e != nil {
		return out, password.ErrPasswordWork
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.c.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Tenant = authorization.TenantID(q.TenantID)
	caller.Request.Action = authorization.Action(q.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	if s.mfa != nil {
		_, observed, challenge, e := coordinator.QueryPasswordMFAChallenge(ctx, q, caller)
		// A classified failed receipt is still authorized original history.
		// Policy/structural denial returns no valid observed binding and cannot
		// select a recovery participant or disclose a partial authentication.
		if e != nil && observed.Validate() != nil {
			return out, e
		}
		if challenge {
			return s.recoverMFASignin(ctx, r, flow, caller)
		}
	}
	receipt, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Feature == nil {
		return out, err
	}
	if receipt.Feature.Operation != phase.operation || receipt.Binding.PolicyID != i.PolicyID || receipt.Binding.PolicyVersion != i.PolicyVersion || receipt.Binding.AnonymousFlowID != string(spec.Binding.ID) {
		return out, identity.ForbiddenError{}
	}
	var sessionID string
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		retained, e := s.sessions.ReadPasswordSigninIdentity(ctx, receipt.Binding)
		if e != nil {
			return out, readerFailure(ctx)
		}
		sessionID = retained.SessionID
	}
	// A historical receipt cannot keep an earlier disclosure grant alive while
	// primary reconciliation/retained reads wait. Recheck through the same owner,
	// without replay or a second recovery state machine.
	current, currentErr := coordinator.QueryCommand(ctx, q, caller)
	if current.Binding != receipt.Binding || current.Feature == nil || *current.Feature != phase.operation {
		if currentErr != nil {
			return out, currentErr
		}
		return out, identity.ForbiddenError{}
	}
	if current.Outcome != receipt.Outcome {
		return password.SigninResult{State: auth.SignInStateRejected, Recovery: r.Recovery, Issuance: session.IssueResult{CommandID: q.CommandID, CommitOutcome: identity.CommitOutcomeUnknown, Replayed: true}}, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	if receipt.Outcome == identity.CommitOutcomeCommitted && currentErr != nil {
		return out, currentErr
	}
	out = password.SigninResult{State: auth.SignInStateRejected, Recovery: r.Recovery, Issuance: session.IssueResult{CommandID: q.CommandID, CommitOutcome: receipt.Outcome, Replayed: true, RetryAfter: receipt.RetryAfter}}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		out.State, out.SessionID = auth.SignInStateAuthenticated, sessionID
	}
	return out, err
}

func (SigninConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "passwordpostgres.SigninConfig(redacted)")
}
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (SigninConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
func (*SigninService) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "passwordpostgres.SigninService(redacted)")
}
