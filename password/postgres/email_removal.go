package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// EmailRemovalConfig selects the password/known-empty-MFA removal profile.
// EmailPrimaryConfig separately enables administrative targets. ConfigurationID
// versions borrowed policy/provider semantics. Domain
// supplies reuse and complete pending-cascade policy; original request keys,
// configuration, evidence and decrypting keys must outlive retained requests.
// MaximumDuration is positive <=1m. Keyed's dedicated intent key must be distinct
// from envelope, directory-reuse and existing command fingerprint keys.
type EmailRemovalConfig struct {
	PolicyID, ConfigurationID string
	MaximumDuration           time.Duration
	Domain                    kernel.EmailRemovalDomainConfig
	Keyed                     KeyedEmailManagementConfig
	Risk                      risk.ProtectedProviderAdmissionCustodyConfig
	CounterPolicy             risk.Policy
	Counters                  *riskpg.Repository
	ActiveEnvelopeKeyID       string
}

// EmailRemovalService composes actual password signin/reset owners with email
// policy and the existing kernel Work, request mapping, risk, capability, audit
// and lifecycle participants. It borrows owners/pool/local keyring; callers keep
// them alive until calls finish. No worker, transaction engine or retry loop is
// created. Independent calls are concurrent-safe; request custody is borrowed.
type EmailRemovalService struct {
	primary   *EmailPrimarySource
	signin    *SigninService
	reset     *ResetService
	directory *kernel.Repository
	domain    *kernel.EmailRemovalDomain
	crypto    *envelope.Service
	custody   risk.ProtectedProviderAdmissionCustody
	csrf      session.CSRFKey
	profile   [32]byte
	config    func() EmailRemovalConfig
}

var _ email.AddressRemovalService = (*EmailRemovalService)(nil)

// NewEmailRemovalService freezes native composition without IO. Both actual
// selected signin and emailed reset request/completion services are mandatory,
// share the primary pool, and remain the eligibility owners. Mere verified
// address counts or caller-supplied recovery booleans cannot substitute for them.
// Their global/authorization scopes must match primary admission. Selected
// material/verifier limits must cover the primary's accepted range, rather than
// accepting a proof for a password the remaining signin owner cannot verify.
func NewEmailRemovalService(primary *EmailPrimarySource, signin *SigninService, reset *ResetService, c EmailRemovalConfig, keys *keyring.Provider) (*EmailRemovalService, error) {
	if primary == nil || primary.source == nil || primary.config.Action != "identity.email.address-remove" || signin == nil || signin.pool != primary.source.pool || signin.repository == nil || reset == nil || reset.pool != primary.source.pool || reset.config == nil || reset.request == nil || reset.configuration == ([32]byte{}) || reset.request.profile == ([32]byte{}) || keys == nil || c.Counters == nil || c.Keyed.intentKey == nil || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) || signin.c.Profile.AuthenticationMethod != "password" || signin.c.Profile.CredentialKind != identity.CredentialPassword || signin.c.Profile.CredentialOwner != "identity/password" {
		return nil, password.ErrPasswordWork
	}
	if !compatibleRemovalOwners(primary, signin, reset) {
		return nil, password.ErrPasswordWork
	}
	directory, err := kernel.NewRepository(primary.source.pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewEmailRemovalDomain(directory, c.Domain)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil || custody.ValidateCounterPolicy(c.CounterPolicy) != nil {
		return nil, password.ErrPasswordWork
	}
	c.Domain.Directory.RetainedIdentifierKeys = maps.Clone(c.Domain.Directory.RetainedIdentifierKeys)
	c.Domain.Cascade.Reasons = slices.Clone(c.Domain.Cascade.Reasons)
	c.Domain.Cascade.ConsumerContracts = maps.Clone(c.Domain.Cascade.ConsumerContracts)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	frame, err := json.Marshal(struct {
		Profile, Configuration, Policy, Audience, Comparison, Namespace, SigninPolicy string
		MaximumAge, MaximumDuration, ReuseCooldown                                    time.Duration
		Transport                                                                     session.CredentialKind
		Cascade                                                                       kernel.IdentifierRemovalCascadeConfig
		Reset, ResetRequest                                                           [32]byte
	}{"identity-email-removal-v1", c.ConfigurationID, c.PolicyID, primary.config.Audience, c.Domain.Directory.ComparisonProfile, c.Keyed.RequestKeys.Namespace, signin.c.PolicyID, primary.config.MaximumAge, c.MaximumDuration, c.Domain.ReuseCooldown, primary.config.Transport, c.Domain.Cascade, reset.configuration, reset.request.profile})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	intentKey := c.Keyed.intentKey()
	mac := hmac.New(sha256.New, intentKey[:])
	_, _ = mac.Write([]byte("identity-email-removal-csrf-intent-v1"))
	material := mac.Sum(nil)
	csrf, err := session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	s := &EmailRemovalService{primary: primary, signin: signin, reset: reset, directory: directory, domain: domain, crypto: crypto, custody: custody, csrf: csrf, profile: profile, config: func() EmailRemovalConfig { return c }}
	if _, _, err := s.coordinator(&emailRemovalPhase{service: s}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func compatibleRemovalOwners(primary *EmailPrimarySource, signin *SigninService, reset *ResetService) bool {
	if primary == nil || primary.source == nil || primary.source.repository == nil || signin == nil || signin.repository == nil || reset == nil || reset.repository == nil || reset.config == nil {
		return false
	}
	source := primary.source
	c := reset.config()
	if signin.c.Profile.GlobalAuthorityID != source.c.Profile.GlobalAuthorityID || signin.c.Profile.PolicyNamespace != source.c.Profile.PolicyNamespace || c.GlobalAuthorityID != source.c.Profile.GlobalAuthorityID || c.AuthorizationNamespace != source.c.Profile.PolicyNamespace || source.c.Verifier.Primitive == nil || signin.c.Verifier.Primitive == nil || signin.c.Verifier.MaximumBytes < source.c.Verifier.MaximumBytes {
		return false
	}
	base := source.repository.policy
	if base.Algorithm() == "" || !removalMaterialLimitsCover(signin.repository.policy.Limits(), base.Limits()) || !removalMaterialLimitsCover(reset.repository.policy.Limits(), base.Limits()) {
		return false
	}
	actual, original := signin.c.Verifier.Primitive.Policy().Limits(), source.c.Verifier.Primitive.Policy().Limits()
	return actual.PasswordBytes >= original.PasswordBytes && removalMaterialLimitsCover(actual, original)
}

func removalMaterialLimitsCover(actual, original primitive.Limits) bool {
	return actual.EncodedHashBytes >= original.EncodedHashBytes && actual.Argon2Time >= original.Argon2Time && actual.MemoryKiB >= original.MemoryKiB && actual.Parallelism >= original.Parallelism && actual.SaltBytes >= original.SaltBytes && actual.OutputBytes >= original.OutputBytes && actual.BcryptCost >= original.BcryptCost
}

func (s *EmailRemovalService) coordinator(p *emailRemovalPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audit, lifecycle, p, s.config().Counters})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.primary.source.pool, registry, s.primary.source.c.Coordinator, s.config().Keyed.RequestKeys)
	return c, registry, err
}

// AddressRemove resolves retained original input before current-source reads,
// then executes one protected native removal. Matching terminal retries return
// original metadata, including pending cascade identity; they cannot remove a
// newer address, consume another proof or renew any original admission.
func (s *EmailRemovalService) AddressRemove(ctx context.Context, r email.AddressRemoveRequest) (out identity.CommandResult, err error) {
	if ctx == nil || s == nil || s.config == nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			if out.Validate() != nil {
				out = identity.CommandResult{}
			}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	p, err := s.resolveRemoval(ctx, r)
	if err != nil {
		return out, err
	}
	plan, err := p.plan(false)
	if err != nil {
		return out, err
	}
	return p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
}

// AddressRemoveRateSource authenticates original proof, cookie/bearer, CSRF and
// keyed input before shared transport-rate admission. It uses the same encrypted
// mapping as AddressRemove, never creates another authority/journal, consumes
// proof or performs removal. Retained input does not renew freshness; current
// authority is mandatory inside the protected transaction for unfinished work.
func (s *EmailRemovalService) AddressRemoveRateSource(ctx context.Context, r email.AddressRemoveRequest) (user identity.UserID, err error) {
	if ctx == nil || s == nil || s.config == nil {
		return "", password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			user, err = "", identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			user, err = "", ctx.Err()
		}
	}()
	p, err := s.resolveRemoval(ctx, r)
	if err != nil {
		return "", err
	}
	spec, ok := p.command.Feature()
	if !ok {
		return "", password.ErrPasswordWork
	}
	return identity.UserID(spec.Binding.ActorID), nil
}

func (s *EmailRemovalService) resolveRemoval(ctx context.Context, r email.AddressRemoveRequest) (*emailRemovalPhase, error) {
	intent, err := s.requestIntent(r)
	if err != nil {
		return nil, err
	}
	p := &emailRemovalPhase{service: s, request: r}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return nil, err
	}
	scope, caller, feature := s.requestScope(r, p.Descriptor())
	binding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return nil, err
	}
	if err := p.restoreRequestKey(ctx, binding, wire); err != nil {
		return nil, err
	}
	return p, nil
}

// AddressRemoveRecover observes/reconciles original history through current
// query policy, never original password proof possession or another mutation.
// Current address absence alone cannot prove commit. No session is issued.
func (s *EmailRemovalService) AddressRemoveRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || s == nil || s.config == nil || q.OperationID != "identity.email.address-remove" || q.ActorKind != authorization.SubjectUser || q.ActorID == "" || string(q.ActorID) != string(q.UserID) && !s.primary.config.AdministrativeTargets || q.UserID == "" || q.RecordID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return identity.CommandResult{}, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	p := &emailRemovalPhase{service: s}
	c, _, err := s.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return c.RecoverFeatureCommand(ctx, q, caller)
}

func (s *EmailRemovalService) prepareRemoval(ctx context.Context, r email.AddressRemoveRequest, id identity.CommandID) (*emailRemovalPhase, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	primaryRequest := EmailPrimaryRequest{TenantID: r.TenantID, TargetSubjectID: r.TargetSubjectID, CommandID: id, AddressID: r.AddressID, Session: r.Primary.Session, Proof: r.Primary.Proof, CSRFToken: r.Primary.CSRFToken, Caller: r.Caller.Clone()}
	primary, err := s.primary.Prepare(ctx, primaryRequest)
	if err != nil {
		return nil, err
	}
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	bindings, err := original.Bindings()
	if err != nil {
		return nil, err
	}
	subject, err := emailPrimarySubject(s.primary, primaryRequest, bindings.UserID)
	if err != nil {
		return nil, err
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: r.TenantID, UserID: subject, MaximumIdentifiers: 128})
	if err != nil {
		return nil, err
	}
	vector, err := bindings.Authority.Bindings()
	if err != nil || r.TargetSubjectID == "" && state.AuthorityVersion != vector.Identifier.Version {
		return nil, identity.ForbiddenError{}
	}
	factorVersion, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.primary.source.pool, r.TenantID, subject, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	if enrolled {
		return nil, identity.ForbiddenError{}
	}
	var actorFactorVersion, targetCredentialVersion uint64
	var targetCredential identity.CredentialID
	if r.TargetSubjectID != "" {
		actorFactorVersion, enrolled, err = mfapg.ReadPasswordSigninFactors(ctx, s.primary.source.pool, r.TenantID, bindings.UserID, min(s.config().MaximumDuration, 5*time.Second))
		if err != nil {
			return nil, err
		}
		if enrolled {
			return nil, identity.ForbiddenError{}
		}
		material, e := s.signin.repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: r.TenantID, SubjectID: subject})
		if e != nil {
			if errors.Is(e, password.ErrCredentialAbsent) {
				return nil, identity.ForbiddenError{}
			}
			return nil, e
		}
		authority := material.Authority()
		if authority.User.ID != subject || authority.User.Version != state.User.Version || identity.CheckCredentialAuthority(authority, authority.Credential, authority.AuthorityVersion, time.Now().UTC()) != nil {
			return nil, identity.ForbiddenError{}
		}
		targetCredential, targetCredentialVersion = authority.Credential.ID, authority.Credential.Version
	}
	op := emailPrimaryOperation("identity.email.address-remove")
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: subject, ActorID: identity.ActorID(bindings.UserID), ActorKind: authorization.SubjectUser, RecordID: string(r.AddressID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(id)}
	intent := kernel.EmailRemovalIntent{Change: identity.IdentifierChange{TenantID: r.TenantID, UserID: subject, ID: r.AddressID, Action: identity.IdentifierRemove, ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion, ExpectedIdentifierVersion: r.ExpectedIdentifierVersion, ExpectedVerificationVersion: r.ExpectedVerificationVersion}, ComparisonProfile: s.config().Domain.Directory.ComparisonProfile, Reason: string(r.Reason), LeavePrimaryUnassigned: r.PrimaryDisposition == email.LeavePrimaryUnassigned}
	if r.TargetSubjectID != "" {
		intent.Administration = kernel.EmailRemovalAdministration{GlobalAuthorityID: s.primary.source.c.Profile.GlobalAuthorityID, GlobalVersion: vector.Global.Version, TenantVersion: vector.Tenant.Version}
	}
	intent.ReplacementPrimary = r.ReplacementPrimary
	policy := email.RemovalProfile{Sessions: email.InvalidateIdentifierSessions, Recovery: r.RecoveryDisposition}
	if _, err := policy.PlanRemoval(state, intent.Change, time.Now().UTC()); err != nil {
		return nil, err
	}
	if intent.ReplacementPrimary != (identity.IdentifierPrimarySelection{}) {
		if _, err := identity.ApplyIdentifierRemovalWithPrimary(state, intent.Change, intent.ReplacementPrimary, time.Now().UTC()); err != nil {
			return nil, err
		}
	}
	for _, record := range state.Identifiers {
		if record.ID == r.AddressID && record.Primary && !intent.LeavePrimaryUnassigned && intent.ReplacementPrimary == (identity.IdentifierPrimarySelection{}) {
			return nil, identity.ForbiddenError{}
		}
	}
	fields, err := kernel.EmailRemovalFields(intent)
	if err != nil {
		return nil, err
	}
	fields = append(fields, identity.FeatureField{Name: "email.removal.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factorVersion}}, identity.FeatureField{Name: "email.removal.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}})
	if r.TargetSubjectID != "" {
		fields = append(fields, identity.FeatureField{Name: "email.removal.actor-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: actorFactorVersion}}, identity.FeatureField{Name: "email.removal.target-credential", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(targetCredential)}}, identity.FeatureField{Name: "email.removal.target-credential-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: targetCredentialVersion}})
	}
	command, err := primary.Command(b, fields)
	if err != nil {
		return nil, err
	}
	command, counter, err := s.config().Counters.PrepareCommandCounters(command, risk.Subject{User: string(subject), Session: bindings.SessionID, Network: r.Network}, r.Primary.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return nil, err
	}
	return &emailRemovalPhase{service: s, request: r, primary: primary, intent: intent, command: command, counter: counter, factorVersion: factorVersion, actorFactorVersion: actorFactorVersion, targetCredential: targetCredential, targetCredentialVersion: targetCredentialVersion}, nil
}

// AdministrativeRemovalConfigured reports explicit native capability selection,
// never caller permission, authentication or fresh authority.
func (s *EmailRemovalService) AdministrativeRemovalConfigured() bool {
	return s != nil && s.primary != nil && s.primary.config.AdministrativeTargets
}

// Format hides borrowed owners, keys and configuration custody.
func (EmailRemovalService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailRemovalService(redacted)"))
}

// MarshalJSON denies implicit runtime custody export.
func (EmailRemovalService) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format hides cryptographic and deployment configuration.
func (EmailRemovalConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailRemovalConfig(redacted)"))
}

// MarshalJSON denies implicit configuration/key export.
func (EmailRemovalConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
