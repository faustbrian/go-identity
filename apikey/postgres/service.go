package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
	"unicode/utf8"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ServiceConfig selects the finite human-owned modern profile. Sessions must
// be the real native primary password-session owner, not a directory projection.
// Profile and LookupKeys must describe that exact owner. Authorization is the
// declared external revision-fenced policy seam; no domain-store callback is
// accepted. Counters is the actual native protected-counter/lockout participant.
// Risk and CounterPolicy must share the exact configured policy instance.
//
// Coordinator and RequestKeys retain sole journal/idempotency ownership. The
// envelope keyring protects safe original correlation and digest-only prepared
// output; it never encrypts a recoverable API-key plaintext. Retain all keys
// needed by pending original operations. Owners/pool remain caller-owned.
type ServiceConfig struct {
	Configuration apikey.Configuration
	// LegacyConfiguration optionally enables exactly one explicitly selected
	// verify-only SHA-256 source profile. Zero preserves modern-only behavior.
	LegacyConfiguration apikey.Configuration
	// ValidateCanonicalKeyID is required only for legacy import. It must honor
	// the bounded context, preserve identifiers, and be concurrency-safe. It is
	// called outside SQL; it supplies ID policy, never owner/source authority.
	ValidateCanonicalKeyID func(context.Context, apikey.KeyID) error
	Clock                  clock.Clock
	MaximumDuration        time.Duration
	Sessions               *session.SessionService
	Session                sessionpg.Config
	Profile                sessionpg.IdentifierAdmissionConfig
	LookupKeys             map[uint32]session.DigestKey
	Authorization          authorization.Service
	PolicyID               string
	PolicyVersion          uint64
	Pepper                 apikey.Pepper
	Counters               *riskpg.Repository
	Risk                   risk.ProtectedProviderAdmissionCustodyConfig
	CounterPolicy          risk.Policy
	Coordinator            kernel.CoordinatorConfig
	RequestKeys            kernel.RequestKeyConfig
	ActiveEnvelopeKeyID    string
	RetainedEnvelopeKeys   map[string][]byte
}

// Service supplies native API-key operations through the existing coordinator.
// It starts no goroutines, owns no pool and never retries a transaction. Calls
// use isolated participants; immutable configuration supports concurrency.
type Service struct {
	pool                  *database.Pool
	directory             *kernel.Repository
	config                func() ServiceConfig
	crypto                *envelope.Service
	custody               risk.ProtectedProviderAdmissionCustody
	issuanceConfiguration apikey.Configuration
	organization          *organizationComposition
	organizationID        apikey.OrganizationID
	// update belongs only to a private per-invocation copy, never the shared
	// configured service. Existing creation phases retain transaction ownership.
	update *apikey.UpdateRequest
}

func validateServiceConfigurations(c ServiceConfig) error {
	if c.Configuration.Spec().Algorithm != apikey.AlgorithmModernHMACSHA256 {
		return apikey.ErrInvalid
	}
	if c.LegacyConfiguration != (apikey.Configuration{}) {
		modern, legacy := c.Configuration.Spec(), c.LegacyConfiguration.Spec()
		if c.LegacyConfiguration.Validate() != nil || legacy.Algorithm != apikey.AlgorithmLegacySHA256V1 || legacy.PermissionReduction != apikey.PermissionReductionNarrow || legacy.ID == modern.ID || legacy.Issuer != modern.Issuer || legacy.Environment != modern.Environment || legacy.Audience != modern.Audience || c.ValidateCanonicalKeyID == nil {
			return apikey.ErrInvalid
		}
	}
	return nil
}

// NewService validates immutable composition without SQL, policy/provider calls
// or secret generation. Apply the native and prerequisite migrations, explicitly
// initialize each tenant/configuration, and retain the actual public owners.
// Only PermissionReductionNarrow is supported: Revoke requires a distinct
// atomic lifecycle profile, not a permission-changed event for a revoked key.
func NewService(pool *database.Pool, c ServiceConfig) (*Service, error) {
	if err := validateServiceConfigurations(c); err != nil {
		return nil, err
	}
	if pool == nil || pool.Raw() == nil || c.Configuration.Validate() != nil || c.Configuration.Spec().PermissionReduction != apikey.PermissionReductionNarrow || c.Configuration.Spec().MaximumLifetime < 24*time.Hour || c.Clock == nil || c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second || !c.Sessions.Configured() || c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > time.Minute || c.Profile.Validate() != nil || c.Profile.AuthenticationMethod != "password" || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" || c.Authorization == nil || !scope(c.PolicyID) || c.PolicyVersion == 0 || c.Pepper == (apikey.Pepper{}) || c.Counters == nil || len(c.LookupKeys) < 1 || len(c.LookupKeys) > 4 || !scope(c.ActiveEnvelopeKeyID) || len(c.RetainedEnvelopeKeys) < 1 || len(c.RetainedEnvelopeKeys) > 16 || len(c.RetainedEnvelopeKeys[c.ActiveEnvelopeKeyID]) != 32 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy.PolicyVersion != c.PolicyVersion || c.Coordinator.AdmissionPolicy.PolicyVersion != c.PolicyVersion || c.RequestKeys.Policy.PolicyVersion != c.PolicyVersion {
		return nil, apikey.ErrInvalid
	}
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for version, key := range c.LookupKeys {
		d, err := probe.Digest(key, "configuration-validation")
		if err != nil || d.KeyVersion != version {
			return nil, apikey.ErrInvalid
		}
	}
	keys := make(map[string][]byte, len(c.RetainedEnvelopeKeys))
	for id, key := range c.RetainedEnvelopeKeys {
		if !scope(id) || len(key) != 32 {
			return nil, apikey.ErrInvalid
		}
		keys[id] = bytes.Clone(key)
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	provider, err := keyring.New(keys)
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	custody, err := risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil || custody.ValidateCounterPolicy(c.CounterPolicy) != nil {
		return nil, apikey.ErrInvalid
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	c.LookupKeys = maps.Clone(c.LookupKeys)
	c.RetainedEnvelopeKeys = nil // Keyring owns its copy; runtime config has no raw key projection.
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	s := &Service{pool: pool, directory: directory, config: func() ServiceConfig { return c }, crypto: crypto, custody: custody, issuanceConfiguration: c.Configuration}
	if _, _, err := s.compose(&creationPhase{service: s}); err != nil {
		return nil, apikey.ErrInvalid
	}
	return s, nil
}

func scope(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, b := range []byte(value) {
		if b <= 32 || b == 127 {
			return false
		}
	}
	return true
}

func (s *Service) compose(p kernel.Contributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, apikey.ErrInvalid
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, apikey.ErrInvalid
	}
	participants := []kernel.Contributor{s.directory, audit, lifecycle}
	if _, management := p.(*creationPhase); management {
		participants = append(participants, s.config().Counters)
	}
	participants = append(participants, p)
	registry, err := kernel.NewContributorRegistry(participants)
	if err != nil {
		return nil, nil, apikey.ErrInvalid
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config().Coordinator, s.config().RequestKeys)
	return coordinator, registry, err
}

// Create authenticates the current self-owner and every requested permission,
// correlates the original keyed intent, and uses the sole coordinator's durable
// generation marker before minting. Only proven committed original invocation
// material can be revealed. Matching retries never generate or reveal a key.
func (s *Service) Create(ctx context.Context, r apikey.CreateRequest) (out apikey.IssuanceResult, err error) {
	result, err := s.manage(ctx, r, nil, false, nil)
	return s.issuance(result, err)
}

// Rotate atomically tombstones the original credential and creates a distinct
// modern successor with the same immutable grant. Modern predecessors retain
// their exact absolute expiry; legacy predecessors use the earlier of that
// expiry and the current modern lifetime ceiling. Only the original successful
// invocation retains reveal-once plaintext custody.
func (s *Service) Rotate(ctx context.Context, r apikey.Rotation) (apikey.IssuanceResult, error) {
	result, err := s.manage(ctx, mutationRequest(r), &r, false, nil)
	return s.issuance(result, err)
}

// Revoke retains a deny-all terminal tombstone. Exact retries recover the sole
// original command without applying a second transition or advancing epochs.
func (s *Service) Revoke(ctx context.Context, r apikey.Revocation) (identity.CommandResult, error) {
	rotation := apikey.Rotation(r)
	result, err := s.manage(ctx, mutationRequest(rotation), &rotation, true, nil)
	return result.receipt, err
}
func mutationRequest(r apikey.Rotation) apikey.CreateRequest {
	return apikey.CreateRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, CorrelationID: r.CorrelationID, Network: r.Network}
}

type nativeResult struct {
	receipt                identity.CommandResult
	record                 *apikey.Record
	secret                 apikey.Secret
	configurationAuthority *apikey.ConfigurationAuthorityBinding
}

func (s *Service) issuance(result nativeResult, executionErr error) (apikey.IssuanceResult, error) {
	if result.receipt.Validate() != nil {
		return apikey.IssuanceResult{}, executionErr
	}
	out, err := apikey.NewIssuanceResult(s.config().Configuration, result.receipt, result.record, result.secret)
	if err != nil {
		return apikey.IssuanceResult{}, err
	}
	return out, executionErr
}
func (s *Service) manage(ctx context.Context, r apikey.CreateRequest, mutation *apikey.Rotation, revoke bool, imported *apikey.ImportRequest) (out nativeResult, err error) {
	if s == nil || s.config == nil || ctx == nil || mutation == nil && imported == nil && r.Validate() != nil || mutation != nil && mutation.Validate() != nil || imported != nil && imported.Validate(s.config().Configuration) != nil {
		return out, apikey.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	var p *creationPhase
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			if p != nil && p.input.Binding.CommandID != "" {
				err = identity.UnknownCommitError{CommandID: p.input.Binding.CommandID}
			}
			out = nativeResult{}
		}
	}()
	started, err := s.primaryTime(ctx)
	if err != nil {
		return out, err
	}
	observed, err := s.human(ctx, r.Authentication)
	if err != nil {
		return out, err
	}
	b, err := observed.Session.Bindings()
	if err != nil {
		return out, apikey.ErrDenied
	}
	if !s.config().Clock.Now().Before(managementProofDeadline(b)) {
		return out, apikey.ErrDenied
	}
	organizationID := s.organizationID
	if imported != nil && imported.Record.Owner.Spec().Kind == apikey.OwnerOrganization {
		organizationID = imported.Record.Owner.Spec().OrganizationID
	}
	if mutation != nil {
		record, profile, e := s.managementRecord(ctx, b.TenantID, mutation.KeyID)
		if e != nil {
			return out, e
		}
		if record.Owner.Spec().Kind == apikey.OwnerOrganization {
			organizationID = record.Owner.Spec().OrganizationID
		}
		if s.update != nil && (s.update.OrganizationID != organizationID || organizationID == "" && record.Owner.Spec().UserID != b.UserID) {
			return out, apikey.ErrDenied
		}
		if revoke || s.update != nil {
			s = s.withConfiguration(profile)
		}
	}
	if organizationID != "" {
		action := "identity.apikey.create"
		if imported != nil {
			action = "identity.apikey.import"
		} else if revoke {
			action = "identity.apikey.delete"
		} else if mutation != nil {
			action = "identity.apikey.rotate"
		}
		if s.update != nil {
			action = "identity.apikey.update"
		}
		s, err = s.selectOrganization(ctx, b.TenantID, b.UserID, organizationID, action, r.CorrelationID)
		if err != nil {
			return out, err
		}
	}
	// A retained mapping is correlation only. Current self-management and every
	// requested ceiling permission authorize both new preparation and historical
	// recovery; kernel request/query admission is a separate, narrower policy.
	p = &creationPhase{service: s, request: r, observed: observed, readStartedAt: started, mutation: mutation, revocation: revoke, imported: imported}
	op := p.operation()
	if err := s.allow(ctx, s.decision(r.Authentication.TenantID, b.UserID, op.OperationID, "api-key", s.config().Configuration.Spec().ID, r.CorrelationID)); err != nil {
		return out, err
	}
	if mutation == nil || s.update != nil {
		if err := s.authorizePermissions(ctx, r.Authentication.TenantID, b.UserID, r.Permissions, r.CorrelationID); err != nil {
			return out, err
		}
	}
	if imported != nil {
		if imported.Record.Owner.Spec().Kind == apikey.OwnerUser && imported.Record.Owner.Spec().UserID != b.UserID || imported.Record.Owner.Spec().Kind == apikey.OwnerOrganization && imported.Record.Owner.Spec().OrganizationID != s.organizationID {
			return out, apikey.ErrDenied
		}
		if err := s.allow(ctx, s.decision(b.TenantID, b.UserID, op.OperationID, "api-key-import-source", imported.SourceID, r.CorrelationID)); err != nil {
			return out, err
		}
		for _, id := range []apikey.KeyID{imported.Record.ID, imported.Record.PreviousID} {
			if id != "" && s.config().ValidateCanonicalKeyID(ctx, id) != nil {
				return out, nativeError(ctx, apikey.ErrInvalid)
			}
		}
		if imported.Record.Status == apikey.KeyActive && (imported.Record.Version == ^uint64(0) || imported.Record.AuthorityVersion == ^uint64(0)) {
			return out, apikey.ErrDenied
		}
	}
	p.coordinator, p.registry, err = s.compose(p)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	intent, err := s.createIntent(r)
	if mutation == nil && imported == nil && s.organizationID != "" {
		intent, err = s.organizationCreateIntent(r)
	}
	if mutation != nil {
		intent, err = s.mutationIntent(*mutation, op)
	}
	if imported != nil {
		intent, err = s.importIntent(*imported)
	}
	if s.update != nil {
		intent, err = s.updateIntent(*s.update)
	}
	if err != nil {
		return out, err
	}
	p.intent = intent
	scope := kernel.RequestKeyScope{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := s.decision(scope.TenantID, b.UserID, op.OperationID, "identity.request-admission", op.OperationID, r.CorrelationID)
	if imported != nil {
		feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
		bound, wire, found, readErr := p.coordinator.ReadPreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, feature, p)
		if readErr != nil {
			clear(wire)
			return out, nativeError(ctx, readErr)
		}
		if found {
			original, restoreErr := p.RestoreRequestKey(ctx, bound, wire)
			clear(wire)
			if restoreErr != nil {
				return out, nativeError(ctx, restoreErr)
			}
			out.receipt, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, recoveryQuery(original), s.decision(b.TenantID, b.UserID, op.OperationID, "identity.user", string(b.UserID), r.CorrelationID), feature, p)
			return out, nativeError(ctx, err)
		}
		clear(wire)
		original, exists, sourceErr := s.importSource(ctx, *imported)
		if sourceErr != nil {
			return out, sourceErr
		}
		if exists {
			out.receipt, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, recoveryQuery(original), s.decision(b.TenantID, b.UserID, op.OperationID, "identity.user", string(b.UserID), r.CorrelationID), feature, p)
			return out, nativeError(ctx, err)
		}
	}
	bound, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, p)
	defer clear(wire)
	if err != nil {
		if p.failure != nil {
			return out, p.failure
		}
		return out, nativeError(ctx, err)
	}
	original, err := p.RestoreRequestKey(ctx, bound, wire)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	if p.input.Binding != original {
		// Status-only original recovery never reconstructs a generated secret.
		receipt, recoveryErr := p.coordinator.RecoverPreparedFeatureCommand(ctx, recoveryQuery(original), s.decision(original.TenantID, b.UserID, original.OperationID, "identity.user", string(original.UserID), r.CorrelationID), kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, p)
		out.receipt = receipt
		if receipt.Outcome == identity.CommitOutcomeCommitted {
			record, authority, readErr := s.originalMetadata(ctx, original)
			if readErr != nil {
				return out, readErr
			}
			if mutation != nil && !revoke {
				if err := s.authorizePermissions(ctx, original.TenantID, b.UserID, record.Grant, r.CorrelationID); err != nil {
					return nativeResult{}, err
				}
			}
			out.record = &record
			out.configurationAuthority = authority
			return out, nativeError(ctx, recoveryErr)
		}
		return out, nativeError(ctx, recoveryErr)
	}
	plan, err := p.plan(false)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	receipt, executionErr := p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
	if receipt.Validate() != nil {
		return out, nativeError(ctx, executionErr)
	}
	out.receipt = receipt
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		copy := p.input.Record
		out.record = &copy
		out.secret = p.secret
		if p.updating() {
			authority := p.input.ConfigurationAuthority
			if p.advancesAuthority() {
				authority.Version++
			}
			out.configurationAuthority = &authority
		}
	}
	return out, nativeError(ctx, executionErr)
}

func (s *Service) human(ctx context.Context, a apikey.Authentication) (session.GetResult, error) {
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		return session.GetResult{}, apikey.ErrDenied
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return session.GetResult{}, apikey.ErrDenied
	}
	observed, err := s.config().Sessions.Get(ctx, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, nativeError(ctx, err)
	}
	if observed.ValidateAt(s.config().Clock.Now()) != nil {
		return session.GetResult{}, apikey.ErrDenied
	}
	if observed.Session.CSRFState() != (session.CSRFState{}) {
		return session.GetResult{}, apikey.ErrDenied
	}
	b, err := observed.Session.Bindings()
	if err != nil || b.TenantID != a.TenantID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" || b.Authentication.Proof.Assurance != auth.AssuranceSingleFactor {
		return session.GetResult{}, apikey.ErrDenied
	}
	return observed, nil
}

func (s *Service) primaryTime(ctx context.Context) (time.Time, error) {
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return time.Time{}, nativeError(ctx, err)
	}
	return at.UTC().Truncate(time.Microsecond), nil
}

func (s *Service) decision(tenant identity.TenantID, user identity.UserID, action, kind, id, correlation string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config().PolicyVersion), CorrelationID: correlation, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: authorization.ResourceType(kind), ID: authorization.ResourceID(id)}}}
}

func (s *Service) allow(ctx context.Context, dc authorization.DecisionContext) error {
	decision, err := s.config().Authorization.Decide(ctx, dc)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return apikey.ErrDenied
	}
	return nil
}

func (s *Service) authorizeCreate(ctx context.Context, r apikey.CreateRequest, user identity.UserID) error {
	if err := s.allow(ctx, s.decision(r.Authentication.TenantID, user, createOperation().OperationID, "api-key", s.config().Configuration.Spec().ID, r.CorrelationID)); err != nil {
		return err
	}
	return s.authorizePermissions(ctx, r.Authentication.TenantID, user, r.Permissions, r.CorrelationID)
}
func (s *Service) authorizePermissions(ctx context.Context, tenant identity.TenantID, user identity.UserID, permissions []string, correlation string) error {
	for _, permission := range permissions {
		decision := s.decision(tenant, user, permission, "api-key", s.config().Configuration.Spec().ID, correlation)
		if s.organizationID != "" {
			decision = s.organizationDecision(tenant, authorization.SubjectUser, string(user), permission, correlation)
		}
		if err := s.allow(ctx, decision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) createIntent(r apikey.CreateRequest) (identity.RequestIntent, error) {
	preimage, err := json.Marshal(struct {
		Name          string
		Permissions   []string
		ExpiresAt     time.Time
		Configuration apikey.ConfigurationSpec
		PolicyID      string
		PolicyVersion uint64
		Network       string
	}{r.Name, r.Permissions, r.ExpiresAt.UTC(), s.config().Configuration.Spec(), s.config().PolicyID, s.config().PolicyVersion, r.Network})
	if err != nil {
		return identity.RequestIntent{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(preimage)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "apikey.create.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

func (s *Service) mutationIntent(r apikey.Rotation, op identity.FeatureOperation) (identity.RequestIntent, error) {
	preimage, err := json.Marshal(struct {
		KeyID           apikey.KeyID
		ExpectedVersion uint64
		Operation       identity.FeatureOperation
		Configuration   apikey.ConfigurationSpec
		PolicyID        string
		PolicyVersion   uint64
		Network         string
	}{r.KeyID, r.ExpectedVersion, op, s.config().Configuration.Spec(), s.config().PolicyID, s.config().PolicyVersion, r.Network})
	if err != nil {
		return identity.RequestIntent{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(preimage)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: intentField(op), Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

// Recover queries only an exact original management command after
// authenticating and authorizing its current self-owner. It never prepares,
// executes, regenerates or reveals material, including for missing commands.
func (s *Service) Recover(ctx context.Context, r apikey.RecoveryRequest) (result identity.CommandResult, err error) {
	if s == nil || s.config == nil || ctx == nil || r.Validate() != nil {
		return result, apikey.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			result = identity.CommandResult{}
			err = identity.UnavailableError{}
		}
	}()
	observed, err := s.human(ctx, r.Authentication)
	if err != nil {
		return result, err
	}
	b, err := observed.Session.Bindings()
	if err != nil || b.UserID != r.Query.UserID {
		return result, apikey.ErrDenied
	}
	if s.organizationID != "" {
		s, err = s.selectOrganization(ctx, b.TenantID, b.UserID, s.organizationID, r.Query.OperationID, "")
		if err != nil {
			return result, err
		}
	}
	op := s.managementOperation(r.Query.OperationID)
	if r.Query.OperationID == "identity.apikey.import" {
		if s.config().LegacyConfiguration.Validate() != nil {
			return result, apikey.ErrDenied
		}
		s = s.withConfiguration(s.config().LegacyConfiguration)
	} else if r.Query.OperationID == "identity.apikey.delete" || r.Query.OperationID == "identity.apikey.update" {
		_, configuration, lookupErr := s.managementRecord(ctx, b.TenantID, apikey.KeyID(r.Query.RecordID))
		if lookupErr != nil {
			return result, lookupErr
		}
		s = s.withConfiguration(configuration)
	}
	if err := s.allow(ctx, s.decision(b.TenantID, b.UserID, op.OperationID, "api-key", s.config().Configuration.Spec().ID, "")); err != nil {
		return result, err
	}
	p := &creationPhase{service: s}
	if r.Query.OperationID == "identity.apikey.update" {
		selected := *s
		selected.update = &apikey.UpdateRequest{}
		p.service = &selected
	}
	if r.Query.OperationID == "identity.apikey.import" {
		p.imported = &apikey.ImportRequest{}
	} else if r.Query.OperationID != "identity.apikey.create" {
		p.mutation = &apikey.Rotation{}
		p.revocation = r.Query.OperationID == "identity.apikey.delete"
	}
	p.coordinator, p.registry, err = s.compose(p)
	if err != nil {
		return result, nativeError(ctx, err)
	}
	result, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, r.Query, s.decision(b.TenantID, b.UserID, op.OperationID, "identity.user", string(b.UserID), ""), kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, p)
	if result.Outcome == identity.CommitOutcomeCommitted {
		// A journal hit is historical execution evidence, not configuration
		// routing authority. The owner's immutable marker binds this exact profile.
		if _, readErr := s.originalRecord(ctx, result.Binding); readErr != nil {
			return identity.CommandResult{}, readErr
		}
	}
	return result, nativeError(ctx, err)
}

func recoveryQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
}

func nativeError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	for _, known := range []error{apikey.ErrInvalid, apikey.ErrDenied, identity.ConflictError{}, identity.UnavailableError{}, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	var unknown identity.UnknownCommitError
	var denied identity.ForbiddenError
	var conflict identity.ConflictError
	switch {
	case errors.As(err, &unknown):
		return unknown
	case errors.As(err, &denied):
		return apikey.ErrDenied
	case errors.As(err, &conflict):
		return identity.ConflictError{}
	default:
		return identity.UnavailableError{}
	}
}

func (Service) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("apikey.postgres.Service(redacted)"))
}
func (Service) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
func (ServiceConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("apikey.postgres.ServiceConfig(redacted)"))
}
func (ServiceConfig) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
