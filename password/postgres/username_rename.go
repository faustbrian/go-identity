package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// UsernameRenameConfig selects the native password/known-empty-MFA profile.
// ConfigurationID versions borrowed policy and validator semantics. Domain must
// select the fixed username profile and the reference thirty-day cooldown.
// RequestKeys, IntentKey, namespace, envelope keys and original configuration
// must remain available while retained commands exist. IntentKey is dedicated,
// independent of lookup, directory reuse, envelope and fingerprint material.
// Risk selects protected provider admission. Counters configures the native
// counter owner and must enable current durable lockouts; construction copies
// its keys rather than retaining mutable caller-owned configuration.
// MaximumDuration is positive <=1m; construction performs no IO or callbacks.
type UsernameRenameConfig struct {
	PolicyID, ConfigurationID string
	MaximumDuration           time.Duration
	Domain                    kernel.UsernameRenameDomainConfig
	RequestKeys               kernel.RequestKeyConfig
	IntentKey                 [32]byte
	Risk                      risk.ProtectedProviderAdmissionCustodyConfig
	Counters                  riskpg.Config
	ActiveEnvelopeKeyID       string
}

// UsernameRenameService borrows native password, directory, risk and keyring
// owners. It uses the sole coordinator and existing encrypted request mapping,
// never a private store, transaction, proof engine, retry loop or goroutine.
// Calls are concurrent-safe with independent borrowed requests and callbacks.
type UsernameRenameService struct {
	primary   *ActionPrimarySource
	policy    *username.Policy
	directory *kernel.Repository
	domain    *kernel.UsernameRenameDomain
	crypto    *envelope.Service
	custody   risk.ProtectedProviderAdmissionCustody
	counters  *riskpg.Repository
	csrf      session.CSRFKey
	profile   [32]byte
	config    func() UsernameRenameConfig
}

var _ username.RenameService = (*UsernameRenameService)(nil)
var _ username.RenameRateSource = (*UsernameRenameService)(nil)

// NewUsernameRenameService freezes explicit native composition. The primary
// source must already select identity.username.update and its signed audience.
// Install identifier normalization/retirement, request-key/preparation, native
// audit/outbox, protected counter/lockout and action-proof histories first.
func NewUsernameRenameService(primary *ActionPrimarySource, p *username.Policy, c UsernameRenameConfig, keys *keyring.Provider) (*UsernameRenameService, error) {
	if primary == nil || primary.primary == nil || primary.primary.source == nil || !primary.Matches("identity.username.update", primary.primary.config.Audience) || p == nil || p.ReservedVersion() == 0 || keys == nil || !c.Counters.EnforceLockouts || c.Counters.CommandCounters == nil || c.IntentKey == ([32]byte{}) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) || c.Domain.NormalizationProfile != string(username.ProfileID) || c.Domain.NormalizationVersion != username.ProfileVersion || c.Domain.ReuseCooldown != 30*24*time.Hour {
		return nil, password.ErrPasswordWork
	}
	source := primary.primary.source
	if source.c.Coordinator.AdmissionPolicy == nil || c.RequestKeys.Policy.PolicyVersion != source.c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, password.ErrPasswordWork
	}
	// This is the existing kernel request-key configuration contract; no email
	// workflow or storage is selected by validating its shared key shape.
	if _, err := NewKeyedEmailManagementConfig(c.RequestKeys, c.IntentKey); err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(source.pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewUsernameRenameDomain(directory, c.Domain)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil || custody.ValidateCounterPolicy(c.Counters.CommandCounters.Policy) != nil {
		return nil, password.ErrPasswordWork
	}
	counters, err := riskpg.NewRepository(c.Counters)
	if err != nil {
		return nil, err
	}
	c.Domain.RetainedIdentifierKeys = maps.Clone(c.Domain.RetainedIdentifierKeys)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	frame, err := json.Marshal(struct {
		Profile, Configuration, Policy, Audience, Namespace, Comparison, Issuer, Environment, CounterSchema string
		ComparisonVersion, ReservedVersion                                                                  uint32
		PolicyVersion, CounterPolicyVersion                                                                 uint64
		MaximumAge, MaximumDuration, Cooldown                                                               time.Duration
		Transport                                                                                           session.CredentialKind
	}{"identity-username-rename-v1", c.ConfigurationID, c.PolicyID, primary.primary.config.Audience, c.RequestKeys.Namespace, c.Domain.NormalizationProfile, source.c.Issuer, source.c.Environment, c.Counters.Schema, c.Domain.NormalizationVersion, p.ReservedVersion(), c.RequestKeys.Policy.PolicyVersion, c.Counters.PolicyVersion, primary.primary.config.MaximumAge, c.MaximumDuration, c.Domain.ReuseCooldown, primary.primary.config.Transport})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	snapshot := *p
	// The native owner has copied its keys; do not retain borrowed mutable maps
	// or pointers in the remaining immutable workflow configuration.
	c.Counters = riskpg.Config{}
	s := &UsernameRenameService{primary: primary, policy: &snapshot, directory: directory, domain: domain, crypto: crypto, custody: custody, counters: counters, profile: sha256.Sum256(frame), config: func() UsernameRenameConfig { return c }}
	clear(frame)
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write([]byte("identity-username-rename-csrf-intent-v1"))
	material := mac.Sum(nil)
	s.csrf, err = session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, _, err = s.coordinator(&usernameRenamePhase{service: s}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func (s *UsernameRenameService) coordinator(p *usernameRenamePhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audit, lifecycle, p, s.counters})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.primary.primary.source.pool, registry, s.primary.primary.source.c.Coordinator, s.config().RequestKeys)
	return c, registry, err
}

// Rename resolves original keyed custody before live reads and executes one
// protected atomic change. Exact committed retries return original metadata,
// never rename a newer value, consume another proof or renew freshness.
func (s *UsernameRenameService) Rename(ctx context.Context, r username.RenameRequest) (out identity.CommandResult, err error) {
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
	p, err := s.resolveRename(ctx, r)
	if err != nil {
		return out, err
	}
	plan, err := p.plan(false)
	if err != nil {
		return out, err
	}
	return p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
}

// RenameRateSource authenticates original request possession for shared
// transport admission without consuming proof or changing the identifier.
func (s *UsernameRenameService) RenameRateSource(ctx context.Context, r username.RenameRequest) (user identity.UserID, err error) {
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
	p, err := s.resolveRename(ctx, r)
	if err != nil {
		return "", err
	}
	spec, ok := p.command.Feature()
	if !ok {
		return "", password.ErrPasswordWork
	}
	return spec.Binding.UserID, nil
}

func (s *UsernameRenameService) resolveRename(ctx context.Context, r username.RenameRequest) (*usernameRenamePhase, error) {
	intent, err := s.requestIntent(r)
	if err != nil {
		return nil, err
	}
	p := &usernameRenamePhase{service: s, request: r}
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
	if err = p.restoreRequestKey(ctx, binding, wire); err != nil {
		return nil, err
	}
	return p, nil
}

// RenameRecover observes original history under current query authorization.
// Identifier absence or a newer value alone is never evidence of commit; no
// proof, session, candidate or bearer is reissued from recovery metadata.
func (s *UsernameRenameService) RenameRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || s == nil || s.config == nil || q.OperationID != "identity.username.update" || q.ActorKind != authorization.SubjectUser || q.ActorID == "" || string(q.ActorID) != string(q.UserID) || q.RecordID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return identity.CommandResult{}, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	p := &usernameRenamePhase{service: s}
	c, _, err := s.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return c.RecoverFeatureCommand(ctx, q, caller)
}

func (s *UsernameRenameService) prepareRename(ctx context.Context, r username.RenameRequest, id identity.CommandID) (*usernameRenamePhase, error) {
	if !validEmailPrimaryCaller(r.Caller) || r.Validate() != nil {
		return nil, username.ErrInvalid
	}
	primary, err := s.primary.Prepare(ctx, ActionPrimaryRequest{TenantID: r.TenantID, CommandID: id, RecordID: string(r.IdentifierID), Session: r.Session, Proof: r.Proof, Caller: r.Caller.Clone(), CSRFToken: r.CSRFToken})
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
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: r.TenantID, UserID: bindings.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return nil, err
	}
	vector, err := bindings.Authority.Bindings()
	if err != nil || state.AuthorityVersion != vector.Identifier.Version {
		return nil, identity.ForbiddenError{}
	}
	factorVersion, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.primary.primary.source.pool, r.TenantID, bindings.UserID, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	if enrolled || factorVersion == 0 {
		return nil, identity.ForbiddenError{}
	}
	name, err := s.policy.Validate(ctx, r.Username)
	if err != nil {
		return nil, err
	}
	n := name.Record()
	intent := kernel.UsernameRenameIntent{Change: identity.IdentifierChange{TenantID: r.TenantID, UserID: bindings.UserID, ID: r.IdentifierID, Action: identity.IdentifierRename, Kind: identity.IdentifierUsername, CanonicalValue: n.Canonical, DisplayValue: n.Display, NormalizationProfile: string(n.ProfileID), NormalizationVersion: n.ProfileVersion, ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion, ExpectedIdentifierVersion: r.ExpectedIdentifierVersion, ExpectedVerificationVersion: r.ExpectedVerificationVersion}}
	// Pure validation catches a stale/no-op/foreign record before any keyed
	// reservation; the kernel repeats this against its locked primary state.
	if _, err = identity.ApplyIdentifierChange(state, intent.Change, time.Now().UTC()); err != nil {
		return nil, err
	}
	fields, err := kernel.UsernameRenameFields(intent)
	if err != nil {
		return nil, err
	}
	fields = append(fields, identity.FeatureField{Name: "action-primary.actor-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factorVersion}}, identity.FeatureField{Name: "action-primary.target-factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factorVersion}}, identity.FeatureField{Name: "username.rename.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}})
	op := actionPrimaryOperation("identity.username.update")
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: bindings.UserID, ActorID: identity.ActorID(bindings.UserID), ActorKind: authorization.SubjectUser, RecordID: string(r.IdentifierID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.primary.primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(id)}
	command, err := primary.Command(b, fields)
	if err != nil {
		return nil, err
	}
	command, counter, err := s.counters.PrepareCommandCounters(command, risk.Subject{User: string(bindings.UserID), Session: bindings.SessionID, Network: r.Network}, r.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return nil, err
	}
	return &usernameRenamePhase{service: s, request: r, primary: primary, intent: intent, command: command, counter: counter, factorVersion: factorVersion}, nil
}

// Format redacts borrowed owners and startup custody.
func (UsernameRenameService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.UsernameRenameService(redacted)"))
}

// MarshalJSON refuses implicit owner export.
func (UsernameRenameService) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// Format redacts startup secrets and correlated scopes.
func (UsernameRenameConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.UsernameRenameConfig(redacted)"))
}

// MarshalJSON refuses implicit configuration export.
func (UsernameRenameConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
