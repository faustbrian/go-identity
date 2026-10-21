package anonymouspostgres

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// UpgradeConfig composes the existing guest, password, capability and session
// owners. Guest supplies disposal/retention, primary stores, request-key custody
// and protected risk counters; it does not select deletion permission. Primary
// must select identity.anonymous.upgrade and ProofAudience. Target is the real
// single-factor password session profile. Both original cookies require CSRF.
// Capability and CapabilityPreparation must retain their keys for recovery.
// Install the corresponding forward histories before use. Constructors perform
// no IO, migration, entropy or provider work. Borrow pools/clocks until calls end.
type UpgradeConfig struct {
	Guest                 DeletionConfig
	Primary               *passwordpg.ActionPrimarySource
	Target                sessionpg.SessionServiceConfig
	TargetCSRFKeys        []session.CSRFKey
	ProofAudience         string
	Issuer                session.IssuerConfig
	CSRF                  session.CSRFKey
	Capability            capabilitypg.IssuerConfig
	CapabilityPreparation capabilitypg.IssuancePreparationConfig
}

// UpgradeService owns native composition, not a second transaction, proof,
// session or replay engine. Immutable configuration permits concurrent calls;
// every call retains its own phase and reveal-once prospective session.
type UpgradeService struct {
	guest      *DeletionService
	primary    *passwordpg.ActionPrimarySource
	target     *session.SessionService
	effect     *sessionpg.AnonymousUpgradeEffect
	capability *capabilitypg.Issuer
	checkpoint *capabilitypg.IssuancePreparationCodec
	intentKey  session.DigestKey
	intentCSRF session.CSRFKey
	config     func() UpgradeConfig
	profile    [32]byte
}

// Explicit trusted projection for the configuration commitment only. The
// public correlated profile deliberately rejects generic serialization.
type upgradeStoredTargetProfile sessionpg.IdentifierAdmissionConfig

var _ anonymous.Upgrader = (*UpgradeService)(nil)

// NewUpgradeService freezes explicit native owner composition. This finite
// profile preserves an existing permanent account, transferring no application
// resources or credentials. Unsupported merge decisions and enrolled MFA deny.
func NewUpgradeService(pool *database.Pool, c UpgradeConfig, keys *keyring.Provider) (*UpgradeService, error) {
	if c.Primary == nil || !c.Primary.Matches(upgradeOperation().OperationID, c.ProofAudience) || !signinText(c.ProofAudience, 128) || len(c.TargetCSRFKeys) == 0 || len(c.TargetCSRFKeys) > 4 || c.CSRF.Version() == 0 || c.Target.Repository != c.Guest.Sessions || c.Target.Profile.GlobalAuthorityID != c.Guest.Profile.GlobalAuthorityID || c.Target.Profile.Audience != c.Guest.Profile.Audience {
		return nil, anonymous.ErrInvalidInput
	}
	guest, err := NewDeletionService(pool, c.Guest, keys)
	if err != nil {
		return nil, err
	}
	c.Guest = guest.config()
	target, err := sessionpg.NewSessionService(pool, c.Target)
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewAnonymousUpgradeEffect(c.Guest.Sessions, sessionpg.IssueAdmissionConfig(c.Target.Profile))
	if err != nil {
		return nil, err
	}
	issuer, err := capabilitypg.NewIssuer(c.Capability)
	if err != nil {
		return nil, err
	}
	checkpoint, err := capabilitypg.NewIssuancePreparationCodec(issuer, c.CapabilityPreparation)
	if err != nil {
		return nil, err
	}
	c.TargetCSRFKeys = slices.Clone(c.TargetCSRFKeys)
	c.Target.Validation.LookupKeys = slices.Clone(c.Target.Validation.LookupKeys)
	for i, key := range c.TargetCSRFKeys {
		if key.Version() == 0 {
			return nil, anonymous.ErrInvalidInput
		}
		for _, previous := range c.TargetCSRFKeys[:i] {
			if previous.Version() == key.Version() {
				return nil, anonymous.ErrInvalidInput
			}
		}
	}
	frame, err := json.Marshal(struct {
		Guest                [32]byte
		Target               upgradeStoredTargetProfile
		Audience, Deployment string
	}{guest.profile, upgradeStoredTargetProfile(c.Target.Profile), c.ProofAudience, c.CapabilityPreparation.Deployment})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	// RFC 5869 purpose-separated keys commit opaque input without revealing it.
	// Their source is the retained request-intent key, not the newest transport
	// key: rotating session/CSRF keys must not change an original retry's intent.
	// These keys grant no session or CSRF authority; actual possession is checked
	// independently against the session's recorded, retained transport keys.
	material, err := hkdf.Key(sha256.New, c.Guest.IntentKey[:], nil, "identity-anonymous-upgrade-intent-credential-v1", 32)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	intentKey, err := session.NewDigestKey(1, material)
	clear(material)
	if err != nil {
		return nil, err
	}
	material, err = hkdf.Key(sha256.New, c.Guest.IntentKey[:], nil, "identity-anonymous-upgrade-intent-csrf-v1", 32)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	intentCSRF, err := session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, err
	}
	s := &UpgradeService{guest: guest, primary: c.Primary, target: target, effect: effect, capability: issuer, checkpoint: checkpoint, intentKey: intentKey, intentCSRF: intentCSRF, config: func() UpgradeConfig { return c }, profile: profile}
	p := &upgradePreparation{service: s}
	p.final = &upgradeExecution{preparation: p}
	if _, _, err = p.coordinatorFor(false); err != nil {
		return nil, err
	}
	if _, _, err = p.coordinatorFor(true); err != nil {
		return nil, err
	}
	if _, err = session.NewAnonymousUpgradeSessionIssuerWithCSRF(p.final, c.Issuer, c.CSRF); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *UpgradeService) targetPossession(tenant identity.TenantID, bearer auth.BearerCredential, csrf session.CSRFToken, original session.Session) bool {
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return false
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return false
	}
	b, err := original.Bindings()
	if err != nil || b.TenantID != tenant || b.Authentication.Kind != session.AuthenticationVerified {
		return false
	}
	matched := false
	for _, key := range s.config().Target.Validation.LookupKeys {
		digest, err := credential.Digest(key, string(tenant))
		if err == nil && digest.KeyVersion == b.Lookup.KeyVersion && subtle.ConstantTimeCompare(digest.Sum[:], b.Lookup.Sum[:]) == 1 {
			matched = true
		}
	}
	if !matched {
		return false
	}
	for _, key := range s.config().TargetCSRFKeys {
		if original.CSRFState().Check(session.CSRFBinding{TenantID: tenant, SessionID: b.SessionID, SessionVersion: b.Version}, csrf, key) == nil {
			return true
		}
	}
	return false
}

func (s *UpgradeService) intent(r anonymous.UpgradeRequest) (identity.RequestIntent, error) {
	merge, err := upgradeMergeDigest(r.Plan)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	remember, err := r.Remember.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	guest, err := r.Guest.Digest(s.intentKey, string(r.TenantID))
	if err != nil {
		return identity.RequestIntent{}, err
	}
	token, err := session.ParseToken(r.TargetSession.Token())
	if err != nil {
		return identity.RequestIntent{}, err
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	target, err := credential.Digest(s.intentKey, string(r.TenantID))
	if err != nil {
		return identity.RequestIntent{}, err
	}
	// Commit the submitted synchronizers without using their reveal-once seam.
	// This intent-only scope grants nothing; both actual session bindings are
	// independently authenticated before request admission and on recovery.
	csrfIntent := session.CSRFBinding{TenantID: r.TenantID, SessionID: "anonymous-upgrade-intent-v1", SessionVersion: 1}
	gcsrf, err := r.GuestCSRF.Digest(s.intentCSRF, csrfIntent)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	tcsrf, err := r.TargetCSRF.Digest(s.intentCSRF, csrfIntent)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	guestCSRF, _ := gcsrf.Bindings()
	targetCSRF, _ := tcsrf.Bindings()
	frame, err := json.Marshal(struct {
		Tenant                  identity.TenantID
		Guest, Target           session.TokenDigest
		GuestCSRF, TargetCSRF   session.CSRFStateSpec
		Proof                   auth.ReauthenticationProof
		Merge                   [32]byte
		Remember                session.RememberPolicySpec
		Caller                  authorization.DecisionContext
		Origin, Network, Device string
	}{r.TenantID, guest, target, guestCSRF, targetCSRF, r.TargetProof, merge, remember, r.Caller, r.Origin, r.Network, r.Device})
	defer clear(frame)
	if err != nil {
		return identity.RequestIntent{}, anonymous.ErrInvalidInput
	}
	key := s.config().Guest.IntentKey
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-anonymous-upgrade-intent-v1\x00"))
	mac.Write(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}}, {Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}})
}

// Upgrade commits original grant issuance first, then atomically consumes that
// grant and fresh target proof with all guest/session effects. Unknown retains
// both original correlations. Only a known newly committed final execution may
// reveal its invocation-local session; retries and recovery reveal no secrets.
func (s *UpgradeService) Upgrade(ctx context.Context, r anonymous.UpgradeRequest) (out anonymous.UpgradeResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil || !supportedUpgradePlan(r.Plan) {
		return out, anonymous.ErrInvalidInput
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Guest.Repository.MaximumDuration)
	defer stop()
	var unknownCommand identity.CommandID
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			out.Session, out.CSRFToken = session.IssueResult{}, session.CSRFToken{}
			err = signinPublicError(ctx, err)
			if ctx.Err() == nil && out.Outcome == identity.CommitOutcomeUnknown && unknownCommand != "" {
				err = identity.UnknownCommitError{CommandID: unknownCommand}
			}
		}
	}()
	if !slices.Contains(s.config().Guest.Origins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	intent, err := s.intent(r)
	if err != nil {
		return out, err
	}
	p := &upgradePreparation{service: s, request: r}
	defer func() { clear(p.output.Proof); clear(p.output.Checkpoint) }()
	p.final = &upgradeExecution{preparation: p}
	p.coordinator, p.registry, err = p.coordinatorFor(false)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Plan.Target), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: upgradeOperation().OperationID}
	caller := s.guest.caller(r.TenantID, identity.UserID(r.Plan.Target), upgradeOperation().OperationID, "identity.request-admission", upgradeOperation().OperationID)
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restoreInput(ctx, k, wire, intent); err != nil {
		return out, err
	}
	out.Preparation, out.Recovery = deletionQuery(p.input.Preparation), deletionQuery(p.input.Final.Binding)
	out.Outcome = identity.CommitOutcomeUnknown
	unknownCommand = out.Preparation.CommandID
	declaration, err := p.plan(true)
	if err != nil {
		return out, err
	}
	receipt, err := p.coordinator.ExecutePreparedFeature(ctx, p.original, declaration)
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		out.Outcome, out.RetryAfter = receipt.Outcome, receipt.RetryAfter
		return out, err
	}
	if err != nil {
		return out, err
	}
	unknownCommand = out.Recovery.CommandID
	// A terminal issuance replay intentionally skips generation/restoration.
	// Read only its existing authenticated output; never sign a replacement.
	if p.command == (identity.Command{}) {
		wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, out.Preparation, s.guest.caller(r.TenantID, identity.UserID(r.Plan.Target), upgradeOperation().OperationID, "identity.user", string(r.Plan.Target)), p.registration(), p)
		if err != nil {
			return out, err
		}
		defer clear(wire)
		if _, _, err = p.restoreOutput(ctx, p.original, generation, wire, false); err != nil {
			return out, err
		}
	}
	return p.final.execute(ctx, out)
}

// RecoverUpgrade authenticates both original cookies/CSRF and exact retained
// two-command scope. It reconciles existing owner evidence only: no current
// signin, new proof, grant generation, mutation or credential redelivery.
func (s *UpgradeService) RecoverUpgrade(ctx context.Context, r anonymous.UpgradeRecoveryRequest) (out anonymous.UpgradeResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, anonymous.ErrInvalidInput
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Guest.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			err = signinPublicError(ctx, err)
		}
	}()
	p := &upgradePreparation{service: s, request: anonymous.UpgradeRequest{TenantID: r.Recovery.TenantID, TargetSession: r.TargetSession, TargetCSRF: r.TargetCSRF, Guest: r.Guest, GuestCSRF: r.GuestCSRF, Origin: r.Origin, Network: r.Network, Device: r.Device}}
	p.final = &upgradeExecution{preparation: p}
	p.coordinator, p.registry, err = p.coordinatorFor(false)
	if err != nil {
		return out, err
	}
	caller := s.guest.caller(r.Recovery.TenantID, r.Recovery.UserID, r.Recovery.OperationID, "identity.user", string(r.Recovery.UserID))
	k, wire, err := p.coordinator.QueryRequestPreparation(ctx, r.Preparation, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restoreInput(ctx, k, wire, identity.RequestIntent{}); err != nil {
		return out, err
	}
	if deletionQuery(p.input.Preparation) != r.Preparation || deletionQuery(p.input.Final.Binding) != r.Recovery {
		return out, identity.ForbiddenError{}
	}
	out.Preparation, out.Recovery, out.Outcome, out.Replayed = r.Preparation, r.Recovery, identity.CommitOutcomeUnknown, true
	prepared, err := p.coordinator.RecoverFeatureCommand(ctx, r.Preparation, caller)
	if err != nil || prepared.Outcome != identity.CommitOutcomeCommitted {
		out.Outcome, out.RetryAfter = prepared.Outcome, prepared.RetryAfter
		return out, err
	}
	final, _, err := p.coordinatorFor(true)
	if err != nil {
		return out, err
	}
	receipt, err := final.RecoverFeatureCommand(ctx, r.Recovery, caller)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	return out, err
}

func (UpgradeConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.UpgradeConfig(redacted)"))
}
func (UpgradeConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (UpgradeConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (*UpgradeService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.UpgradeService(redacted)"))
}
func (*UpgradeService) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
