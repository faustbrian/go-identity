package mfapostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// TOTPActivePrimary retains the original authenticated session and synchronizer
// binding for native active-factor verification. Snapshot contains no bearer.
// Admit borrows preparation Work; Check requires the exact final Apply command.
// Neither operation verifies a factor or renews the original observation.
type TOTPActivePrimary interface {
	TOTPURIPrimary
	Snapshot() ([]byte, error)
}

// TOTPActivePrimarySource is the native current-session boundary. Prepare must
// use a real primary session adapter and return its owned observation unchanged.
// Restore accepts only snapshot bytes authenticated by the native MFA envelope;
// it is IO-free and rechecks submitted bearer/CSRF possession. Protected current
// owner checks remain mandatory even after a successful restore.
type TOTPActivePrimarySource interface {
	PrepareStepUp(context.Context, mfa.TotpVerifyRequest) (TOTPActivePrimary, session.GetResult, error)
	RestoreStepUp(context.Context, mfa.TotpVerifyRequest, []byte) (TOTPActivePrimary, error)
}

// FactorVerificationSigningKey owns immutable Ed25519 custody for the existing
// authentication original-reauthentication frame. It is not an access-token key
// or a new signature format. Copies share immutable custody; erase caller bytes.
type FactorVerificationSigningKey struct {
	sign   func(auth.SignedReauthenticationRecord) (auth.SignedReauthenticationRecord, error)
	public func() (string, ed25519.PublicKey)
}

// NewFactorVerificationSigningKey copies a complete consistent private key.
// Rotation must retain the public key while original journal evidence exists.
func NewFactorVerificationSigningKey(id string, key ed25519.PrivateKey) (FactorVerificationSigningKey, error) {
	if !factorEvidenceKeyID(id) || len(key) != ed25519.PrivateKeySize {
		return FactorVerificationSigningKey{}, invalidAuthority()
	}
	owned := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(owned, key) {
		clear(owned)
		return FactorVerificationSigningKey{}, invalidAuthority()
	}
	return FactorVerificationSigningKey{sign: func(r auth.SignedReauthenticationRecord) (auth.SignedReauthenticationRecord, error) {
		r.KeyID, r.Signature = id, nil
		frame, err := r.SigningBytes()
		if err != nil {
			return auth.SignedReauthenticationRecord{}, invalidAuthority()
		}
		defer clear(frame)
		r.Signature = ed25519.Sign(owned, frame)
		return r, nil
	}, public: func() (string, ed25519.PublicKey) {
		return id, ed25519.PublicKey(slices.Clone(owned[ed25519.SeedSize:]))
	}}, nil
}

func factorEvidenceKeyID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		if id[i] < 33 || id[i] > 126 {
			return false
		}
	}
	return true
}

// TOTPActiveStepUpConfig explicitly selects authenticated TOTP for recovery
// regeneration. Issuer/environment/audience and lifetime are startup policy,
// never request overrides. Comparison and signing keys must be independent of
// lookup, envelope, recovery and command keys. Origins are exact HTTPS origins.
// Counters, risk, coordinator and encryption use the borrowed enrollment graph.
type TOTPActiveStepUpConfig struct {
	Primary                       TOTPActivePrimarySource
	AllowedOrigins                []string
	ComparisonKey                 [32]byte
	ComparisonKeyVersion          uint32
	SigningKey                    FactorVerificationSigningKey
	VerificationKeys              map[string]ed25519.PublicKey
	Issuer, Environment, Audience string
	TTL                           time.Duration
}

// TOTPActiveStepUpService verifies a real enrolled factor and persists original
// signed evidence together with replay advancement, audit and lifecycle effects.
// It never issues a session. Calls have private participants; borrowed owners
// must remain available until calls drain. No background work or private journal.
type TOTPActiveStepUpService struct{ state func() *activeStepUpState }
type activeStepUpState struct {
	shared   *totpEnrollmentState
	config   TOTPActiveStepUpConfig
	verifier mfa.TOTPVerifier
	reader   *TOTPFactorReader
	identity [32]byte
}

// NewTOTPActiveStepUpService freezes selected native composition without IO.
// Install FactorVerificationMigrationSource before calling the service.
func NewTOTPActiveStepUpService(enrollment *TOTPEnrollmentService, c TOTPActiveStepUpConfig) (*TOTPActiveStepUpService, error) {
	if enrollment == nil || enrollment.state == nil || nilEnrollmentPrimary(c.Primary) || c.ComparisonKey == ([32]byte{}) || c.ComparisonKeyVersion == 0 || c.SigningKey.sign == nil || c.SigningKey.public == nil || c.TTL < time.Second || c.TTL > 5*time.Minute || c.TTL%time.Microsecond != 0 || len(c.AllowedOrigins) < 1 || len(c.AllowedOrigins) > 16 || len(c.VerificationKeys) < 1 || len(c.VerificationKeys) > 64 {
		return nil, invalidAuthority()
	}
	for _, value := range []string{c.Issuer, c.Environment, c.Audience} {
		if !enrollmentText(value, 128) {
			return nil, invalidAuthority()
		}
	}
	c.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	slices.Sort(c.AllowedOrigins)
	for i, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin || i > 0 && origin == c.AllowedOrigins[i-1] {
			return nil, invalidAuthority()
		}
	}
	c.VerificationKeys = maps.Clone(c.VerificationKeys)
	for id, key := range c.VerificationKeys {
		if !factorEvidenceKeyID(id) || len(key) != ed25519.PublicKeySize {
			return nil, invalidAuthority()
		}
		c.VerificationKeys[id] = slices.Clone(key)
	}
	id, key := c.SigningKey.public()
	if !bytes.Equal(c.VerificationKeys[id], key) {
		return nil, invalidAuthority()
	}
	s := &activeStepUpState{shared: enrollment.state(), config: c}
	var err error
	s.verifier, err = mfa.NewTOTPVerifier(c.ComparisonKey)
	if err != nil {
		return nil, err
	}
	s.reader, err = NewTOTPFactorReader(s.shared.pool, s.shared.config.MaximumDuration)
	if err != nil {
		return nil, err
	}
	admitted, err := s.shared.config.Counters.CommandCounters.Policy.Admit("identity.mfa.totp-verify")
	if err != nil || admitted.Profile.Class != risk.CredentialMutation {
		return nil, invalidAuthority()
	}
	frame, err := json.Marshal(struct {
		Shared                             [32]byte
		Origins                            []string
		Issuer, Environment, Audience, Key string
		Public                             ed25519.PublicKey
		Comparison                         [32]byte
		Version                            uint32
		TTL                                time.Duration
	}{s.shared.identity, c.AllowedOrigins, c.Issuer, c.Environment, c.Audience, id, key, sha256.Sum256(c.ComparisonKey[:]), c.ComparisonKeyVersion, c.TTL})
	if err != nil {
		return nil, invalidAuthority()
	}
	s.identity = sha256.Sum256(frame)
	clear(frame)
	return &TOTPActiveStepUpService{state: func() *activeStepUpState { return s }}, nil
}

func activeStepUpOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-step-up", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *activeStepUpState) intent(r mfa.TotpVerifyRequest) ([32]byte, error) {
	scope, err := json.Marshal(struct {
		Profile, Tenant, User, Factor, Command, Purpose, Origin, Network string
		Version                                                          uint32
	}{"mfa-active-step-up-v1", string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.FactorID), string(r.CommandID), string(r.StepUp.Purpose), r.Origin, r.Network, s.config.ComparisonKeyVersion})
	if err != nil {
		return [32]byte{}, invalidAuthority()
	}
	defer clear(scope)
	code, err := r.Code.CommandDigest(s.config.ComparisonKey, string(scope))
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(code[:])
	mac := hmac.New(sha256.New, s.config.ComparisonKey[:])
	_, _ = mac.Write(scope)
	_, _ = mac.Write(code[:])
	_, _ = mac.Write([]byte(r.StepUp.Session.Token()))
	_, _ = mac.Write(s.identity[:])
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest, nil
}

// TotpVerify accepts only the explicit authenticated StepUp arm. Original
// encrypted preparation is reused before current-source reads on retry. Actual
// TOTP verification and signature persistence run in one protected transaction;
// known terminal replay, ambiguity, cancellation and recovery return no proof.
func (s *TOTPActiveStepUpService) TotpVerify(ctx context.Context, r mfa.TotpVerifyRequest) (out mfa.TotpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.StepUp == nil || r.Validate() != nil {
		return out, invalidAuthority()
	}
	state := s.state()
	if !slices.Contains(state.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	p := &activeStepUpPhase{state: state, request: r}
	defer p.destroy()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.StepUpProof = mfa.ContinuationProof{}
		}
	}()
	p.coordinator, p.registry, err = state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	if err = authorizeNativeMFAAction(ctx, state.shared, r.Caller, "identity.mfa.totp-verify"); err != nil {
		return out, err
	}
	if err = p.load(ctx); err != nil {
		return out, err
	}
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	result, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	out.Outcome = result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		if !time.Now().Before(p.until) {
			return out, identity.ForbiddenError{}
		}
		out.StepUpProof, err = mfa.NewContinuationProof(p.record.Original.Proof)
	}
	return out, err
}

// RecoverTotpVerify resolves historical issuance without a factor code or proof
// redelivery. It never advances replay or reconstructs current authority.
func (s *TOTPActiveStepUpService) RecoverTotpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.TotpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != activeStepUpOperation().OperationID {
		return out, invalidAuthority()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.shared.config.MaximumDuration)
	defer stop()
	p := &activeStepUpPhase{state: state}
	c, _, err := state.shared.coordinator(p)
	if err != nil {
		return out, err
	}
	r, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.Outcome = r.Outcome
	return out, err
}

// Format redacts cryptographic custody and correlated configuration.
func (FactorVerificationSigningKey) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.FactorVerificationSigningKey(redacted)"))
}

// MarshalJSON rejects implicit key export.
func (FactorVerificationSigningKey) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit key export.
func (FactorVerificationSigningKey) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format redacts cryptographic custody and correlated configuration.
func (TOTPActiveStepUpConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPActiveStepUpConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (TOTPActiveStepUpConfig) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit configuration export.
func (TOTPActiveStepUpConfig) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format redacts borrowed native owners.
func (TOTPActiveStepUpService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPActiveStepUpService(redacted)"))
}

// MarshalJSON rejects implicit service export.
func (TOTPActiveStepUpService) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit service export.
func (TOTPActiveStepUpService) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

var _ mfa.TOTPCompletionService = (*TOTPActiveStepUpService)(nil)
