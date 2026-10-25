package reference

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkeypg "github.com/faustbrian/go-passkey/postgres"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// MagicLinkTOTPCompletionConfig selects the original magic-link/TOTP native
// completion profile, not HTTP or primary challenge issuance. The selected
// reference graph constructs it from its actual counted risk, original request
// owner and explicit MagicLinkTOTPConfiguration; authority profiles are not
// independently overridden by consumers.
// ComparisonKey is independent versioned cryptographic comparison custody,
// never derived from a factor secret. Retain CookieKeys for every live original
// browser flow. Inputs/providers are borrowed immutable, bounded and concurrent-
// safe; no constructor callback, IO, bootstrap or background work is performed.
// This profile does not select enrollment, trusted devices or TOTP transport.
type MagicLinkTOTPCompletionConfig struct {
	MaximumDuration      time.Duration
	ConfigurationID      string
	PolicyID             string
	Coordinator          kernel.CoordinatorConfig
	Issuer               capabilitypg.IssuerConfig
	Session              sessionpg.Config
	Profile              sessionpg.MagicLinkAdmissionConfig
	SessionIssuer        session.IssuerConfig
	CSRF                 session.CSRFKey
	CookieKeys           map[uint32]session.DigestKey
	Risk                 risk.ProtectedProviderAdmissionCustodyConfig
	Counters             riskpg.Config
	ComparisonKey        [32]byte
	ComparisonKeyVersion uint32
	ActiveEnvelopeKeyID  string
}

// Format redacts signing, session, envelope and comparison-key custody.
func (MagicLinkTOTPCompletionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.MagicLinkTOTPCompletionConfig(redacted)"))
}

// MarshalJSON rejects implicit secret-bearing configuration export.
func (MagicLinkTOTPCompletionConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText rejects implicit text/map-key configuration export.
func (MagicLinkTOTPCompletionConfig) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// LogValue redacts all native key/policy configuration.
func (MagicLinkTOTPCompletionConfig) LogValue() slog.Value {
	return slog.StringValue("reference.MagicLinkTOTPCompletionConfig(redacted)")
}

// The closure prevents diagnostic traversal of borrowed providers and key
// configuration even when fmt suppresses methods on an unexported parent field.
type magicLinkTOTPService struct{ state func() *magicLinkTOTPState }
type magicLinkTOTPState struct {
	pool           *database.Pool
	request        *magicpg.RequestService
	password       *passwordpg.SigninService
	verification   *passwordpg.VerificationSigninService
	passkey        *passkeypg.SigninService
	config         MagicLinkTOTPCompletionConfig
	issuer         *capabilitypg.Issuer
	directory      *kernel.Repository
	continuation   *mfapg.ContinuationReader
	factors        *mfapg.TOTPFactorReader
	policy         *policy.AuthorityStore
	crypto         *envelope.Service
	verifier       mfa.TOTPVerifier
	custody        risk.ProtectedProviderAdmissionCustody
	counters       *riskpg.Repository
	effect         *sessionpg.MFATOTPCompletionEffect
	passkeyEffect  *sessionpg.MFAPasskeyTOTPCompletionEffect
	recoveryKeys   mfapg.RecoveryVerificationKeys
	recoveryEffect *sessionpg.MFARecoveryCompletionEffect
	history        *kernel.Coordinator
}

func invalidTOTPCompletion() error {
	return identity.InvalidInputError{Field: "reference_mfa_totp"}
}

func newMagicLinkTOTPService(pool *database.Pool, request *magicpg.RequestService, c MagicLinkTOTPCompletionConfig, keys *keyring.Provider) (*magicLinkTOTPService, error) {
	return newNativeTOTPService(pool, request, nil, c, sessionpg.IdentifierAdmissionConfig{}, keys)
}

func newPasswordTOTPService(pool *database.Pool, primary *passwordpg.SigninService, c MagicLinkTOTPCompletionConfig, profile sessionpg.IdentifierAdmissionConfig, keys *keyring.Provider) (*magicLinkTOTPService, error) {
	return newNativeTOTPService(pool, nil, primary, c, profile, keys)
}

func newPhonePasswordTOTPService(pool *database.Pool, primary *passwordpg.SigninService, c MagicLinkTOTPCompletionConfig, profile sessionpg.IdentifierAdmissionConfig, keys *keyring.Provider) (*magicLinkTOTPService, error) {
	return newNativeMFAServiceMode(pool, nil, primary, nil, c, profile, keys, nil, true)
}

func newNativeTOTPService(pool *database.Pool, request *magicpg.RequestService, passwordPrimary *passwordpg.SigninService, c MagicLinkTOTPCompletionConfig, passwordProfile sessionpg.IdentifierAdmissionConfig, keys *keyring.Provider) (*magicLinkTOTPService, error) {
	return newNativeMFAService(pool, request, passwordPrimary, nil, c, passwordProfile, keys, nil)
}

func newNativeRecoveryService(pool *database.Pool, request *magicpg.RequestService, passwordPrimary *passwordpg.SigninService, c MagicLinkTOTPCompletionConfig, passwordProfile sessionpg.IdentifierAdmissionConfig, keys *keyring.Provider, recoveryKeys map[uint32][32]byte) (*magicLinkTOTPService, error) {
	if recoveryKeys == nil {
		return nil, invalidTOTPCompletion()
	}
	return newNativeMFAService(pool, request, passwordPrimary, nil, c, passwordProfile, keys, recoveryKeys)
}

func newNativeMFAService(pool *database.Pool, request *magicpg.RequestService, passwordPrimary *passwordpg.SigninService, verification *passwordpg.VerificationSigninService, c MagicLinkTOTPCompletionConfig, passwordProfile sessionpg.IdentifierAdmissionConfig, keys *keyring.Provider, recoveryKeys map[uint32][32]byte) (*magicLinkTOTPService, error) {
	return newNativeMFAServiceMode(pool, request, passwordPrimary, verification, c, passwordProfile, keys, recoveryKeys, false)
}

func newNativeMFAServiceMode(pool *database.Pool, request *magicpg.RequestService, passwordPrimary *passwordpg.SigninService, verification *passwordpg.VerificationSigninService, c MagicLinkTOTPCompletionConfig, passwordProfile sessionpg.IdentifierAdmissionConfig, keys *keyring.Provider, recoveryKeys map[uint32][32]byte, phone bool) (*magicLinkTOTPService, error) {
	return newNativeMFAServiceOrigin(pool, request, passwordPrimary, verification, nil, c, passwordProfile, sessionpg.MFAPasskeySessionAdmission{}, keys, recoveryKeys, phone)
}

func newPasskeyTOTPService(pool *database.Pool, primary *passkeypg.SigninService, c MagicLinkTOTPCompletionConfig, mapping sessionpg.MFAPasskeySessionAdmission, keys *keyring.Provider) (*magicLinkTOTPService, error) {
	return newNativeMFAServiceOrigin(pool, nil, nil, nil, primary, c, sessionpg.IdentifierAdmissionConfig{}, mapping, keys, nil, false)
}

func newNativeMFAServiceOrigin(pool *database.Pool, request *magicpg.RequestService, passwordPrimary *passwordpg.SigninService, verification *passwordpg.VerificationSigninService, passkeyPrimary *passkeypg.SigninService, c MagicLinkTOTPCompletionConfig, passwordProfile sessionpg.IdentifierAdmissionConfig, mapping sessionpg.MFAPasskeySessionAdmission, keys *keyring.Provider, recoveryKeys map[uint32][32]byte, phone bool) (*magicLinkTOTPService, error) {
	recovery := recoveryKeys != nil
	if phone && (passwordPrimary == nil || request != nil || verification != nil || passkeyPrimary != nil || recovery) || passkeyPrimary != nil && recovery {
		return nil, invalidTOTPCompletion()
	}
	origins := 0
	for _, present := range []bool{request != nil, passwordPrimary != nil, verification != nil, passkeyPrimary != nil} {
		if present {
			origins++
		}
	}
	if pool == nil || pool.Raw() == nil || origins != 1 || verification != nil && recovery || keys == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.MaximumDuration <= 0 || c.Coordinator.MaximumDuration > c.MaximumDuration || c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > c.MaximumDuration || !recovery && c.ComparisonKeyVersion == 0 || len(c.CookieKeys) == 0 || len(c.CookieKeys) > 32 || c.Issuer.Audience != c.Profile.Audience {
		return nil, invalidTOTPCompletion()
	}
	if c.Counters.CommandCounters == nil {
		return nil, invalidTOTPCompletion()
	}
	for _, value := range []string{c.ConfigurationID, c.PolicyID, c.ActiveEnvelopeKeyID} {
		if _, err := identity.ParseIdentifierID(value); err != nil {
			return nil, invalidTOTPCompletion()
		}
	}
	if c.Coordinator.QueryPolicy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || !sameServerAuthorization(c.Coordinator.QueryPolicy.Authorization, c.Coordinator.AdmissionPolicy.Authorization) {
		return nil, invalidTOTPCompletion()
	}
	probe, err := session.ParseToken(strings.Repeat("A", 43))
	if err != nil {
		return nil, invalidTOTPCompletion()
	}
	for version, key := range c.CookieKeys {
		digest, err := probe.Digest(key, "mfa-configuration")
		if err != nil || version == 0 || digest.KeyVersion != version {
			return nil, invalidTOTPCompletion()
		}
	}
	c.CookieKeys = maps.Clone(c.CookieKeys)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	s := &magicLinkTOTPState{pool: pool, request: request, password: passwordPrimary, verification: verification, passkey: passkeyPrimary, config: c}
	if recovery {
		s.recoveryKeys, err = mfapg.NewRecoveryVerificationKeys(recoveryKeys)
		if err != nil {
			return nil, invalidTOTPCompletion()
		}
	}
	s.issuer, err = capabilitypg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_issuer"}
	}
	s.directory, err = kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, invalidTOTPCompletion()
	}
	// History needs only the native journal reader and current query policy.
	// Mutation participants are selected separately for each exact invocation.
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory})
	if err != nil {
		return nil, invalidTOTPCompletion()
	}
	s.history, err = kernel.NewCoordinator(pool, registry, c.Coordinator)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_coordinator"}
	}
	s.continuation, err = mfapg.NewContinuationReader(pool, c.MaximumDuration)
	if err != nil {
		return nil, invalidTOTPCompletion()
	}
	if !recovery {
		s.factors, err = mfapg.NewTOTPFactorReader(pool, c.MaximumDuration)
		if err != nil {
			return nil, invalidTOTPCompletion()
		}
	}
	s.policy, err = policy.NewAuthorityStore(pool.Raw(), c.MaximumDuration)
	if err != nil {
		return nil, invalidTOTPCompletion()
	}
	s.crypto, err = envelope.NewService(keys)
	if err != nil {
		return nil, invalidTOTPCompletion()
	}
	if !recovery {
		s.verifier, err = mfa.NewTOTPVerifier(c.ComparisonKey)
		if err != nil {
			return nil, invalidTOTPCompletion()
		}
	}
	s.custody, err = risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_risk"}
	}
	if passkeyPrimary != nil {
		if mapping.Profile.GlobalAuthorityID != c.Profile.GlobalAuthorityID || mapping.Profile.PolicyNamespace != c.Profile.PolicyNamespace || mapping.Profile.Audience != c.Profile.Audience {
			return nil, invalidTOTPCompletion()
		}
		s.passkeyEffect, err = sessionpg.NewMFAPasskeyTOTPCompletionEffect(c.Session, mapping)
	} else if passwordPrimary != nil {
		if passwordProfile.GlobalAuthorityID != c.Profile.GlobalAuthorityID || passwordProfile.PolicyNamespace != c.Profile.PolicyNamespace || passwordProfile.Audience != c.Profile.Audience {
			return nil, invalidTOTPCompletion()
		}
		if recovery {
			s.recoveryEffect, err = sessionpg.NewMFAPasswordRecoveryCompletionEffect(c.Session, passwordProfile)
		} else if phone {
			s.effect, err = sessionpg.NewMFAPhonePasswordTOTPCompletionEffect(c.Session, passwordProfile)
		} else {
			s.effect, err = sessionpg.NewMFAPasswordTOTPCompletionEffect(c.Session, passwordProfile)
		}
	} else if verification != nil {
		s.effect, err = sessionpg.NewMFAVerificationTOTPCompletionEffect(c.Session, c.Profile)
	} else {
		if recovery {
			s.recoveryEffect, err = sessionpg.NewMFARecoveryCompletionEffect(c.Session, c.Profile)
		} else {
			s.effect, err = sessionpg.NewMFATOTPCompletionEffect(c.Session, c.Profile)
		}
	}
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_session_effect"}
	}
	if err := s.custody.ValidateCounterPolicy(c.Counters.CommandCounters.Policy); err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_counter_policy"}
	}
	s.counters, err = riskpg.NewRepository(c.Counters)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_counters"}
	}
	// Validate through the actual selected issuer constructor. The closed native
	// executor below cannot disclose anything without a reconciled exact receipt.
	if passkeyPrimary != nil {
		_, err = session.NewMFAPasskeySessionIssuerWithCSRF(&magicTOTPDelivery{}, c.SessionIssuer, c.CSRF)
	} else if passwordPrimary != nil {
		_, err = session.NewMFAPasswordSessionIssuerWithCSRF(&magicTOTPDelivery{}, c.SessionIssuer, c.CSRF)
	} else if verification != nil {
		_, err = session.NewMFAVerificationSessionIssuerWithCSRF(&magicTOTPDelivery{}, c.SessionIssuer, c.CSRF)
	} else {
		_, err = session.NewMFAMagicLinkSessionIssuerWithCSRF(&magicTOTPDelivery{}, c.SessionIssuer, c.CSRF)
	}
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp_session_issuer"}
	}
	return &magicLinkTOTPService{state: func() *magicLinkTOTPState { return s }}, nil
}

type magicTOTPInput struct {
	request             mfa.TotpVerifyRequest
	recovery            *mfa.RecoveryUseRequest
	command             identity.Command
	continuation        mfa.PartialAuthContinuation
	scope               mfa.ContinuationSpec
	child               kernel.CapabilityPlan
	flow                session.PreAuthTransaction
	primary             nativeMFAEmailPrimary
	passwordPrimary     *passwordpg.MFAPasswordPrimary
	verificationPrimary *passwordpg.MFAVerificationPrimary
	passkeyPrimary      *passkeypg.MFAPasskeyPrimary
	recipient           kernel.RecipientRecord
	directory           kernel.DirectoryAuthorityRecord
	policy              policy.AuthorityRecord
	snapshot            mfapg.TOTPFactorSnapshot
	secret              password.Secret
	comparison          []byte
	historical          *identity.CommandResult
	historyError        error
	missingFactor       bool
	rateUser            identity.UserID
	rateChallenge       string
	rateLifetime        time.Duration
}

// Email-possession metadata is shared storage vocabulary, not a magic-link
// consumption assertion. The distinct native origin above authenticates it.
type nativeMFAEmailPrimary struct {
	Recipient      kernel.RecipientRecord
	Authentication session.MagicLinkAuthentication
}

func (i *magicTOTPInput) primaryCommandID() (identity.CommandID, error) {
	if i == nil {
		return "", invalidTOTPCompletion()
	}
	if i.passwordPrimary != nil {
		if _, err := identity.ParseCommandID(string(i.passwordPrimary.CommandID)); err != nil {
			return "", err
		}
		return i.passwordPrimary.CommandID, nil
	}
	if i.passkeyPrimary != nil {
		return i.passkeyPrimary.CommandID, nil
	}
	p, err := i.primary.Authentication.Bindings()
	return p.CommandID, err
}

func (i *magicTOTPInput) userID() identity.UserID {
	if i.passkeyPrimary != nil {
		return i.passkeyPrimary.Primary.UserID
	}
	return i.recipient.User.ID
}

func (i *magicTOTPInput) browserCommandID() (identity.CommandID, error) {
	if i != nil && i.verificationPrimary != nil {
		return i.verificationPrimary.SignupCommandID, nil
	}
	return i.primaryCommandID()
}

func (i *magicTOTPInput) passwordCredential() (kernel.CredentialAdmission, error) {
	if i == nil || i.passwordPrimary == nil {
		return kernel.CredentialAdmission{}, invalidTOTPCompletion()
	}
	p := i.passwordPrimary.Authentication
	a, err := i.passwordPrimary.Authority.Bindings()
	if err != nil {
		return kernel.CredentialAdmission{}, err
	}
	return kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(p.CredentialID), TenantID: i.scope.TenantID, UserID: identity.UserID(i.scope.SubjectID), Kind: identity.CredentialPassword, Owner: "identity/password", Version: p.CredentialVersion}, UserAuthorityVersion: a.User.Version, IdentifierAuthorityVersion: a.Identifier.Version, CredentialAuthorityVersion: a.Credential.Version}, nil
}

func (i *magicTOTPInput) destroy() {
	if i != nil {
		i.secret.Destroy()
		clear(i.comparison)
	}
}

// readInput is a bounded pre-transaction ownership/admission path. It decrypts
// only the factor owner's fenced snapshot, before any native SQL locks. Actual
// code comparison, shared denial charge, replay consumption and session effects
// remain the protected native invocation's responsibility. It cannot issue.
func (s *magicLinkTOTPService) readInput(ctx context.Context, r mfa.TotpVerifyRequest) (out *magicTOTPInput, err error) {
	return s.readInputMode(ctx, r, false)
}

func (s *magicLinkTOTPService) readInputMode(ctx context.Context, r mfa.TotpVerifyRequest, rateSource bool) (out *magicTOTPInput, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Enrollment != nil || r.StepUp != nil || r.Validate() != nil {
		return nil, invalidTOTPCompletion()
	}
	return s.readNativeMFAInput(ctx, nativeMFAOriginalInput{TenantID: r.TenantID, CommandID: r.CommandID, ChallengeID: mfa.ContinuationID(r.ChallengeID), PreAuthID: r.PreAuthID, Proof: r.Proof, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Callback: r.Callback, Network: r.Network, Device: r.Device, totp: &r}, rateSource)
}

// Only validated public requests enter this shared primary/browser reader.
// It owns no factor comparison or transaction; method-specific credential
// custody stays in the original request, never converted into another method.
type nativeMFAOriginalInput struct {
	TenantID                          identity.TenantID
	CommandID                         identity.CommandID
	ChallengeID                       mfa.ContinuationID
	PreAuthID                         identity.PreAuthTransactionID
	Proof                             capability.Proof
	Cookie                            auth.BearerCredential
	Caller                            authorization.DecisionContext
	Origin, Callback, Network, Device string
	totp                              *mfa.TotpVerifyRequest
	recovery                          *mfa.RecoveryUseRequest
}

func (r nativeMFAOriginalInput) preparedInput() *magicTOTPInput {
	i := &magicTOTPInput{recovery: r.recovery}
	if r.totp != nil {
		i.request = *r.totp
	}
	return i
}

func (s *magicLinkTOTPService) readNativeMFAInput(ctx context.Context, r nativeMFAOriginalInput, rateSource bool) (out *magicTOTPInput, err error) {
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.destroy()
			out = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.totp != nil && r.totp.TrustDevice || r.Caller.PolicyRevision != authorization.Revision(state.config.Coordinator.AdmissionPolicy.PolicyVersion) {
		return nil, identity.ForbiddenError{}
	}
	grant, primaryID, replayVersion, err := state.issuer.ReadIssuanceOrigin(ctx, state.pool, r.Proof, "identity.mfa.complete")
	if err != nil {
		return nil, err
	}
	if grant.Payload().Tenant != string(r.TenantID) || grant.Payload().ID != string(r.ChallengeID) {
		return nil, identity.ForbiddenError{}
	}
	payload := grant.Payload()
	rateLifetime := payload.ExpiresAt.Sub(payload.IssuedAt)
	if rateSource && (rateLifetime < time.Second || rateLifetime > 5*time.Minute || rateLifetime%time.Microsecond != 0) {
		return nil, identity.ForbiddenError{}
	}
	if _, err := identity.ParseIdentifierID(payload.Subject); rateSource && err != nil {
		return nil, identity.ForbiddenError{}
	}
	var command identity.Command
	if r.recovery != nil {
		command, err = state.originalRecoveryCommand(*r.recovery, grant.EnvelopeDigest())
	} else {
		command, err = state.originalCommand(*r.totp, grant.EnvelopeDigest())
	}
	if err != nil {
		return nil, err
	}
	// Exact retries precede mutable factor/continuation reads: a previous denial
	// advanced that version, and a successful completion is no longer active.
	caller := r.Caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.PreAuthID)}
	var receipt identity.CommandResult
	var found bool
	var historyErr error
	if r.recovery != nil {
		receipt, found, historyErr = state.history.QueryMFARecoveryCommand(ctx, command, caller)
	} else {
		receipt, found, historyErr = state.history.QueryMFATOTPCommand(ctx, command, caller)
	}
	if found {
		// Historical errors belong to the original receipt, not current admission.
		// Retain no decrypted factor, session token or renewed authority here.
		if receipt.Validate() != nil {
			return nil, identity.UnavailableError{}
		}
		if rateSource && historyErr != nil {
			var denied identity.ForbiddenError
			// Found includes changed input. Only an exact retained denial may
			// supply source metadata; conflict or unavailable evidence cannot.
			if receipt.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(historyErr, &denied) {
				return nil, historyErr
			}
		}
		out = r.preparedInput()
		out.command, out.historical, out.historyError = command, &receipt, historyErr
		out.rateUser, out.rateChallenge, out.rateLifetime = identity.UserID(payload.Subject), payload.ID, rateLifetime
		return out, nil
	}
	if historyErr != nil {
		return nil, historyErr
	}
	continuation, err := state.continuation.Read(ctx, grant, grant.Payload().Issuer)
	if err != nil {
		return nil, err
	}
	c, err := continuation.Bindings()
	if err != nil || c.SourcePreAuthID != r.PreAuthID || c.Origin != r.Origin || c.PolicyVersion != state.config.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, identity.ForbiddenError{}
	}
	method := "totp"
	if r.recovery != nil {
		method = "recovery-code"
	}
	if !slices.Contains(c.AllowedMethods, method) {
		return nil, identity.ForbiddenError{}
	}
	flow, err := sessionpg.ReadPreAuth(ctx, state.pool.Raw(), state.config.Session, r.TenantID, r.PreAuthID)
	if err != nil {
		return nil, err
	}
	f, err := flow.Bindings()
	if err != nil || f.Binding.Intent.Origin != r.Origin || f.Binding.Intent.CallbackURL != r.Callback {
		return nil, identity.ForbiddenError{}
	}
	// The original request owner below authenticates its own primary PolicyID
	// against retained issuance. Completion has a distinct policy identity; it
	// must not relabel or compare that identity to the original browser intent.
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	digest, err := token.PreAuthDigest(state.config.CookieKeys[f.Cookie.KeyVersion], f.Binding)
	if err != nil || flow.Check(time.Now().UTC(), f.Binding, digest) != nil {
		return nil, identity.ForbiddenError{}
	}
	var primary nativeMFAEmailPrimary
	var passwordPrimary *passwordpg.MFAPasswordPrimary
	var verificationPrimary *passwordpg.MFAVerificationPrimary
	var passkeyPrimary *passkeypg.MFAPasskeyPrimary
	var current kernel.RecipientRecord
	var user identity.UserID
	if state.passkey != nil {
		// Subject attribution comes only from the authenticated signed child,
		// never a request-selected user. The native primary reader separately
		// checks its committed assertion, original scope and current authority.
		caller := r.Caller.Clone()
		caller.Request.Subject = authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(c.SubjectID)}
		caller.Request.Action = "identity.passkey.signin-verify"
		caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(c.SubjectID)}
		verified, err := state.passkey.ReadMFAPasskeyPrimary(ctx, r.Proof, continuation, flow, caller)
		if err != nil {
			return nil, err
		}
		if verified.CommandID != primaryID {
			return nil, identity.ForbiddenError{}
		}
		passkeyPrimary, user = &verified, verified.Primary.UserID
	} else if state.password != nil {
		verified, err := state.password.ReadMFAPasswordPrimary(ctx, r.Proof, continuation, flow, r.Caller)
		if err != nil {
			return nil, err
		}
		if verified.CommandID != primaryID {
			return nil, identity.ForbiddenError{}
		}
		passwordPrimary, current = &verified, verified.Recipient
	} else if state.verification != nil {
		verified, err := state.verification.ReadMFAVerificationPrimary(ctx, r.Proof, continuation, flow, r.Caller)
		if err != nil {
			return nil, err
		}
		if verified.CommandID != primaryID {
			return nil, identity.ForbiddenError{}
		}
		verificationPrimary, current = &verified, verified.Recipient
		primary = nativeMFAEmailPrimary{Recipient: verified.Recipient, Authentication: verified.Authentication}
	} else {
		parent, err := state.issuer.ReadMFAMagicLinkParent(ctx, state.pool, r.Proof, string(c.PrimaryProofID), c.PrimaryProofDigest, c.PrimaryProofExpiresAt)
		if err != nil {
			return nil, err
		}
		bindings, err := parent.Bindings()
		if err != nil || bindings.PrimaryCommandID != primaryID {
			return nil, identity.ForbiddenError{}
		}
		verified, readErr := state.request.ReadMFAMagicLinkPrimary(ctx, parent, flow, c.IssuedAt, r.Caller)
		err = readErr
		primary = nativeMFAEmailPrimary(verified)
		if err != nil {
			return nil, err
		}
		current, err = state.directory.ResolveRecipient(ctx, primary.Recipient.Query)
		if err != nil {
			return nil, err
		}
		original := primary.Recipient
		if current.Validate() != nil || current.Suppressed || current.User.ID != identity.UserID(c.SubjectID) || current.Identifier.ID != original.Identifier.ID || current.Identifier.Version != original.Identifier.Version || current.Verification.Version != original.Verification.Version || current.UserAuthorityVersion != original.UserAuthorityVersion || current.IdentifierAuthorityVersion != original.IdentifierAuthorityVersion || current.CredentialAuthorityVersion != original.CredentialAuthorityVersion {
			return nil, identity.ForbiddenError{}
		}
	}
	if passkeyPrimary == nil {
		user = current.User.ID
	}
	// Observe every authority epoch before the policy callback. A callback that
	// changes authority cannot be paired with a newly read epoch as its grant.
	directory, err := state.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: state.config.Profile.GlobalAuthorityID, TenantID: r.TenantID})
	if err != nil || !directory.Enabled {
		if err != nil {
			return nil, err
		}
		return nil, identity.ForbiddenError{}
	}
	epoch, err := state.policy.Get(ctx, policy.AuthorityScope{TenantID: authorization.TenantID(r.TenantID), SubjectID: authorization.SubjectID(user), PolicyNamespace: state.config.Profile.PolicyNamespace})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	if passwordPrimary != nil {
		a, err := passwordPrimary.Authority.Bindings()
		if err != nil || directory.GlobalVersion != a.Global.Version || directory.TenantVersion != a.Tenant.Version || epoch.Version != a.Authorization.Version {
			return nil, identity.ForbiddenError{}
		}
	}
	if verificationPrimary != nil {
		a, err := verificationPrimary.Authority.Bindings()
		if err != nil || directory.GlobalVersion != a.Global.Version || directory.TenantVersion != a.Tenant.Version || epoch.Version != a.Authorization.Version {
			return nil, identity.ForbiddenError{}
		}
	}
	if passkeyPrimary != nil {
		a, err := passkeyPrimary.Primary.Authority.Bindings()
		if err != nil || directory.GlobalVersion != a.Global.Version || directory.TenantVersion != a.Tenant.Version || epoch.Version != a.Authorization.Version {
			return nil, identity.ForbiddenError{}
		}
	}
	selected := r.Caller.Clone()
	selected.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	selected.Request.Environment.Time = time.Now().UTC()
	decision, err := state.config.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, selected)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != selected.PolicyRevision {
		return nil, identity.ForbiddenError{}
	}
	if rateSource {
		out = r.preparedInput()
		out.command = command
		out.rateUser, out.rateChallenge, out.rateLifetime = identity.UserID(payload.Subject), payload.ID, rateLifetime
		return out, nil
	}
	scope, scopeErr := continuation.ScopeDigest()
	if scopeErr != nil {
		return nil, identity.ForbiddenError{}
	}
	feature, _ := command.Feature()
	b := feature.Binding
	child, err := state.issuer.PrepareMFAConsumption(ctx, b, user, identity.CommandID(c.ID), scope, grant.Payload().Issuer, r.Proof, grant.EnvelopeDigest(), replayVersion)
	if err != nil {
		return nil, err
	}
	out = r.preparedInput()
	out.command, out.continuation, out.scope, out.child, out.flow = command, continuation, c, child, flow
	out.primary, out.passwordPrimary, out.recipient, out.directory, out.policy = primary, passwordPrimary, current, directory, epoch
	out.verificationPrimary = verificationPrimary
	out.passkeyPrimary = passkeyPrimary
	if r.recovery != nil {
		return out, nil
	}
	totp := r.totp
	snapshot, err := state.factors.Read(ctx, grant, grant.Payload().Issuer, string(totp.FactorID))
	if err != nil {
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) {
			return nil, err
		}
		// This is only a candidate, not proof of absence. The MFA owner must
		// recheck original authority and actual factor eligibility under locks.
		out.missingFactor = true
		return out, nil
	}
	metadata, err := snapshot.Metadata()
	if err != nil || metadata.ContinuationVersion != c.Version || metadata.ScopeDigest != scope || metadata.FactorAuthorityVersion != c.FactorVersion {
		return nil, identity.ForbiddenError{}
	}
	sealed, err := snapshot.Envelope()
	if err != nil {
		return nil, err
	}
	aad, err := snapshot.EncryptionContext()
	if err != nil {
		return nil, err
	}
	plain, err := state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) < 20 || len(plain) > 128 {
		return nil, identity.UnavailableError{}
	}
	secret, err := password.NewSecret(plain)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	out.snapshot, out.secret = snapshot, secret
	out.comparison, err = json.Marshal(struct {
		Domain, Tenant, User, Factor, Challenge string
		KeyVersion                              uint32
	}{"identity-mfa-totp-comparison-v1", string(r.TenantID), string(user), string(totp.FactorID), string(r.ChallengeID), state.config.ComparisonKeyVersion})
	return out, err
}

// originalCommand binds submitted intent, never a mutable continuation version
// or generated session. Proof identity comes only from the actual issuer's
// verified canonical envelope; borrowed proof custody is never transferred.
func (s *magicLinkTOTPState) originalCommand(r mfa.TotpVerifyRequest, proof [32]byte) (identity.Command, error) {
	if s == nil || proof == ([32]byte{}) || r.Validate() != nil || s.config.Coordinator.AdmissionPolicy == nil {
		return identity.Command{}, invalidTOTPCompletion()
	}
	op := magicTOTPCompletionOperation()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config.PolicyID, PolicyVersion: s.config.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID)}
	frame, err := json.Marshal(struct {
		Profile, Origin, Callback, Network, Device, Factor string
		Proof                                              [32]byte
		ComparisonVersion                                  uint32
		TrustDevice                                        bool
	}{s.config.ConfigurationID, r.Origin, r.Callback, r.Network, r.Device, string(r.FactorID), proof, s.config.ComparisonKeyVersion, r.TrustDevice})
	defer clear(frame)
	if err != nil {
		return identity.Command{}, invalidTOTPCompletion()
	}
	intent := sha256.Sum256(frame)
	return identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "mfa.input", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(intent[:])}}}}, r.Code, r.Cookie)
}

func magicTOTPCompletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// Delivery is a closed post-commit adapter, not an alternative transaction. It
// starts empty and is armed only by the reconciled native completion result.
type magicTOTPDelivery struct {
	recovery    bool
	command     identity.Command
	receipt     identity.CommandResult
	record      session.Session
	deliverable bool
}

func (p *magicTOTPDelivery) ExecuteIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || p == nil || !p.deliverable || ctx.Err() != nil || p.receipt.Validate() != nil || p.receipt.Outcome != identity.CommitOutcomeCommitted {
		return session.IssueExecution{}, invalidTOTPCompletion()
	}
	command, record, ok := request.MFACommand()
	if !ok || command != p.command {
		return session.IssueExecution{}, invalidTOTPCompletion()
	}
	mapFields := sessionpg.MFATOTPCompletionSessionFields
	if p.recovery {
		mapFields = sessionpg.MFARecoveryCompletionSessionFields
	}
	actual, err := mapFields(record)
	expected, expectedErr := mapFields(p.record)
	if err != nil || expectedErr != nil || !reflect.DeepEqual(actual, expected) {
		return session.IssueExecution{}, invalidTOTPCompletion()
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: p.record}, nil
}

func (*magicTOTPDelivery) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	// Native recovery is code-free and handled through the sole command owner;
	// an ephemeral IssueRequest cannot recover or redeliver credentials.
	return session.IssueExecution{}, identity.ForbiddenError{}
}

func clearTOTPDelivery(result *mfa.TotpVerifyResult) {
	result.Session.Token = session.Token{}
	result.Session.Cookie = http.Cookie{}
	result.CSRFToken = session.CSRFToken{}
}
