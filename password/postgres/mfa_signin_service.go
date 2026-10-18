package passwordpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

// MFAChallengeConfig explicitly selects password-first MFA continuations.
// Issuer and Custody retain their native key/clock ownership contracts; use
// independent signing, replay and envelope keys. Lifetime is whole seconds,
// at most five minutes, and capped by original password/browser expiry.
// Install password primary, MFA continuation/selected factor and complete capability
// histories before calling. This configuration is not request data or a UI.
type MFAChallengeConfig struct {
	// AllowedMethods is an owned explicit TOTP/OTP selection with optional recovery-code.
	// Empty preserves the existing TOTP-only profile. Selection grants no factor
	// authority; completion independently verifies the enrolled method and shares
	// one original attempt budget. Unsupported methods and duplicates deny.
	AllowedMethods []string
	Lifetime       time.Duration
	MaxAttempts    uint32
	IssuerURL      string
	Issuer         issuerpg.IssuerConfig
	Custody        issuerpg.IssuancePreparationConfig
}

// Format redacts all deployment and key configuration.
func (MFAChallengeConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.MFAChallengeConfig(redacted)")
}

// MarshalJSON denies implicit secret-bearing configuration export.
func (MFAChallengeConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit textual configuration export.
func (MFAChallengeConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

type signinMFAComposition struct {
	config MFAChallengeConfig
	issuer *issuerpg.Issuer
	codec  *issuerpg.IssuancePreparationCodec
}

// NewMFASigninService freezes explicit native password/MFA composition without
// IO. Known empty factor authority may use ordinary SFA; enrolled users receive
// only a committed continuation. Missing/unsupported factor state denies.
// The existing NewSigninService remains unchanged. Pool and policy collaborators
// are borrowed and must outlive bounded concurrent calls. No session is issued
// before actual second-factor completion. Username selection is unsupported;
// use NewSigninService for the known-empty-factor username profile.
func NewMFASigninService(pool *database.Pool, c SigninConfig, m MFAChallengeConfig) (*SigninService, error) {
	// MFA challenge custody and recovery retain the password operation. Until
	// username continuation is selected, reject the mixed profile at startup
	// rather than issue an original username outcome that cannot be recovered.
	if c.Username != nil {
		return nil, password.ErrPasswordWork
	}
	methods, methodErr := freezeMFACompletionMethods(m.AllowedMethods)
	if methodErr != nil {
		return nil, methodErr
	}
	u, err := url.Parse(m.IssuerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || len(m.IssuerURL) > 2048 || m.Lifetime < time.Second || m.Lifetime > 5*time.Minute || m.Lifetime%time.Second != 0 || m.MaxAttempts < 1 || m.MaxAttempts > 100 || m.Issuer.Audience != c.Profile.Audience {
		return nil, password.ErrPasswordWork
	}
	s, err := NewSigninService(pool, c)
	if err != nil {
		return nil, err
	}
	i, err := issuerpg.NewIssuer(m.Issuer)
	if err != nil {
		return nil, err
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(i, m.Custody)
	if err != nil {
		return nil, err
	}
	// All cryptographic configuration is frozen by its actual owner factories;
	// retain only non-secret lifetime/issuer policy here.
	s.mfa = &signinMFAComposition{config: MFAChallengeConfig{AllowedMethods: methods, Lifetime: m.Lifetime, MaxAttempts: m.MaxAttempts, IssuerURL: m.IssuerURL}, issuer: i, codec: codec}
	return s, nil
}

func (s *SigninService) signinMFA(ctx context.Context, r password.SigninRequest, b identity.CommandBinding, recipient kernel.RecipientRecord, material password.CredentialSnapshot, flow session.PreAuthTransaction, key session.DigestKey, admission risk.AuthenticationAdmission, authority session.AuthoritySnapshot, factor uint64, upgrade *kernel.PasswordHashUpgradeIntent, replacement primitive.EncodedHash, out password.SigninResult) (password.SigninResult, error) {
	at := s.c.Issuance.Clock.Now().UTC().Truncate(time.Second)
	until := at.Add(min(s.c.ProofTTL, s.mfa.config.Lifetime))
	f, _ := flow.Bindings()
	if f.Binding.ExpiresAt.Before(until) {
		until = f.Binding.ExpiresAt.UTC().Truncate(time.Second)
	}
	m := material.Authority()
	if !m.ExpiresAt.IsZero() && m.ExpiresAt.Before(until) {
		until = m.ExpiresAt.UTC().Truncate(time.Second)
	}
	version := m.Credential.Version
	if upgrade != nil {
		version++
	}
	vector, _ := authority.Bindings()
	primary, err := s.c.SigningKey.signMFAPrimary(mfaSigninPrimary{Profile: mfaSigninPrimaryProfile, State: auth.SignInStateChallengeRequired, Issuer: s.c.Issuer, Environment: s.c.Environment, ProofVersion: 1, CredentialID: string(m.Credential.ID), CredentialVersion: version, IdentifierID: recipient.Identifier.ID, IdentifierVersion: recipient.Identifier.Version, VerificationVersion: recipient.Verification.Version, Authority: vector, Proof: auth.Proof{ID: auth.ProofID(b.CommandID), Tenant: string(b.TenantID), Subject: string(recipient.User.ID), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: session.PasswordMFAPrimaryPurpose, Audience: s.c.Profile.Audience, IssuedAt: at, ExpiresAt: until}})
	if err != nil {
		return out, fmt.Errorf("password MFA primary: %w", err)
	}
	wire, digest, err := encodeMFASigninPrimary(primary)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	id, err := identity.NewCommandID()
	if err != nil {
		return out, err
	}
	continuation, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: mfa.ContinuationID(id), PrimaryProofID: primary.Proof.ID, PrimaryProofDigest: digest, PrimaryProofExpiresAt: until, TenantID: b.TenantID, SubjectID: identity.SubjectID(recipient.User.ID), SourcePreAuthID: r.PreAuthID, Origin: r.Origin, AllowedMethods: s.mfa.config.AllowedMethods, PolicyVersion: b.PolicyVersion, FactorVersion: factor, RememberPolicy: r.Remember, Purpose: "identity.mfa.complete", Audience: s.c.Profile.Audience, IssuedAt: at, ExpiresAt: until, MaxAttempts: s.mfa.config.MaxAttempts, AttemptsRemaining: s.mfa.config.MaxAttempts, State: mfa.Pending, Version: 1})
	if err != nil {
		return out, err
	}
	payload, err := continuation.CapabilityPayload(s.mfa.config.IssuerURL)
	if err != nil {
		return out, err
	}
	prepared, err := s.mfa.issuer.PrepareMFAContinuation(ctx, b, payload)
	if err != nil {
		return out, err
	}
	var proof capability.Proof
	checkpoint, err := s.mfa.codec.CheckpointPreparation(ctx, prepared, 1, func(_ context.Context, index uint16, raw []byte) error {
		if index != 0 {
			return password.ErrPasswordWork
		}
		var e error
		proof, e = capability.ParseProof(string(raw), capability.DefaultLimits())
		return e
	})
	if err != nil {
		return out, err
	}
	defer clear(checkpoint)
	authorityWire, err := json.Marshal(vector)
	if err != nil {
		return out, err
	}
	scope, err := continuation.ScopeDigest()
	if err != nil {
		return out, err
	}
	fields := []identity.FeatureField{
		{Name: "password.mfa.primary", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}},
		{Name: "password.mfa.scope", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: scope[:]}},
		{Name: "password.mfa.authority", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: authorityWire}},
		{Name: "password.mfa.checkpoint", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: checkpoint}},
	}
	if upgrade != nil {
		extra, e := kernel.PasswordHashUpgradeFields(*upgrade)
		if e != nil {
			return out, e
		}
		fields = append(fields, extra...)
		fields = append(fields, signinRehashCommitment(replacement))
	}
	command, err := identity.NewFeaturePasswordSigninCommand(identity.FeatureCommandSpec{Binding: b, Operation: signinOperation(), Fields: fields}, r.Password, r.Cookie)
	if err != nil {
		return out, err
	}
	p := &signinMFAChallengePhase{service: s, command: command, request: r, recipient: recipient, material: material, flow: flow, key: key, admission: admission, authority: vector, primary: primary, continuation: continuation, prepared: prepared, upgrade: upgrade, replacement: replacement}
	coordinator, registry, err := s.mfaCoordinator(p)
	if err != nil {
		return out, fmt.Errorf("password MFA coordinator: %w", err)
	}
	plan, err := p.plan(coordinator, registry, at)
	if err != nil {
		return out, fmt.Errorf("password MFA plan: %w", err)
	}
	reservation, receipt, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err == nil && reservation != (kernel.Reservation{}) {
		work, e := coordinator.Begin(ctx, reservation)
		if e != nil {
			receipt.Outcome = identity.CommitOutcomeUnknown
			err = e
		} else {
			defer coordinator.Abort(work, identity.UnavailableError{})
			receipt, err = coordinator.ApplyFeature(ctx, work, command)
			if err != nil {
				receipt, err = coordinator.Abort(work, err)
			} else {
				receipt, err = coordinator.Commit(work, receipt)
			}
		}
	} else if reservation == (kernel.Reservation{}) {
		out.Issuance.Replayed = true
	}
	out.Issuance.CommitOutcome, out.Issuance.RetryAfter = receipt.Outcome, receipt.RetryAfter
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		out.State = auth.SignInStateChallengeRequired
		out.Challenge = password.MFAChallengeResult{ID: id, Method: "totp", ExpiresAt: until}
		if err == nil && !out.Issuance.Replayed {
			err = p.checkDelivery(ctx, s.c.Issuance.Clock.Now())
			if err == nil {
				out.Challenge.Proof = proof
			}
		}
	}
	return out, err
}

func freezeMFACompletionMethods(input []string) ([]string, error) {
	if len(input) == 0 {
		return []string{"totp"}, nil
	}
	if len(input) > 3 {
		return nil, password.ErrPasswordWork
	}
	methods := slices.Clone(input)
	slices.Sort(methods)
	if !slices.Contains(methods, "totp") && !slices.Contains(methods, "otp") {
		return nil, password.ErrPasswordWork
	}
	for i, method := range methods {
		if method != "totp" && method != "otp" && method != "recovery-code" || i > 0 && method == methods[i-1] {
			return nil, password.ErrPasswordWork
		}
	}
	return methods, nil
}
