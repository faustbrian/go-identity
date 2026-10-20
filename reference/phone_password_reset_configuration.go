package reference

import (
	"context"
	"crypto/subtle"
	"fmt"
	"slices"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PhonePasswordResetConfiguration independently selects the native SMS plus
// confirmed independent-TOTP recovery profile, not HTTP or phone signin. Both
// native carrier-risk enablement flags remain mandatory. This initial reference
// profile requires DurableAdmission; it reuses that exact durable counter state.
//
// The graph supplies Request.SMS, Request.Delivery.Owner/Renderer, both risk
// key lists, Risk.Issuer.Evaluation/Executor, Risk.Store.UseIssuer/UseCounters and
// Completion.TOTP; those fields must be zero. Risk.Coordinator must retain the
// graph's authoritative query/admission policy. Other native configuration,
// canonical issuer/key custody, external carrier evaluator and bounded HIBP
// collector remain explicit. PreAuth uses actual retained password-flow keys,
// exact origin/callback and zero Remember. Issuance selects the SMS template and
// OTP policy; its session-key/freshness fields are unused and must be zero.
// If email password reset is also selected, it must use the same session schema;
// mixed reset stores are rejected rather than rewriting installed email history.
// No fake store, accepted factor or caller-selected account can be supplied.
type PhonePasswordResetConfiguration struct {
	Policy               *phone.NumberPolicy
	Request              passwordpg.PhonePasswordResetRequestConfig
	Completion           passwordpg.PhonePasswordResetCompletionConfig
	Issuance             PhoneIssuanceConfiguration
	PreAuth              PasswordPreAuthConfiguration
	ComparisonKey        [32]byte
	ComparisonKeyVersion uint32
}

type phonePasswordResetState struct {
	owner                  *passwordpg.PhonePasswordResetService
	request                *passwordpg.PhonePasswordResetRequestService
	sms                    *otppg.PhonePasswordResetIssuer
	preauth                *session.PreAuthIssuer
	bind                   func(context.Context, identity.TenantID, string) ([32]byte, error)
	policy                 *phone.NumberPolicy
	preauthConfig          PasswordPreAuthConfiguration
	provider, linkProvider uint64
	policyID               string
	policyVersion          uint64
}

func composePhonePasswordReset(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, primary *passwordpg.SigninService, state *storeState) (*phonePasswordResetState, error) {
	if c.PhonePasswordReset == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone_password_reset"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || primary == nil || state == nil || !state.durable || c.DurableAdmission == nil || c.PasswordSignin == nil || c.Session == nil || c.OTP == nil || c.Delivery == nil {
		return nil, invalid
	}
	p := *c.PhonePasswordReset
	n, o := c.PasswordSignin.Native, c.OTP
	if c.PasswordReset != nil && c.PasswordReset.Native.Session.Schema != n.Session.Schema {
		// identity_reset_session has immutable installed SQL/checksums. Selecting
		// phone recovery must not move an existing email reset's physical owner.
		return nil, invalid
	}
	r := p.Request
	commandPolicy := o.RequestKeys.Policy
	if p.Policy == nil || p.Policy.Profile() != phone.CurrentNumberProfile() || r.SMS != nil || r.Delivery.Owner != nil || r.Delivery.Renderer != nil || r.Risk.Issuer.Evaluation != (risk.Evaluator{}) || r.Risk.Issuer.Executor != nil || len(r.Risk.Issuer.Keys) != 0 || len(r.Risk.Store.EvidenceKeys) != 0 || r.Risk.Store.UseIssuer != nil || r.Risk.Store.UseCounters != nil || p.Completion.TOTP != nil || p.Completion.Screening.Now != nil || r.Risk.Store.Schema != c.DurableAdmission.Schema || r.Risk.Store.PolicyVersion != commandPolicy.PolicyVersion || r.RequestKeys.Policy.PolicyVersion != commandPolicy.PolicyVersion || !sameServerAuthorization(r.RequestKeys.Policy.Authorization, commandPolicy.Authorization) || len(p.Issuance.SessionKeys) != 0 || p.Issuance.FreshnessLimit != 0 || n.Session.Schema != c.Session.Native.Execution.Repository.Schema || n.Session.Schema != o.Store.PreAuth.Schema || !slices.Contains(n.Origins, p.PreAuth.Origin) || !slices.Contains(n.CallbackURLs, p.PreAuth.CallbackURL) || !slices.Contains(r.Profile.Callbacks, p.PreAuth.CallbackURL) || r.Delivery.Endpoint != p.PreAuth.CallbackURL || uint64(p.PreAuth.FlowKeyIndex) >= uint64(len(n.FlowKeys)) || !phonePasswordResetFlowKeysMatch(n.FlowKeys, o.Store.PreAuthCookieKeys) {
		return nil, invalid
	}
	if r.Risk.Coordinator.QueryPolicy == nil || r.Risk.Coordinator.AdmissionPolicy == nil {
		return nil, invalid
	}
	for _, policy := range []struct {
		version uint64
		service any
	}{{r.Risk.Coordinator.QueryPolicy.PolicyVersion, r.Risk.Coordinator.QueryPolicy.Authorization}, {r.Risk.Coordinator.AdmissionPolicy.PolicyVersion, r.Risk.Coordinator.AdmissionPolicy.Authorization}} {
		if policy.version != commandPolicy.PolicyVersion || !sameServerAuthorization(policy.service, commandPolicy.Authorization) {
			return nil, invalid
		}
	}
	var counters *riskpg.DurableCounterStore
	for _, tenant := range state.tenants {
		current, ok := tenant.counter.(riskpg.DurableCounterStore)
		if !ok {
			return nil, invalid
		}
		if counters == nil {
			counters = &current
		} else if current != *counters {
			return nil, invalid
		}
	}
	if counters == nil {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, err
	}
	owner, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, err
	}
	renderer, err := delivery.NewTemplateRenderer(c.Delivery.Templates)
	if err != nil {
		return nil, err
	}
	codec, err := otppg.NewAttemptCodec(o.Codec)
	if err != nil {
		return nil, err
	}
	store := o.Store
	store.Codec = codec
	sms, err := otppg.NewPhonePasswordResetIssuer(otppg.PhonePasswordResetIssuerConfig{Store: store, Delivery: owner, Policy: p.Issuance.Policy, TemplateID: p.Issuance.TemplateID, TemplateVersion: p.Issuance.TemplateVersion, ProviderVersion: p.Issuance.ProviderVersion, LocaleChain: p.Issuance.LocaleChain, Templates: c.Delivery.Templates})
	if err != nil {
		return nil, err
	}
	r.SMS, r.Delivery.Owner, r.Delivery.Renderer = sms, owner, renderer
	r.Risk.Issuer.Evaluation, r.Risk.Issuer.Keys = evaluation, slices.Clone(o.RiskKeys)
	r.Risk.Store.EvidenceKeys, r.Risk.Store.UseCounters = slices.Clone(o.RiskKeys), counters
	policy := *p.Policy
	request, err := passwordpg.NewPhonePasswordResetRequestService(primary, &policy, r, keys)
	if err != nil {
		return nil, err
	}
	verifier, err := mfapg.NewPhoneRecoveryTOTPVerifier(crypto, p.ComparisonKey, p.ComparisonKeyVersion)
	if err != nil {
		return nil, err
	}
	completion := p.Completion
	completion.TOTP, completion.Screening.Now = verifier, time.Now
	native, err := passwordpg.NewPhonePasswordResetService(request, completion)
	if err != nil {
		return nil, err
	}
	pre := p.PreAuth
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: n.Session, Coordinator: n.Coordinator, Authorization: n.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: pre.ActorID, Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", Origin: pre.Origin, CallbackURL: pre.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, AuditRetentionVersion: pre.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: pre.ActorID, Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", Origin: pre.Origin, CallbackURL: pre.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, Clock: clock.System{}, MaximumDuration: n.Session.MaximumDuration, FlowTTL: pre.FlowTTL, LookupKey: n.FlowKeys[pre.FlowKeyIndex], TokenSize: pre.TokenSize, Cookie: pre.Cookie})
	if err != nil {
		return nil, err
	}
	identifierKey := slices.Clone(n.IdentifierKey)
	return &phonePasswordResetState{owner: native, request: request, sms: sms, preauth: issuer, policy: &policy, preauthConfig: pre, provider: p.Issuance.ProviderVersion, linkProvider: r.Delivery.ProviderVersion, policyID: n.PolicyID, policyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, bind: func(ctx context.Context, tenant identity.TenantID, raw string) ([32]byte, error) {
		number, err := policy.Canonicalize(ctx, raw)
		if err != nil {
			return [32]byte{}, err
		}
		return phone.PasswordResetIdentifierBinding(number, tenant, identifierKey)
	}}, nil
}

// Compare opaque keys through their owning digest, never reflection, exported
// material or key-version equality alone. Both readers must retain the same set.
func phonePasswordResetFlowKeysMatch(keys []session.DigestKey, material map[uint32][]byte) bool {
	if len(keys) == 0 || len(keys) != len(material) {
		return false
	}
	probe, _ := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	seen := make(map[uint32]bool, len(keys))
	for _, key := range keys {
		expected, err := probe.Digest(key, "reference-phone-password-reset-flow-keys")
		if err != nil || seen[expected.KeyVersion] {
			return false
		}
		seen[expected.KeyVersion] = true
		other, err := session.NewDigestKey(expected.KeyVersion, material[expected.KeyVersion])
		if err != nil {
			return false
		}
		actual, err := probe.Digest(other, "reference-phone-password-reset-flow-keys")
		if err != nil || subtle.ConstantTimeCompare(expected.Sum[:], actual.Sum[:]) != 1 {
			return false
		}
	}
	return true
}

func (PhonePasswordResetConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhonePasswordResetConfiguration(redacted)"))
}
func (PhonePasswordResetConfiguration) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
func (PhonePasswordResetConfiguration) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
