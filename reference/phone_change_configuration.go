package reference

import (
	"fmt"
	"slices"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PhoneChangeConfiguration independently selects native verified-phone
// replacement, not enrollment or HTTP. The graph injects its genuine password
// proof, email signin/reset, session, OTP, risk and delivery owners. Native.Issuer,
// both risk Evaluation/Keys and Notice.Delivery/Templates must be zero. Cookie
// primary CSRFKeys must be zero for injection from PasswordVerification. Sending
// and consuming primaries select distinct actions/audiences on the same owner.
type PhoneChangeConfiguration struct {
	Policy                     *phone.NumberPolicy
	SendPrimary, UpdatePrimary passwordpg.ActionPrimaryConfig
	Native                     passwordpg.PhoneChangeConfig
	Issuance                   PhoneIssuanceConfiguration
}

type phoneChangeState struct {
	owner          *passwordpg.PhoneChangeService
	policy         *phone.NumberPolicy
	provider       uint64
	noticeProvider uint64
}

func composePhoneChange(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proofs *passwordVerificationState, signin *passwordpg.SigninService, reset *passwordpg.ResetService) (*phoneChangeState, error) {
	if c.PhoneChange == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone_change"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || proofs == nil || proofs.native == nil || signin == nil || reset == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil || c.PasswordVerification == nil {
		return nil, invalid
	}
	n := *c.PhoneChange
	notice := n.Native.Notice.Delivery
	if n.Policy == nil || n.SendPrimary.Action != "identity.phone.send-verification" || n.UpdatePrimary.Action != "identity.phone.update" || n.Native.Issuer != nil || n.Native.AuthenticationRisk.Evaluation != (risk.Evaluator{}) || len(n.Native.AuthenticationRisk.Keys) != 0 || n.Native.UpdateRisk.Evaluation != (risk.Evaluator{}) || len(n.Native.UpdateRisk.Keys) != 0 || notice.Deployment != "" || notice.CurrentDigestKeyVersion != 0 || len(notice.RetainedDigestKeys) != 0 || notice.ActiveEnvelopeKeyID != "" || notice.PreparationTimeout != 0 || len(notice.ProviderProfiles) != 0 || len(n.Native.Notice.Templates) != 0 || n.Native.MaximumDuration > c.OTP.Timeout || n.Native.RequestKeys.Namespace == c.OTP.RequestKeys.Namespace || n.Native.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.Native.RequestKeys.Policy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || n.Native.Counters.Schema != c.Velocity.Schema || n.Native.Counters.CommandCounters == nil || n.Native.Counters.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !emailOTPSessionKeysMatch(c, n.Issuance.SessionKeys) {
		return nil, invalid
	}
	for _, primary := range []*passwordpg.ActionPrimaryConfig{&n.SendPrimary, &n.UpdatePrimary} {
		if primary.Transport == session.CredentialCookie {
			if len(primary.CSRFKeys) != 0 {
				return nil, invalid
			}
			primary.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
		}
	}
	send, err := passwordpg.NewActionPrimarySource(proofs.native, n.SendPrimary)
	if err != nil {
		return nil, err
	}
	update, err := passwordpg.NewActionPrimarySource(proofs.native, n.UpdatePrimary)
	if err != nil {
		return nil, err
	}
	codec, err := otppg.NewAttemptCodec(c.OTP.Codec)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, err
	}
	delivery, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, err
	}
	store := c.OTP.Store
	store.Codec, store.PreAuth, store.PreAuthCookieKeys = codec, sessionpg.Config{}, nil
	issuer, err := otppg.NewPhoneChangeIssuer(otppg.PhoneEnrollmentIssuerConfig{Store: store, Session: otppg.SessionAdmissionConfig{Store: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, RetainedTokenKeys: n.Issuance.SessionKeys, FreshnessLimit: n.Issuance.FreshnessLimit}, Delivery: delivery, Policy: n.Issuance.Policy, TemplateID: n.Issuance.TemplateID, TemplateVersion: n.Issuance.TemplateVersion, ProviderVersion: n.Issuance.ProviderVersion, LocaleChain: n.Issuance.LocaleChain, Templates: c.Delivery.Templates})
	if err != nil {
		return nil, err
	}
	n.Native.Issuer = issuer
	n.Native.AuthenticationRisk.Evaluation, n.Native.AuthenticationRisk.Keys = evaluation, slices.Clone(c.OTP.RiskKeys)
	n.Native.UpdateRisk.Evaluation, n.Native.UpdateRisk.Keys = evaluation, slices.Clone(c.OTP.RiskKeys)
	n.Native.Notice.Delivery, n.Native.Notice.Templates = c.Delivery.Enqueue.Custody, c.Delivery.Templates
	policy := *n.Policy
	owner, err := passwordpg.NewPhoneChangeService(send, update, signin, reset, &policy, n.Native, keys)
	if err != nil {
		return nil, fmt.Errorf("reference phone change: %w", err)
	}
	return &phoneChangeState{owner: owner, policy: &policy, provider: n.Issuance.ProviderVersion, noticeProvider: n.Native.Notice.ProviderVersion}, nil
}

// Format redacts retained native configuration and key custody.
func (PhoneChangeConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneChangeConfiguration(redacted)"))
}

// MarshalJSON rejects implicit native configuration export.
func (PhoneChangeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// MarshalText rejects implicit native configuration/map-key export.
func (PhoneChangeConfiguration) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
