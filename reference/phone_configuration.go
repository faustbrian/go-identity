package reference

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PhoneConfiguration selects native existing-account enrollment and consuming
// SMS verification, not HTTP or login. The graph supplies its actual proof,
// pool, counted risk, OTP codec/session, encrypted delivery and migration owners.
// Primary.Action must be identity.phone.send-verification. Native.Issuer and
// Native.Risk.Evaluation must be zero for graph injection. RequestKeys must use
// a distinct namespace under the graph's same authoritative policy. Every
// retention/key/cooldown policy stays explicit in its native configuration.
type PhoneConfiguration struct {
	Policy   *phone.NumberPolicy
	Primary  passwordpg.ActionPrimaryConfig
	Native   passwordpg.PhoneVerificationConfig
	Issuance PhoneIssuanceConfiguration
}

// PhoneIssuanceConfiguration selects an existing SMS template/provider and
// consuming phone-verification OTP policy. SessionKeys must match the graph's
// current password issuer and retained session readers. FreshnessLimit can only
// shorten native source validity. Locale/key inputs are copied by native owners.
type PhoneIssuanceConfiguration struct {
	Policy          otp.AttemptPolicy
	SessionKeys     map[uint32][]byte
	FreshnessLimit  time.Duration
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	LocaleChain     []string
}

type phoneState struct {
	owner    *passwordpg.PhoneVerificationService
	policy   *phone.NumberPolicy
	provider uint64
}

func composePhone(c StoreConfiguration, d ReferenceDependencies, evaluator risk.Evaluator, proofs *passwordVerificationState) (*phoneState, error) {
	if c.Phone == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	n := *c.Phone
	if !ok || keys == nil || d.PostgreSQL == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil || c.PasswordSignin == nil || proofs == nil || proofs.native == nil || n.Policy == nil || n.Policy.Profile() != phone.CurrentNumberProfile() || n.Primary.Action != "identity.phone.send-verification" || n.Native.Issuer != nil || n.Native.Risk.Evaluation != (risk.Evaluator{}) || n.Native.MaximumDuration > c.OTP.Timeout || n.Native.RequestKeys.Namespace == c.OTP.RequestKeys.Namespace || n.Native.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.Native.RequestKeys.Policy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || !emailOTPSessionKeysMatch(c, n.Issuance.SessionKeys) {
		return nil, invalid
	}
	primary, err := passwordpg.NewActionPrimarySource(proofs.native, n.Primary)
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
	issuer, err := otppg.NewPhoneEnrollmentIssuer(otppg.PhoneEnrollmentIssuerConfig{Store: store, Session: otppg.SessionAdmissionConfig{Store: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, RetainedTokenKeys: n.Issuance.SessionKeys, FreshnessLimit: n.Issuance.FreshnessLimit}, Delivery: delivery, Policy: n.Issuance.Policy, TemplateID: n.Issuance.TemplateID, TemplateVersion: n.Issuance.TemplateVersion, ProviderVersion: n.Issuance.ProviderVersion, LocaleChain: n.Issuance.LocaleChain, Templates: c.Delivery.Templates})
	if err != nil {
		return nil, err
	}
	n.Native.Issuer, n.Native.Risk.Evaluation = issuer, evaluator
	snapshot := *n.Policy
	owner, err := passwordpg.NewPhoneVerificationService(primary, &snapshot, n.Native, keys)
	if err != nil {
		return nil, err
	}
	return &phoneState{owner: owner, policy: &snapshot, provider: n.Issuance.ProviderVersion}, nil
}

// Format redacts retained native configuration and session key custody.
func (PhoneConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneConfiguration(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (PhoneConfiguration) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// MarshalText rejects implicit text/map-key configuration export.
func (PhoneConfiguration) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// Format redacts retained session issuance keys.
func (PhoneIssuanceConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PhoneIssuanceConfiguration(redacted)"))
}

// MarshalJSON rejects implicit issuance configuration export.
func (PhoneIssuanceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}

// MarshalText rejects implicit issuance configuration export.
func (PhoneIssuanceConfiguration) MarshalText() ([]byte, error) {
	return nil, phone.ErrVerificationDisclosure
}
