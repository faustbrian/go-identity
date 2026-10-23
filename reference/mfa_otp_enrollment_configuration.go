package reference

import (
	"fmt"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// MFAOTPEnrollmentConfiguration selects native pending OTP enrollment, delivered
// confirmation and original recovery. It enables no HTTP route or login method.
// Native.Primary and Native.Risk.Evaluation must be absent: the graph supplies
// its actual password proof and counted risk owners. Policy must select consuming
// MFA challenges; templates and SessionKeys must match this graph's delivery and
// password-session owners. FreshnessLimit cannot renew original session custody.
// Configuration and borrowed dependencies must remain immutable during use.
type MFAOTPEnrollmentConfiguration struct {
	Native            mfapg.OTPEnrollmentConfig
	Primary           passwordpg.MFAEnablePrimaryConfig
	CSRFKeys          []session.CSRFKey
	AllowedOrigins    []string
	SessionKeys       map[uint32][]byte
	FreshnessLimit    time.Duration
	Policy            otp.AttemptPolicy
	AttemptKeyVersion uint32
	TemplateID        string
	TemplateVersion   uint32
	LocaleChain       []string
}

type mfaOTPEnrollmentState struct {
	enable  *mfapg.OTPEnrollmentService
	send    *mfapg.OTPEnrollmentSendService
	confirm *mfapg.OTPEnrollmentConfirmationService
	issuer  *otppg.MFAEnrollmentIssuer
}

func composeMFAOTPEnrollment(c StoreConfiguration, d ReferenceDependencies, verification *passwordVerificationState, evaluation risk.Evaluator) (*mfaOTPEnrollmentState, error) {
	if c.MFAOTPEnrollment == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_mfa_otp_enrollment"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || c.PasswordVerification == nil || verification == nil || verification.native == nil || c.OTP == nil || c.Delivery == nil || c.Session == nil {
		return nil, invalid
	}
	p, o := c.MFAOTPEnrollment, c.OTP
	n := p.Native
	if n.Primary != nil || n.Risk.Evaluation != (risk.Evaluator{}) || n.MaximumDuration > o.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy || n.RequestKeys.Namespace == o.RequestKeys.Namespace || n.RequestKeys.Policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.RequestKeys.Policy.Authorization, o.RequestKeys.Policy.Authorization) || !emailOTPSessionKeysMatch(c, p.SessionKeys) {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy} {
		if policy == nil || policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, o.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	for _, action := range []risk.Action{"identity.mfa.enable", "identity.mfa.otp-send", "identity.mfa.otp-verify"} {
		profile, err := n.Counters.CommandCounters.Policy.Admit(action)
		if err != nil || profile.Profile.Class != risk.CredentialMutation || profile.PolicyVersion != n.Counters.PolicyVersion {
			return nil, invalid
		}
	}
	primary, err := passwordpg.NewMFAEnablePrimarySource(verification.native, p.Primary)
	if err != nil {
		return nil, invalid
	}
	primary, err = passwordpg.NewCookieMFAEnablePrimarySource(primary, p.CSRFKeys)
	if err != nil {
		return nil, invalid
	}
	n.Primary, n.Risk.Evaluation = primary, evaluation
	enable, err := mfapg.NewOTPEnrollmentService(d.PostgreSQL, n, keys)
	if err != nil {
		return nil, invalid
	}
	codec, err := otppg.NewAttemptCodec(o.Codec)
	if err != nil {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	delivery, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, invalid
	}
	store := o.Store
	store.Codec, store.PreAuth, store.PreAuthCookieKeys = codec, sessionpg.Config{}, nil
	issuer, err := otppg.NewMFAEnrollmentIssuer(otppg.MFAEnrollmentIssuerConfig{Store: store, Session: otppg.SessionAdmissionConfig{Store: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, RetainedTokenKeys: p.SessionKeys, FreshnessLimit: p.FreshnessLimit}, Delivery: delivery, Policy: p.Policy, TemplateID: p.TemplateID, TemplateVersion: p.TemplateVersion, ProviderVersion: o.ProviderVersion, LocaleChain: p.LocaleChain, Templates: c.Delivery.Templates})
	if err != nil {
		return nil, invalid
	}
	send, err := mfapg.NewOTPEnrollmentSendService(enable, mfapg.OTPEnrollmentSendConfig{Primary: primary, Issuance: issuer, AllowedOrigins: p.AllowedOrigins})
	if err != nil {
		return nil, invalid
	}
	confirm, err := mfapg.NewOTPEnrollmentConfirmationService(send, mfapg.OTPEnrollmentConfirmationConfig{Primary: primary, AttemptKeyVersion: p.AttemptKeyVersion})
	if err != nil {
		return nil, invalid
	}
	return &mfaOTPEnrollmentState{enable: enable, send: send, confirm: confirm, issuer: issuer}, nil
}

// Format hides native key, session and policy custody.
func (MFAOTPEnrollmentConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.MFAOTPEnrollmentConfiguration(redacted)"))
}

// MarshalJSON rejects implicit export of secret-bearing startup configuration.
func (MFAOTPEnrollmentConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects implicit textual export of startup custody.
func (MFAOTPEnrollmentConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// LogValue redacts startup configuration in structured logs.
func (MFAOTPEnrollmentConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.MFAOTPEnrollmentConfiguration(redacted)")
}
