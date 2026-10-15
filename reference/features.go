package reference

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// OTPSendConfiguration selects the native public Send workflow. It has the
// same bounds and retained-key obligations as otp/postgres.SendConfig, except
// risk, templates and delivery custody are owned once by this graph. Risk uses
// Velocity's exact policy/key history, real wall time and the native router.
// ConfigurationID versions the retained admission semantics; change it when
// those semantics change. RiskTimeout/AuditTimeout are 1ms..5s, with audit
// inside risk and risk inside Timeout. Only velocity-only profiles are supported
// in this development composition; no missing source gets an allow-all default.
type OTPSendConfiguration struct {
	// BootstrapTenantIDs is the explicit immutable 0..256-entry directory set.
	// Empty bootstraps no tenants and grants no tenant authority. It is never
	// inferred from velocity scopes or users. Retain it after migration apply;
	// later onboarding uses the owning lifecycle APIs, not edited migrations.
	BootstrapTenantIDs            []identity.TenantID
	Store                         otppg.ContributorConfig
	Codec                         otppg.AttemptCodecConfig
	Session                       *otppg.SessionAdmissionConfig
	Coordinator                   kernel.CoordinatorConfig
	RequestKeys                   kernel.RequestKeyConfig
	Policy                        otp.AttemptPolicy
	TemplateID                    string
	TemplateVersion               uint32
	LocaleChain                   []string
	ProviderVersion               uint64
	PolicyID                      string
	PolicyVersion                 uint64
	PreAuthAction                 string
	IntentKey, IdentifierKey      [32]byte
	Timeout                       time.Duration
	RiskTimeout, AuditTimeout     time.Duration
	RiskPolicyID, ConfigurationID string
	RiskKeys                      []risk.EvidenceKey
	// Signin explicitly enables the native single-factor consuming workflow.
	// Nil exposes Send only. Supply current admission/query policy, independent
	// session/CSRF keys and the matching deployment authority namespace. The
	// selected session namespace may share the pre-auth or authenticated store.
	// Additional-factor policy must deny until the MFA profile is composed.
	Signin *otppg.SigninConfig
	// PreAuth explicitly enables original flow initiation. Nil preserves the
	// existing externally initiated Send profile without exposing an issuer.
	PreAuth *OTPPreAuthConfiguration
}

// DeliveryConfiguration owns delivery custody, retained policies and templates
// once for OTP and its real delivery workers. StateTracking is mandatory.
// Native receipt/cancellation/reconciliation selections retain their adapter
// semantics; this slice exposes processing, not their complete operator APIs.
// Authorization is the exact existing service in OTP.RequestKeys.Policy.
// Workers share the strictest retained SenderConcurrency ceiling, acquired
// before claiming. Supply a dedicated sender instance for this graph; sharing
// it with unrelated graphs or direct callers requires external capacity control.
type DeliveryConfiguration struct {
	Enqueue   deliverypg.EnqueueConfig
	Templates []delivery.Template
}

// featureState is immutable after construction except the fields explicitly
// protected by storeState.mu. Startup and all requests share StoreSet's lifetime.
type featureState struct {
	migrations                   featureMigrationConfig
	otp                          *otppg.SendService
	signin                       *otppg.SigninService
	reset                        *passwordpg.ResetService
	magicRequest                 *magicpg.RequestService
	magicConsume                 *magicpg.ConsumeService
	magicTOTP                    *magicLinkTOTPService
	passwordTOTP                 *magicLinkTOTPService
	passwordRecovery             *magicLinkTOTPService
	passwordOTP                  *PasswordOTPLoginCompletionService
	magicPreauth                 *session.PreAuthIssuer
	httpMagicLink                *magicLinkHTTPState
	httpMFA                      *mfaHTTPState
	httpMFAEnrollment            *mfaEnrollmentHTTPState
	httpMFAActiveStepUp          *mfaActiveStepUpHTTPState
	httpMFARecoveryRegeneration  *mfaRecoveryRegenerationHTTPState
	httpMFAFactorUpdate          *mfaFactorUpdateHTTPState
	httpMFADisable               *mfaDisableHTTPState
	httpMFAList                  *mfaListHTTPState
	httpEmailAddresses           *emailAddressesHTTPState
	httpEmailRequests            *emailRequestsHTTPState
	passwordSignin               *passwordpg.SigninService
	passwordSignup               *passwordpg.SignupService
	session                      *sessionState
	passwordVerification         *passwordVerificationState
	email                        *emailState
	mfaEnrollment                *mfaEnrollmentState
	passwordChange               *passwordChangeState
	httpPasswordVerification     *passwordVerificationHTTPState
	httpPasswordChange           *passwordChangeHTTPState
	httpSession                  *sessionHTTPState
	signupPreauth                *session.PreAuthIssuer
	passwordPreauth              *session.PreAuthIssuer
	preauth                      *session.PreAuthIssuer
	delivery                     *deliverypg.EnqueueService
	sender                       delivery.Sender
	timeout                      time.Duration
	provider                     uint64
	deliveryWorkers              []*deliverypg.Worker
	deliverySlots                chan struct{}
	authorize                    authorization.Service
	httpPreAuth                  *preAuthHTTPState
	httpEmailSignin              *emailSigninHTTPState
	httpPasswordReset            *passwordResetHTTPState
	httpPasswordSignin           *passwordSigninHTTPState
	httpPasswordSignup           *passwordSignupHTTPState
	httpRegistrationVerification *registrationVerificationHTTPState
	// mu-protected graph progression and startup state.
	providers, workers, composed, initializing, ready bool
}

func (s *storeState) composeFeatureStores(c StoreConfiguration, d ReferenceDependencies) error {
	if c.HTTPEmailRequests != nil && (c.Email == nil || c.Session == nil || c.OTP == nil || c.HTTPRate == nil) {
		return identity.InvalidInputError{Field: "reference_http_email_requests"}
	}
	if c.HTTPEmailAddresses != nil && (c.Email == nil || c.Email.Addresses == nil || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_email_addresses"}
	}
	if err := validateEmailSelection(c); err != nil {
		return err
	}
	if c.HTTPMFADisable != nil && (c.MFAEnrollment == nil || c.MFAEnrollment.Disable == nil || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_mfa_disable"}
	}
	if c.HTTPMFAFactorUpdate != nil && (c.MFAEnrollment == nil || c.MFAEnrollment.FactorManagement == nil || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_mfa_factor_update"}
	}
	if c.HTTPMFAList != nil && (c.MFAEnrollment == nil || !c.MFAEnrollment.Listing || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_mfa_list"}
	}
	if c.HTTPMFARecoveryRegeneration != nil && (c.MFAEnrollment == nil || c.MFAEnrollment.Regeneration == nil || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_mfa_regeneration"}
	}
	if c.HTTPMFAActiveStepUp != nil && (c.MFAEnrollment == nil || c.MFAEnrollment.ActiveStepUp == nil || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_mfa_step_up"}
	}
	if c.HTTPMFAEnrollment != nil && (c.MFAEnrollment == nil || c.PasswordVerification == nil || c.Session == nil) {
		return identity.InvalidInputError{Field: "reference_http_mfa_enrollment"}
	}
	if c.MFAEnrollment != nil && c.PasswordVerification == nil {
		return identity.InvalidInputError{Field: "reference_mfa_enrollment"}
	}
	if c.HTTPMFA != nil && ((c.HTTPMFA.TOTPVerify && (c.MagicLink == nil || c.MagicLink.TOTP == nil)) || (c.HTTPMFA.PasswordTOTPVerify && (c.PasswordSignin == nil || c.PasswordSignin.TOTP == nil)) || (c.HTTPMFA.PasswordRecoveryUse && (c.PasswordSignin == nil || c.PasswordSignin.Recovery == nil)) || ((c.HTTPMFA.PasswordOTPVerify || c.HTTPMFA.PasswordOTPSend) && (c.PasswordSignin == nil || c.PasswordSignin.OTP == nil))) {
		return identity.InvalidInputError{Field: "reference_http_mfa"}
	}
	if c.HTTPMagicLink != nil && c.MagicLink == nil {
		return identity.InvalidInputError{Field: "reference_http_magic_link"}
	}
	if c.HTTPPasswordVerification != nil && c.PasswordVerification == nil || c.HTTPPasswordChange != nil && c.PasswordChange == nil {
		return identity.InvalidInputError{Field: "reference_http_password_protection"}
	}
	if c.PasswordChange != nil && c.PasswordVerification == nil {
		return identity.InvalidInputError{Field: "reference_password_change"}
	}
	if c.PasswordVerification != nil && (c.Session == nil || c.PasswordSignin == nil || c.OTP == nil || c.OTP.Signin == nil) {
		return identity.InvalidInputError{Field: "reference_password_verification"}
	}
	if c.HTTPSession != nil && c.Session == nil {
		return identity.InvalidInputError{Field: "reference_http_session"}
	}
	if c.Session != nil && (c.OTP == nil || c.OTP.Signin == nil) {
		return identity.InvalidInputError{Field: "reference_session"}
	}
	if c.PasswordSignup != nil && (c.OTP == nil || c.Delivery == nil) {
		return identity.InvalidInputError{Field: "reference_password_signup"}
	}
	if c.PasswordSignin != nil && (c.OTP == nil || c.OTP.Signin == nil) {
		return identity.InvalidInputError{Field: "reference_password_signin"}
	}
	if c.PasswordReset != nil && (c.OTP == nil || c.Delivery == nil) {
		return identity.InvalidInputError{Field: "reference_password_reset"}
	}
	if c.MagicLink != nil && (c.OTP == nil || c.Delivery == nil) {
		return identity.InvalidInputError{Field: "reference_magic_link"}
	}
	httpPreAuth, err := composePreAuthHTTP(c)
	if err != nil {
		return err
	}
	httpEmailSignin, err := composeEmailSigninHTTP(c, httpPreAuth)
	if err != nil {
		return err
	}
	httpPasswordReset, err := composePasswordResetHTTP(c, httpPreAuth, s.httpRate)
	if err != nil {
		return err
	}
	// A failed later graph construction must not retain a private rate owner.
	retainedResetHTTP := false
	defer func() {
		if httpPasswordReset != nil && !retainedResetHTTP {
			httpPasswordReset.close()
		}
	}()
	httpPasswordSignin, err := composePasswordSigninHTTP(c, httpPreAuth)
	if err != nil {
		return err
	}
	httpPasswordSignup, err := composePasswordSignupHTTP(c, httpPreAuth)
	if err != nil {
		return err
	}
	httpRegistrationVerification, err := composeRegistrationVerificationHTTP(c, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpRegistrationVerification != nil && !retainedResetHTTP {
			httpRegistrationVerification.rate.Close()
		}
	}()
	if c.OTP == nil && c.Delivery == nil {
		return nil
	}
	if c.OTP == nil || c.Delivery == nil || d.EnvelopeKeys == nil || d.DeliverySender == nil || !c.Delivery.Enqueue.StateTracking {
		return identity.InvalidInputError{Field: "reference_features"}
	}
	for _, policy := range c.Delivery.Enqueue.Policies {
		if !policy.Production {
			return identity.InvalidInputError{Field: "reference_delivery"}
		}
	}
	o := *c.OTP
	if len(o.BootstrapTenantIDs) > 256 {
		return identity.InvalidInputError{Field: "reference_bootstrap_tenants"}
	}
	migrationConfig := featureMigrationConfig{otpSchema: o.Store.Schema, sessionSchema: o.Store.PreAuth.Schema, global: o.Store.GlobalAuthorityID, tenants: slices.Clone(o.BootstrapTenantIDs)}
	migrationConfig.cancellation = c.Delivery.Enqueue.Cancellation
	migrationConfig.receiptTracking = c.Delivery.Enqueue.ReceiptTracking
	migrationConfig.receipts = c.Delivery.Enqueue.Receipts != nil
	migrationConfig.reconciliation = c.Delivery.Enqueue.Reconciliation != nil
	if o.Session != nil {
		migrationConfig.authenticatedSchema = o.Session.Store.Schema
	}
	if o.Signin != nil {
		profile, _, err := o.Policy.Bindings()
		if err != nil || profile.Purpose != otp.PurposeSignin || migrationConfig.sessionSchema == "" || o.Signin.Profile.GlobalAuthorityID != o.Store.GlobalAuthorityID || o.Signin.Profile.PolicyNamespace != o.Store.UserPolicyNamespace {
			return identity.InvalidInputError{Field: "reference_otp_signin"}
		}
		migrationConfig.signinSchema = o.Signin.Session.Schema
	}
	preauthOwner, err := composeOTPPreAuth(d.PostgreSQL, o)
	if err != nil {
		return err
	}
	migrationConfig.preauthIssue = preauthOwner != nil
	if err := migrationConfig.validateNamespaces(c.Velocity.Schema); err != nil {
		return err
	}
	// Validate explicit bootstrap inputs without IO before retaining the graph.
	if _, err := (kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 1016, GlobalAuthorityID: migrationConfig.global, TenantIDs: migrationConfig.tenants}).Load(context.Background()); err != nil {
		return err
	}
	if o.RiskTimeout < time.Millisecond || o.RiskTimeout > 5*time.Second || o.RiskTimeout > o.Timeout || o.AuditTimeout < time.Millisecond || o.AuditTimeout > o.RiskTimeout {
		return identity.InvalidInputError{Field: "reference_risk"}
	}
	crypto, err := envelope.NewService(d.EnvelopeKeys)
	if err != nil {
		return err
	}
	sink, err := auditpg.New(d.PostgreSQL.Raw(), auditpg.Config{})
	if err != nil {
		return err
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: s.policy, Keys: s.keys, Store: velocityCounterRouter{state: s}, Clock: time.Now, Timeout: o.RiskTimeout})
	if err != nil {
		return err
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: s.policy, Counters: &counters, Clock: time.Now, Timeout: o.RiskTimeout, DecisionAudit: &risk.DecisionAuditConfig{
		PolicyID: o.RiskPolicyID, Timeout: o.AuditTimeout, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed},
		// Retry only the immutable original event through its idempotent owner.
		// Failure still denies; this is not a durable outage backlog or a claim
		// that complete operational audit recovery has been implemented.
		OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
			_, err := sink.Append(ctx, lost.Record())
			return err
		},
	}})
	if err != nil {
		return err
	}
	deliveryOwner, err := deliverypg.NewUninitializedEnqueueService(d.PostgreSQL, c.Delivery.Enqueue, crypto, o.RequestKeys.Policy.Authorization, c.Delivery.Templates)
	if err != nil {
		return err
	}
	otpOwner, err := otppg.NewSendService(d.PostgreSQL, otppg.SendConfig{
		Store: o.Store, Codec: o.Codec, Session: o.Session, Delivery: c.Delivery.Enqueue.Custody,
		Coordinator: o.Coordinator, RequestKeys: o.RequestKeys, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: o.ConfigurationID, Keys: o.RiskKeys},
		Policy: o.Policy, TemplateID: o.TemplateID, TemplateVersion: o.TemplateVersion, LocaleChain: o.LocaleChain, Templates: c.Delivery.Templates,
		ProviderVersion: o.ProviderVersion, PolicyID: o.PolicyID, PolicyVersion: o.PolicyVersion, PreAuthAction: o.PreAuthAction,
		IntentKey: o.IntentKey, IdentifierKey: o.IdentifierKey, Timeout: o.Timeout,
	}, crypto)
	if err != nil {
		return err
	}
	var signinOwner *otppg.SigninService
	if o.Signin != nil {
		signinOwner, err = otppg.NewSigninService(otpOwner, *o.Signin)
		if err != nil {
			return err
		}
	}
	resetOwner, err := composePasswordReset(c, d, evaluator)
	if err != nil {
		return err
	}
	magicRequest, magicConsume, err := composeMagicLink(c, d, evaluator)
	if err != nil {
		return err
	}
	magicPreauth, err := composeMagicLinkPreAuth(d.PostgreSQL, c.MagicLink)
	if err != nil {
		return err
	}
	magicTOTP, err := composeMagicLinkTOTP(c, d, magicRequest, evaluator)
	if err != nil {
		return err
	}
	migrationConfig.magicTOTP = magicTOTP != nil
	migrationConfig.magicSignup = c.MagicLink != nil && c.MagicLink.Request.Signup != nil
	if magicPreauth != nil {
		migrationConfig.preauthIssue = true
	}
	if magicConsume != nil {
		migrationConfig.magicSessionSchema = c.MagicLink.Request.Session.Schema
		migrationConfig.magicMFAChallenge = c.MagicLink.Consume.MFA != nil
	}
	httpMagicLink, err := composeMagicLinkHTTP(c, httpPreAuth, s.httpRate)
	if err != nil {
		return err
	}
	httpMFA, err := composeMFAHTTP(c, httpPreAuth, s.httpRate)
	if err != nil {
		if httpMagicLink != nil && httpMagicLink.rate != nil {
			httpMagicLink.rate.Close()
		}
		return err
	}
	defer func() {
		if httpMagicLink != nil && httpMagicLink.rate != nil && !retainedResetHTTP {
			httpMagicLink.rate.Close()
		}
		if httpMFA != nil && !retainedResetHTTP {
			httpMFA.rate.Close()
		}
	}()
	if resetOwner != nil {
		migrationConfig.resetSchema = c.PasswordReset.Native.Session.Schema
	}
	passwordSigninOwner, err := composePasswordSignin(c, d, evaluator)
	if err != nil {
		return err
	}
	passwordTOTP, err := composePasswordTOTP(c, d, passwordSigninOwner, evaluator)
	if err != nil {
		return err
	}
	passwordRecovery, err := composePasswordRecovery(c, d, passwordSigninOwner, evaluator)
	if err != nil {
		return err
	}
	passwordOTP, err := composePasswordOTP(c, d, passwordSigninOwner, evaluator)
	if err != nil {
		return err
	}
	migrationConfig.passwordMFA = c.PasswordSignin != nil && c.PasswordSignin.MFA != nil
	migrationConfig.passwordTOTP = passwordTOTP != nil
	migrationConfig.passwordRecovery = passwordRecovery != nil
	migrationConfig.passwordOTP = passwordOTP != nil
	passwordSignupOwner, err := composePasswordSignup(c, d, evaluator)
	if err != nil {
		return err
	}
	sessionOwner, err := composeSession(c, d)
	if err != nil {
		return err
	}
	migrationConfig.singleSessionRevocation = sessionOwner != nil
	passwordVerificationOwner, err := composePasswordVerification(c, d, evaluator)
	if err != nil {
		return err
	}
	emailOwner, err := composeEmail(c, d, evaluator, passwordVerificationOwner, passwordSigninOwner, resetOwner)
	if err != nil {
		return err
	}
	if c.HTTPRegistrationVerification != nil && c.HTTPRegistrationVerification.ManagedAddresses {
		emailOwner.confirmation, err = passwordpg.NewEmailVerificationRouter(passwordSignupOwner, emailOwner.verification)
		if err != nil {
			return err
		}
	}
	passwordChangeOwner, err := composePasswordChange(c, d, passwordVerificationOwner)
	if err != nil {
		return err
	}
	mfaEnrollmentOwner, err := composeMFAEnrollment(c, d, passwordVerificationOwner, evaluator, resetOwner)
	if err != nil {
		return err
	}
	if err := composeMFAListing(c, mfaEnrollmentOwner, sessionOwner); err != nil {
		return err
	}
	migrationConfig.mfaEnrollment = mfaEnrollmentOwner != nil
	httpMFADisable, err := composeMFADisableHTTP(c, d, mfaEnrollmentOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpMFADisable != nil && !retainedResetHTTP {
			httpMFADisable.rate.Close()
		}
	}()
	httpMFAFactorUpdate, err := composeMFAFactorUpdateHTTP(c, d, mfaEnrollmentOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpMFAFactorUpdate != nil && !retainedResetHTTP {
			httpMFAFactorUpdate.rate.Close()
		}
	}()
	httpMFARecoveryRegeneration, err := composeMFARecoveryRegenerationHTTP(c, d, mfaEnrollmentOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpMFARecoveryRegeneration != nil && !retainedResetHTTP {
			httpMFARecoveryRegeneration.rate.Close()
		}
	}()
	httpMFAActiveStepUp, err := composeMFAActiveStepUpHTTP(c, mfaEnrollmentOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpMFAActiveStepUp != nil && !retainedResetHTTP {
			httpMFAActiveStepUp.rate.Close()
		}
	}()
	httpMFAEnrollment, err := composeMFAEnrollmentHTTP(c, mfaEnrollmentOwner, passwordVerificationOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpMFAEnrollment != nil && !retainedResetHTTP {
			httpMFAEnrollment.rate.Close()
			if httpMFAEnrollment.verifyRate != nil {
				httpMFAEnrollment.verifyRate.Close()
			}
		}
	}()
	httpPasswordVerification, err := composePasswordVerificationHTTP(c, passwordVerificationOwner, httpPreAuth, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpPasswordVerification != nil && !retainedResetHTTP {
			httpPasswordVerification.rate.Close()
		}
	}()
	httpPasswordChange, err := composePasswordChangeHTTP(c, passwordChangeOwner, passwordVerificationOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpPasswordChange != nil && !retainedResetHTTP {
			httpPasswordChange.rate.Close()
		}
	}()
	httpSession, err := composeSessionHTTP(c, sessionOwner, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpSession != nil && !retainedResetHTTP {
			httpSession.rate.Close()
		}
	}()
	httpMFAList, err := composeMFAListHTTP(c, mfaEnrollmentOwner, sessionOwner, httpSession, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpMFAList != nil && httpMFAList.owned && !retainedResetHTTP {
			httpMFAList.rate.Close()
		}
	}()
	httpEmailAddresses, err := composeEmailAddressesHTTP(c, emailOwner, sessionOwner, httpSession, httpMFAList, s.httpRate)
	if err != nil {
		return err
	}
	defer func() {
		if httpEmailAddresses != nil && httpEmailAddresses.owned && !retainedResetHTTP {
			httpEmailAddresses.rate.Close()
		}
	}()
	httpEmailRequests, err := composeEmailRequestsHTTP(c, emailOwner, passwordVerificationOwner, s.httpRate, httpPasswordChange, httpRegistrationVerification)
	if err != nil {
		return err
	}
	defer func() {
		if httpEmailRequests != nil && !retainedResetHTTP {
			httpEmailRequests.close()
		}
	}()
	signupPreauthOwner, err := composeSignupPreAuth(d.PostgreSQL, c.PasswordSignup)
	if err != nil {
		return err
	}
	if signupPreauthOwner != nil {
		migrationConfig.preauthIssue = true
	}
	passwordPreauthOwner, err := composePasswordPreAuth(d.PostgreSQL, c.PasswordSignin)
	if err != nil {
		return err
	}
	if passwordPreauthOwner != nil {
		if c.PasswordSignin.Native.Session.Schema != migrationConfig.sessionSchema {
			return identity.InvalidInputError{Field: "reference_password_preauth"}
		}
		migrationConfig.preauthIssue = true
	}
	if passwordSigninOwner != nil {
		migrationConfig.passwordSigninSchema = c.PasswordSignin.Native.Session.Schema
	}
	// All workers borrow one sender instance. The strictest retained policy
	// ceiling bounds the whole graph, not each independently constructed worker.
	capacity := uint8(64)
	for _, policy := range c.Delivery.Enqueue.Policies {
		if policy.SenderConcurrency < capacity {
			capacity = policy.SenderConcurrency
		}
	}
	s.features = &featureState{migrations: migrationConfig, otp: otpOwner, signin: signinOwner, reset: resetOwner, passwordSignin: passwordSigninOwner, passwordPreauth: passwordPreauthOwner, preauth: preauthOwner, delivery: deliveryOwner, sender: d.DeliverySender, timeout: o.Timeout, provider: o.ProviderVersion, deliverySlots: make(chan struct{}, int(capacity)), authorize: o.RequestKeys.Policy.Authorization, httpPreAuth: httpPreAuth, httpEmailSignin: httpEmailSignin, httpPasswordReset: httpPasswordReset, httpPasswordSignin: httpPasswordSignin}
	s.features.passwordSignup = passwordSignupOwner
	s.features.session = sessionOwner
	s.features.passwordVerification = passwordVerificationOwner
	s.features.email = emailOwner
	s.features.passwordChange = passwordChangeOwner
	s.features.mfaEnrollment = mfaEnrollmentOwner
	s.features.httpPasswordVerification = httpPasswordVerification
	s.features.httpPasswordChange = httpPasswordChange
	s.features.httpSession = httpSession
	s.features.signupPreauth = signupPreauthOwner
	s.features.httpPasswordSignup = httpPasswordSignup
	s.features.httpRegistrationVerification = httpRegistrationVerification
	s.features.magicRequest, s.features.magicConsume, s.features.magicPreauth, s.features.httpMagicLink = magicRequest, magicConsume, magicPreauth, httpMagicLink
	s.features.magicTOTP = magicTOTP
	s.features.passwordTOTP = passwordTOTP
	s.features.passwordRecovery = passwordRecovery
	s.features.passwordOTP = passwordOTP
	s.features.httpMFA = httpMFA
	s.features.httpMFAEnrollment = httpMFAEnrollment
	s.features.httpMFAActiveStepUp = httpMFAActiveStepUp
	s.features.httpMFARecoveryRegeneration = httpMFARecoveryRegeneration
	s.features.httpMFAFactorUpdate = httpMFAFactorUpdate
	s.features.httpMFADisable = httpMFADisable
	s.features.httpMFAList = httpMFAList
	s.features.httpEmailAddresses = httpEmailAddresses
	s.features.httpEmailRequests = httpEmailRequests
	retainedResetHTTP = true
	return nil
}

// ProviderSet is the sealed selected deployment-provider owner. Copies share
// one graph; no sender, key service or native feature owner is exported.
type ProviderSet struct{ state *storeState }

// ComposeProviders consumes this graph's selected providers once, without IO,
// callbacks, migrations or goroutines. Zero/recovery-only/closed graphs deny.
func ComposeProviders(stores StoreSet) (ProviderSet, error) {
	s := stores.state
	if s == nil {
		return ProviderSet{}, identity.InvalidInputError{Field: "reference_providers"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || s.features.providers {
		return ProviderSet{}, identity.UnavailableError{}
	}
	s.features.providers = true
	return ProviderSet{state: s}, nil
}

// WorkerSet retains actual delivery workers and their concurrency ceilings.
// ProcessDeliveryOne is explicitly scheduled: construction starts no worker.
// Copies share the exact owners; indexes are fixed by ComposeWorkers input.
type WorkerSet struct {
	state    *storeState
	delivery []*deliverypg.Worker
}

// ComposeWorkers composes 1..128 real bounded native delivery workers from the
// selected provider and store graph. Each selected tenant must have a worker
// for the OTP provider. Duplicate tenant/provider pairs deny. Native scope and
// current authorization policy requirements are validated by the owning adapter.
// All construction is pure; unsuccessful validation leaves the stage retryable.
func ComposeWorkers(stores StoreSet, providers ProviderSet, configs ...deliverypg.WorkerConfig) (WorkerSet, error) {
	s := stores.state
	if s == nil || providers.state != s || len(configs) < 1 || len(configs) > 128 {
		return WorkerSet{}, identity.InvalidInputError{Field: "reference_workers"}
	}
	s.mu.Lock()
	if s.closed || s.features == nil || !s.features.providers || s.features.workers {
		s.mu.Unlock()
		return WorkerSet{}, identity.UnavailableError{}
	}
	f := s.features
	s.mu.Unlock()
	workers := make([]*deliverypg.Worker, 0, len(configs))
	seen := make(map[string]map[uint64]bool, len(configs))
	for _, c := range configs {
		tenant := string(c.Scope.Request.Tenant)
		if s.tenants[tenant] == nil || seen[tenant][c.ProviderConfigVersion] {
			return WorkerSet{}, identity.InvalidInputError{Field: "reference_workers"}
		}
		if seen[tenant] == nil {
			seen[tenant] = make(map[uint64]bool)
		}
		seen[tenant][c.ProviderConfigVersion] = true
		worker, err := f.delivery.NewWorker(c, f.sender)
		if err != nil {
			return WorkerSet{}, err
		}
		workers = append(workers, worker)
	}
	if len(seen) != len(s.tenants) {
		return WorkerSet{}, identity.InvalidInputError{Field: "reference_workers"}
	}
	for tenant := range s.tenants {
		if !seen[tenant][f.provider] {
			return WorkerSet{}, identity.InvalidInputError{Field: "reference_workers"}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || f.workers {
		return WorkerSet{}, identity.UnavailableError{}
	}
	f.workers = true
	f.deliveryWorkers = workers
	return WorkerSet{state: s, delivery: workers}, nil
}

// FeatureSet exposes public workflow interfaces, never concrete adapter stores.
// This development profile contains OTP Send, optional original-flow initiation
// and optional single-factor Signin,
// not HTTP or a complete server.
// Initialize and RecoverVelocity remain explicit, separate startup operations.
type FeatureSet struct{ state *storeState }

// ComposeFeatures consumes the same sealed stores/providers/workers exactly
// once. A foreign graph or absent native worker fails before exposing features.
func ComposeFeatures(stores StoreSet, providers ProviderSet, workers WorkerSet) (FeatureSet, error) {
	s := stores.state
	if s == nil || providers.state != s || workers.state != s || len(workers.delivery) == 0 {
		return FeatureSet{}, identity.InvalidInputError{Field: "reference_features"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.workers || s.features.composed {
		return FeatureSet{}, identity.UnavailableError{}
	}
	s.features.composed = true
	return FeatureSet{state: s}, nil
}

// Initialize registers selected native delivery/OTP startup metadata in order,
// never schema, risk coverage or business effects. All operations remain denied
// until both succeed; exact configuration retries are supported. It is bounded
// by the OTP timeout and shutdown; a concurrent startup returns unavailable.
func (f FeatureSet) Initialize(ctx context.Context) error {
	w, done, err := f.state.enterFeature(ctx, false)
	if err != nil {
		return err
	}
	defer done()
	s := f.state
	s.mu.Lock()
	if s.features.ready {
		s.mu.Unlock()
		return nil
	}
	if s.features.initializing {
		s.mu.Unlock()
		return identity.UnavailableError{}
	}
	s.features.initializing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.features.initializing = false; s.mu.Unlock() }()
	if err := s.features.delivery.Initialize(w); err != nil {
		return err
	}
	if err := s.features.otp.Initialize(w); err != nil {
		return err
	}
	if otp := s.features.passwordOTP; otp != nil {
		if otp.state == nil || otp.state() == nil {
			return invalidPasswordOTPCompletion()
		}
		if err := otp.state().sender.config.Issuance.Initialize(w, s.pool); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := w.Err(); err != nil {
		return err
	}
	if s.closed {
		return identity.UnavailableError{}
	}
	s.features.ready = true
	return nil
}

// OTP returns the public Send interface for the selected graph. The handle may
// be retained before startup, but every call checks startup, tenant and lifetime.
// Close permanently denies even terminal replay through this graph.
func (f FeatureSet) OTP() (otp.Service, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_otp"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed {
		return nil, identity.UnavailableError{}
	}
	return composedOTP{state: s}, nil
}

type composedOTP struct{ state *storeState }

func (f composedOTP) Send(ctx context.Context, r otp.SendRequest) (otp.SendResult, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return otp.SendResult{}, err
	}
	defer done()
	if f.state.tenants[string(r.TenantID)] == nil {
		return otp.SendResult{}, identity.UnavailableError{}
	}
	// Never discard the native result on cancellation: committed or unknown
	// outcomes must retain the original correlation and recovery semantics.
	return f.state.features.otp.Send(w, r)
}

// ProcessDeliveryOne performs one selected native worker step. No polling loop
// or automatic retry is created. Startup and shutdown apply to retained handles;
// the original native result preserves unknown sends and committed checkpoints.
func (w WorkerSet) ProcessDeliveryOne(ctx context.Context, index int) (delivery.ProcessResult, error) {
	bounded, done, err := w.state.enterFeature(ctx, true)
	if err != nil {
		return delivery.ProcessResult{}, err
	}
	defer done()
	if index < 0 || index >= len(w.delivery) {
		return delivery.ProcessResult{}, identity.InvalidInputError{Field: "reference_worker"}
	}
	// One shared sender budget dominates all tenant/provider worker entries.
	// Waiting occurs before leasing, so capacity exhaustion cannot strand a
	// durable attempt or manufacture an ambiguous provider outcome.
	select {
	case w.state.features.deliverySlots <- struct{}{}:
		defer func() { <-w.state.features.deliverySlots }()
	case <-bounded.Done():
		return delivery.ProcessResult{}, bounded.Err()
	}
	if err := bounded.Err(); err != nil {
		return delivery.ProcessResult{}, err
	}
	return w.delivery[index].ProcessOne(bounded)
}

func (s *storeState) enterFeature(ctx context.Context, ready bool) (context.Context, func(), error) {
	if ctx == nil || s == nil {
		return nil, nil, identity.InvalidInputError{Field: "reference_feature"}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	if s.closed || s.features == nil || !s.features.composed || ready && !s.features.ready {
		s.mu.Unlock()
		return nil, nil, identity.UnavailableError{}
	}
	if s.active == 0 {
		s.drained = make(chan struct{})
	}
	s.active++
	s.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, s.features.timeout)
	stop := context.AfterFunc(s.lifetime, cancel)
	return bounded, func() {
		stop()
		cancel()
		s.mu.Lock()
		s.active--
		if s.active == 0 {
			close(s.drained)
		}
		s.mu.Unlock()
	}, nil
}

func (OTPSendConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.OTPSendConfiguration(redacted)")
}
func (DeliveryConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.DeliveryConfiguration(redacted)")
}
func (OTPSendConfiguration) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (OTPSendConfiguration) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (DeliveryConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (DeliveryConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

func (ProviderSet) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.ProviderSet(redacted)")
}
func (WorkerSet) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.WorkerSet(redacted)")
}
func (FeatureSet) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.FeatureSet(redacted)")
}
func (ProviderSet) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (ProviderSet) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (WorkerSet) MarshalJSON() ([]byte, error)   { return nil, risk.ErrSensitiveSerialization }
func (WorkerSet) MarshalText() ([]byte, error)   { return nil, risk.ErrSensitiveSerialization }
func (FeatureSet) MarshalJSON() ([]byte, error)  { return nil, risk.ErrSensitiveSerialization }
func (FeatureSet) MarshalText() ([]byte, error)  { return nil, risk.ErrSensitiveSerialization }
