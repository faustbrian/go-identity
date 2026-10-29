//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type referenceRegistrationPolicy struct{}

func (referenceRegistrationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 {
		if c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.passkey.register-options" || c.Request.Action == "identity.passkey.update" || c.Request.Action == "identity.passkey.delete") && c.Request.Resource.Type == "identity.request-admission" && string(c.Request.Resource.ID) == string(c.Request.Action) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
		if c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" && c.Request.Action == "identity.passkey.signin-options" {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
		if c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" && (c.Request.Resource.Type == "identity.anonymous-flow" || c.Request.Resource.Type == "identity.request-admission" || c.Request.Resource.Type == "identity.preauth") {
			switch c.Request.Action {
			case "identity.passkey.register-options", "identity.passkey.register-verify", "identity.passkey.register-options.recover", "identity.passkey.register-verify.recover":
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
		if c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Resource.Type == "identity.user" && string(c.Request.Resource.ID) == string(c.Request.Subject.ID) {
			switch c.Request.Action {
			case "identity.passkey.register-options", "identity.passkey.register-verify", "identity.passkey.register-verify.recover", "identity.passkey.signin-verify", "identity.passkey.list", "identity.passkey.update", "identity.passkey.delete":
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.phone.send-verification" || c.Request.Action == "identity.phone.verify" || c.Request.Action == "identity.phone.verify.recover" || c.Request.Action == "identity.phone.update" || c.Request.Action == "identity.phone.update.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" {
		switch c.Request.Action {
		case "identity.mfa.otp-send", "identity.mfa.otp-verify", "identity.mfa.otp-send.recover", "identity.mfa.otp-verify.recover":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		case "identity.password.signup", "identity.user.create", "identity.email.verification-confirm", "identity.email.verification-signin", "identity.email.change-confirm", "identity.password.signup.recover", "identity.magic-link.request", "identity.magic-link.consume", "identity.magic-link.request.recover", "identity.magic-link.consume.recover", "identity.mfa.totp-verify", "identity.mfa.totp-verify.recover", "identity.mfa.recovery-use", "identity.mfa.recovery-use.recover":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.session.revoke-one" || c.Request.Action == "identity.session.revoke-one.recover" || c.Request.Action == "identity.password.verify" || c.Request.Action == "identity.password.verify.recover" || c.Request.Action == "identity.password.change" || c.Request.Action == "identity.password.change.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Resource.Type == "identity.user" && string(c.Request.Resource.ID) == string(c.Request.Subject.ID) {
		switch c.Request.Action {
		case "identity.mfa.otp-send", "identity.mfa.otp-verify":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		case "identity.mfa.enable", "identity.mfa.totp-uri", "identity.mfa.totp-verify", "identity.mfa.recovery-regenerate", "identity.mfa.list", "identity.mfa.factor-update", "identity.mfa.disable", "identity.email.verification-send", "identity.email.change-request", "identity.email.address-remove", "identity.email.address-remove.recover", "identity.email.address-get", "identity.email.address-list", "identity.otp.send", "identity.otp.email-verify", "identity.otp.email-verify.recover", "identity.otp.email-change-request", "identity.otp.email-change-confirm", "identity.otp.email-change-confirm.recover":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && (c.Request.Action == "identity.mfa.enable" || c.Request.Action == "identity.mfa.factor-update" || c.Request.Action == "identity.mfa.disable" || c.Request.Action == "identity.email.verification-send" || c.Request.Action == "identity.email.change-request" || c.Request.Action == "identity.email.address-remove" || c.Request.Action == "identity.otp.send") && c.Request.Resource.Type == "identity.request-admission" && string(c.Request.Resource.ID) == string(c.Request.Action) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Action == "identity.mfa.otp-send" && c.Request.Resource.Type == "identity.request-admission" && c.Request.Resource.ID == "identity.mfa.otp-send" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceResetPolicy{}).Decide(ctx, c)
}

func registrationRiskPolicy(t *testing.T, version uint64, screening bool, username ...bool) risk.Policy {
	t.Helper()
	p, err := risk.NewPolicy(registrationRiskPolicyConfig(version, screening, username...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func registrationRiskPolicyConfig(version uint64, screening bool, username ...bool) risk.PolicyConfig {
	c := risk.PolicyConfig{Version: version, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	if screening {
		c.HIBP = risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.signup", "identity.password.change"}}
		if len(username) != 0 && username[0] {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.username.signup")
		}
	}
	return c
}

// Only provider IO is synthetic. The owned client derives padded SHA-1-prefix
// requests and binds results to the actual native command before hashing.
func registrationScreening(t *testing.T, policy risk.Policy, selected ...string) (func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error), *atomic.Int32) {
	t.Helper()
	operation := "identity.password.signup"
	if len(selected) != 0 {
		operation = selected[0]
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || r.Header.Get("Add-Padding") != "true" || r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
			t.Error("HIBP transport leaked candidate/custody")
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("0", 35)+":0\r\n")
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	owner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	checker, err := hibp.New(hibp.Config{UserAgent: "golib-reference/synthetic-registration", AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1024, MaxBreachCount: 1000000000, OutboundConcurrency: 1, Timeout: time.Second, PolicyVersion: "reference-signup-v1", MaxWaiters: 8, MaxCandidateBytes: 128, CacheBytes: 1024, DisableCache: true}, owner, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	native := checker.(*hibp.Client)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := native.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	provider, err := hibp.NewSignalProvider(native, policy)
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, b risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		command, err := identity.ParseCommandID(b.Attempt)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: operation, TenantID: identity.TenantID(b.Tenant), Action: b.Operation, Purpose: operation, SubjectScope: "password-screening", PolicyVersion: "reference-signup-v1", ReplayID: command, Candidate: candidate})
		return []risk.Signal{signal}, err
	}, &calls
}

func configureReferenceRegistration(t *testing.T, c *reference.StoreConfiguration, origin string, selected ...authorization.Service) *atomic.Int32 {
	t.Helper()
	query := kernel.CommandQueryPolicy{Authorization: referenceRegistrationPolicy{}, Clock: clock.System{}, PolicyVersion: 9}
	if len(selected) > 1 {
		t.Fatal("ambiguous application authorization policy")
	}
	if len(selected) == 1 {
		query.Authorization = selected[0]
	}
	c.OTP.RequestKeys.Policy = query
	c.OTP.Signin.Coordinator.QueryPolicy = &query
	c.PasswordSignin.Native.Coordinator.QueryPolicy, c.PasswordSignin.Native.Coordinator.AdmissionPolicy = &query, &query
	n := c.PasswordReset.Native
	coordinator := n.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	schema := identity.AttributeSchema{ID: "reference-signup-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "registered"}}}}}
	fields, err := identity.NewAttributeProcessor(schema, query.Authorization, func(ctx context.Context, _ identity.NormalizationPolicy, value identity.AttributeScalar) (identity.AttributeScalar, error) {
		return value, ctx.Err()
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 9, ValidateCanonicalUserID: func(ctx context.Context, user identity.UserID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := identity.ParseSubjectID(string(user)); err != nil {
			return err
		}
		return nil
	}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error { return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	callback := origin + "/confirm"
	verification, err := email.NewRegistrationVerificationPolicy(email.RegistrationVerificationConfig{Address: c.PasswordSignin.Native.Address, Issuer: origin, Audience: "email", MaximumLifetime: 5 * time.Minute, Redirects: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {118}}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("reference-signup", bytes.Repeat([]byte{119}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{119}, 32))
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "reference-signup", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-signup", [32]byte{120}, query)
	if err != nil {
		t.Fatal(err)
	}
	screening := n.Screening
	screening.Policy = registrationRiskPolicy(t, 3, true)
	var calls *atomic.Int32
	screening.Collect, calls = registrationScreening(t, screening.Policy)
	digest, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{121}, 32))
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "registration", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096})
	c.PasswordSignup = &reference.PasswordSignupConfiguration{
		Native: passwordpg.SignupConfig{Repository: n.Repository, Registration: password.RegistrationPolicy{Enabled: true, RequireVerifiedEmail: true, MinimumBytes: 8, MaximumBytes: 128}, ConfigurationID: "reference-signup-v1", PolicyID: "password-signup", Fields: fields, FieldSchema: schema, Address: n.Request.Address, SelectUser: func(ctx context.Context) (identity.UserID, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			id, err := identity.NewSubjectID()
			return identity.UserID(id), err
		}, Session: c.OTP.Signin.Session, FlowKeys: c.PasswordSignin.Native.FlowKeys, Origins: []string{origin}, CallbackURLs: []string{callback}, RegistrationDomain: kernel.PasswordRegistrationDomainConfig{ComparisonProfile: "reference-email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {122}}}, RequestKeys: requestKeys, IntentKey: [32]byte{123}, ActiveEnvelopeKeyID: "issue-envelope", Screening: screening, Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-signup-v1", Keys: c.OTP.RiskKeys}, Coordinator: coordinator, Verification: passwordpg.SignupVerificationConfig{Policy: verification, Lifetime: time.Minute}, Delivery: passwordpg.SignupDeliveryConfig{Resolver: resolver, Endpoint: origin + "/email/confirm", TemplateID: "registration", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{124}, Timeout: time.Second}},
		Issuer:      issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "email", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {125}}, PreparationTimeout: time.Second},
		Preparation: issuerpg.IssuancePreparationConfig{Deployment: "deployment", ActiveEnvelopeKey: "signup-issuer", EnvelopeKeys: map[string][]byte{"signup-issuer": bytes.Repeat([]byte{126}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "reference-signup", HMAC: bytes.Repeat([]byte{119}, 32)}}, Clock: time.Now},
		Counters:    riskpg.Config{Schema: c.Velocity.Schema, PolicyVersion: 9, EvidenceKeys: c.OTP.RiskKeys, EnvelopeKeys: map[string][]byte{"counter": bytes.Repeat([]byte{127}, 32)}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: registrationRiskPolicy(t, 9, false), Keys: []risk.CounterDigestKey{digest}}},
		PreAuth:     &reference.PasswordPreAuthConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", Origin: origin, CallbackURL: callback, FlowKeyIndex: 0, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: c.OTP.PreAuth.Cookie},
	}
	c.HTTPPasswordSignup = &reference.HTTPPasswordSignupConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9}
	c.PasswordSignup.Native.AuthorizationNamespace = c.PasswordSignin.Native.Profile.PolicyNamespace
	c.HTTPRegistrationVerification = &reference.HTTPRegistrationVerificationConfiguration{Origin: origin, ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9, VerificationNamespace: "reference-registration", VerificationKey: [32]byte{128}}
	c.PasswordReset, c.HTTPPasswordReset = nil, nil
	return calls
}

// Actual public HTTP orchestration and migrations create the first account;
// no user, password, factor-authority or original-flow fixture supplies it.
func TestReferenceServerNativePasswordSignup(t *testing.T) {
	t.Run("rollback", func(t *testing.T) { proveReferenceSignupGraph(t, false) })
	t.Run("competing", func(t *testing.T) { proveReferenceSignupGraph(t, true) })
}

func proveReferenceSignupGraph(t *testing.T, competing bool, protected ...bool) {
	proveReferenceSignupGraphExtensions(t, competing, signupGraphExtensions{}, protected...)
}

type signupGraphExtensions struct {
	apiKey                   bool
	apiKeyUpgrade            bool
	organization             bool
	organizationUpgrade      bool
	organizationTransfer     bool
	organizationExpiry       bool
	organizationLifecycle    bool
	organizationTeams        bool
	organizationTeamCRUD     bool
	organizationRoles        bool
	organizationBindings     bool
	organizationTeamBindings bool
	passkey                  bool
	passkeyUpgrade           bool
	passkeyDiscovery         bool
	passkeySessionHTTP       bool
	passkeyKeyed             bool
	passkeyHTTP              bool
	passkeyManagement        bool
	passkeyDeletion          bool
	passkeySignup            bool
	passkeySignupHTTP        bool
	passkeyTOTP              bool
	passkeyTOTPManagement    bool
	passkeyTOTPEnrollment    bool
	passkeyTOTPDeletion      bool
	mfaOTPDisable            bool
	mfaOTPDisableAll         bool
	mfaOTPActiveCase         string
	mfaOTPManage             bool
	mfaOTPRemoval            bool
	mfaOTPRemovalRace        bool
	mfaOTPActive             bool
	mfaOTPEnrollment         bool
	mfaOTPEnrollmentOnly     bool
	mfaOTPListing            bool
	mfaOTPListingHTTP        bool
	phoneEnrollment          bool
	phonePassword            bool
	phoneTOTP                bool
	phoneTOTPOnly            bool
	phonePasswordReset       bool
	phoneResetRollback       bool
	phoneTOTPRollback        bool
	phoneOTP                 string
	phoneRemoval             string
	phoneChange              bool

	emailSignin                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            string
	usernameTOTPOnly                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       bool
	usernameTOTPPersistent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 bool
	usernameTOTPWithdrawal                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 string
	usernameTOTP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           bool
	username                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               bool
	confirmationHooks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      string
	verificationHooks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      string
	verificationSignin                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     string
	emailOTPInitialPrimary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 bool
	administrativeEmailRemoval                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             bool
	administrativeEmailQueries                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             bool
	emailRemoval                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           bool
	emailManagementChange                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  bool
	emailChangeCase                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        string
	emailManagementResend                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  bool
	emailAddressQueries                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    bool
	postgresBaseline                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       bool
	disable, disableAll, disablePending, disableHTTP, mfaEnrollment, mfaListing, mfaListHTTP, mfaListStandalone, mfaListDenials, mfaListRecheck, activeStepUp, activeStepUpHTTP, factorManagement, factorReplacement, factorReplacementDelayed, factorReplacementRollback, factorReplacementConfirmationFault, factorReplacementConfirmationRace, factorReplacementPredecessorUse, factorReplacementRecovery, factorManagementHTTP, factorManagementRace, factorManagementDenials, factorManagementClear, factorRemoval, factorRemovalReset, factorRemovalLocks, regeneration, regenerationHTTP, regenerationRace, regenerationDenials, passwordMFA, passwordRecovery, recoveryRace, completionCommitFault bool
	replacementContinuationDenial                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          string
	replacementSourceMethod                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                string
}

func proveReferenceSignupGraphExtensions(t *testing.T, competing bool, extensions signupGraphExtensions, protected ...bool) {
	t.Helper()
	budget := 60 * time.Second
	if extensions.mfaOTPManage {
		// Two genuine OTP logins span two required resend intervals. This is
		// a whole-journey budget, not a changed product or security timeout.
		budget = 120 * time.Second
	}
	if extensions.factorReplacementPredecessorUse || extensions.replacementSourceMethod == "totp" || extensions.phonePasswordReset {
		// The genuine predecessor replay counter needs a later TOTP step. Only
		// the whole test budget changes; native deadlines remain unchanged.
		budget = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, extensions.postgresBaseline)
	f.mfaOTPEnrollment = extensions.mfaOTPEnrollment
	f.mfaOTPActiveCase = extensions.mfaOTPActiveCase
	f.mfaOTPRemoval = extensions.mfaOTPRemoval
	f.mfaOTPRemovalRace = extensions.mfaOTPRemovalRace
	f.mfaOTPDisable, f.mfaOTPDisableAll = extensions.mfaOTPDisable, extensions.mfaOTPDisableAll
	f.mfaOTPEnrollmentOnly = extensions.mfaOTPEnrollmentOnly
	f.usernameTOTP = extensions.usernameTOTP
	f.phoneTOTP = extensions.phoneTOTP
	f.phoneTOTPOnly = extensions.phoneTOTPOnly
	f.phonePasswordReset = extensions.phonePasswordReset
	f.phoneResetRollback = extensions.phoneResetRollback
	if extensions.phonePasswordReset {
		f.phoneResetCompleted = new(bool)
	}
	f.phoneTOTPRollback = extensions.phoneTOTPRollback
	if extensions.phoneTOTP {
		f.phoneTOTPCompleted = new(bool)
	}
	f.usernameTOTPOnly = extensions.usernameTOTPOnly
	f.usernameTOTPWithdrawal = extensions.usernameTOTPWithdrawal
	f.usernameTOTPPersistent = extensions.usernameTOTPPersistent
	f.disable, f.disableAll = extensions.disable, extensions.disableAll
	f.disablePending = extensions.disablePending
	f.disableHTTP = extensions.disableHTTP
	f.recoveryRace = extensions.recoveryRace
	f.regenerationRace = extensions.regenerationRace
	f.factorManagementRace = extensions.factorManagementRace
	f.factorManagementDenials = extensions.factorManagementDenials
	f.factorManagementClear = extensions.factorManagementClear
	f.factorReplacement = extensions.factorReplacement
	f.factorReplacementDelayed = extensions.factorReplacementDelayed
	f.factorReplacementRollback = extensions.factorReplacementRollback
	f.factorReplacementConfirmationFault = extensions.factorReplacementConfirmationFault
	f.factorReplacementConfirmationRace = extensions.factorReplacementConfirmationRace
	f.factorReplacementPredecessorUse = extensions.factorReplacementPredecessorUse
	f.factorReplacementRecovery = extensions.factorReplacementRecovery
	f.replacementContinuationDenial = extensions.replacementContinuationDenial
	f.replacementSourceMethod = extensions.replacementSourceMethod
	f.factorRemoval = extensions.factorRemoval
	f.factorRemovalReset = extensions.factorRemovalReset
	f.factorRemovalResetHTTP = extensions.factorRemovalReset && extensions.factorManagementHTTP
	f.factorRemovalLocks = extensions.factorRemovalLocks
	f.regenerationDenials = extensions.regenerationDenials
	f.mfaListDenials = extensions.mfaListDenials
	f.mfaListRecheck = extensions.mfaListRecheck
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	if strings.HasPrefix(extensions.phoneRemoval, "fence-") {
		deps.PostgreSQL, f.phoneRemovalTrace = newPhoneRemovalFencePool(t, ctx, f.pool)
	}
	if strings.HasPrefix(extensions.verificationSignin, "totp-") {
		var traced *database.Pool
		traced, f.verificationMFAHook = newVerificationMFAEnrollmentTrace(t, ctx, f.pool)
		deps.PostgreSQL = traced
	}
	if extensions.completionCommitFault {
		f.completionFault = &completionCommitFault{factorProof: extensions.activeStepUp, regeneration: extensions.regeneration, factorManagement: extensions.factorManagement || extensions.disable || extensions.mfaOTPManage, replacementConfirmation: extensions.factorReplacementConfirmationFault, emailRemoval: extensions.emailRemoval}
		f.completionFault.phoneRemoval = extensions.phoneRemoval != ""
		f.completionFault.phonePasswordReset = extensions.phonePasswordReset
		f.completionFault.beforeCommit = extensions.phoneRemoval == "before-commit"
		f.completionFault.emailPreparation = extensions.emailChangeCase == "removal-admin-output-unknown" || extensions.mfaOTPActiveCase == "observation-expiry"
		f.completionFault.emailVerification = extensions.emailChangeCase == "otp-verification-unknown" || extensions.emailChangeCase == "otp-change-unknown"
		f.completionFault.registrationVerification = extensions.verificationSignin == "verification-unknown" || extensions.verificationHooks == "unknown"
		f.completionFault.mfaChallenge = extensions.verificationSignin == "totp-child-unknown"
		if strings.HasPrefix(extensions.emailChangeCase, "totp-change") {
			f.completionFault.factorProof = false
			f.completionFault.emailFactorUse = extensions.emailChangeCase == "totp-change-unknown-request"
			f.completionFault.emailVerification = extensions.emailChangeCase == "totp-change-unknown-confirm"
		}
		faultPool, err := database.Connect(ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 4, Configure: func(pc *database.PoolConfig) error {
			pc.ConnConfig.DialFunc = f.completionFault.dial
			if f.verificationMFAHook != nil {
				pc.ConnConfig.Tracer = f.verificationMFAHook
			}
			if f.completionFault.emailPreparation || f.completionFault.emailVerification || f.completionFault.emailFactorUse || f.completionFault.registrationVerification || f.completionFault.phonePasswordReset {
				// Keep parameterized extended queries, but send their SQL rather
				// than a previously cached statement name to the fault boundary.
				pc.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
			}
			return nil
		}})
		if err != nil {
			t.Fatal("completion fault pool unavailable")
		}
		t.Cleanup(func() {
			bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := faultPool.Close(bounded); err != nil {
				t.Error("completion fault pool cleanup failed")
			}
		})
		deps.PostgreSQL = faultPool
	}
	configureReferencePreAuth(t, &c)
	configureReferenceSignin(t, &c)
	network := httptest.NewUnstartedServer(nil)
	t.Cleanup(network.Close)
	origin := "https://" + network.Listener.Addr().String()
	if extensions.passkeyHTTP {
		// The authenticator's RP/origin is a real DNS deployment authority;
		// only the TLS listener is local. Requests below retain this Host.
		origin = "https://identity.example"
	}
	c.OTP.PreAuth.Origin = origin
	c.Velocity.LeaseDuration = 10 * time.Second
	// These account graphs apply many selected histories as one operator run.
	// Keep that run bounded at five seconds rather than the velocity-only
	// fixture's one-second budget. Native authentication/read budgets stay capped.
	c.Velocity.PrimaryTimeout = 5 * time.Second
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-registration", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	key, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{107}, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	c.HTTPPreAuth = &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "reference-registration", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: cookie}}
	resetRiskVersion := uint64(3)
	if extensions.emailRemoval || extensions.phoneRemoval != "" || extensions.phoneChange || extensions.phonePasswordReset {
		resetRiskVersion = 9
	}
	configureReferencePasswordResetPolicy(t, &c, origin, f.pool, resetRiskVersion, !extensions.factorRemoval && !extensions.mfaOTPRemoval && !extensions.emailRemoval && extensions.phoneRemoval == "" && !extensions.phoneChange && !extensions.passkeyDeletion, extensions.factorRemoval || extensions.mfaOTPRemoval || extensions.emailRemoval || extensions.phoneRemoval != "" || extensions.phoneChange || extensions.passkeyDeletion, extensions.factorRemovalReset || extensions.mfaOTPRemoval || extensions.emailRemoval || extensions.phoneRemoval != "")
	selectedReset := c.PasswordReset
	selectedResetHTTP := c.HTTPPasswordReset
	var selectedAuthorization authorization.Service = referenceRegistrationPolicy{}
	if extensions.apiKey {
		selectedAuthorization = referenceAPIKeyPolicy{}
	}
	if extensions.organization {
		selectedAuthorization = referenceOrganizationPolicy{}
	}
	if extensions.organizationTeams {
		selectedAuthorization = referenceOrganizationTeamsPolicy{}
	}
	if extensions.organizationRoles {
		selectedAuthorization = referenceOrganizationRolesPolicy{}
	}
	if extensions.emailSignin == "changed" {
		selectedAuthorization = &otpSigninFactorChangePolicy{pool: f.pool}
	}
	if extensions.username {
		selectedAuthorization = referenceUsernamePolicy{}
	}
	if extensions.phonePassword || extensions.phoneOTP != "" {
		selectedAuthorization = referencePhoneSigninPolicy{}
	}
	if extensions.phonePasswordReset {
		selectedAuthorization = referencePhonePasswordResetPolicy{}
	}
	if extensions.verificationSignin == "totp-original-expiry" {
		f.verificationMFAOriginalExpiry = &verificationMFAOriginalExpiryPolicy{pool: f.pool}
		selectedAuthorization = f.verificationMFAOriginalExpiry
	}
	if strings.HasPrefix(extensions.verificationSignin, "totp-late-") {
		f.verificationMFALateAuthority = &verificationMFALateAuthorityPolicy{pool: f.pool, mode: extensions.verificationSignin}
		selectedAuthorization = f.verificationMFALateAuthority
	}
	if extensions.verificationSignin == "totp-withdrawn-parent" {
		f.verificationMFAWithdrawnParent = &verificationMFAWithdrawnParentPolicy{pool: f.pool}
		selectedAuthorization = f.verificationMFAWithdrawnParent
	}
	var verificationExpiryClock *verificationSigninExpiryClock
	if strings.HasPrefix(extensions.verificationSignin, "policy-denied") {
		selectedAuthorization = verificationSigninDenyPolicy{}
	}
	if extensions.verificationSignin == "late-factor" {
		selectedAuthorization = verificationSigninLateFactorPolicy{pool: f.pool}
	}
	if strings.HasPrefix(extensions.verificationSignin, "late-issuer-expiry") {
		verificationExpiryClock = &verificationSigninExpiryClock{}
		selectedAuthorization = verificationSigninExpiryPolicy{clock: verificationExpiryClock}
	}
	if extensions.administrativeEmailQueries || extensions.administrativeEmailRemoval {
		f.adminEmailGrant = &administrativeEmailGrant{removal: extensions.administrativeEmailRemoval}
		selectedAuthorization = f.adminEmailGrant
	}
	calls := configureReferenceRegistration(t, &c, origin, selectedAuthorization)
	if extensions.apiKey && !extensions.apiKeyUpgrade {
		configureReferenceAPIKey(t, &c, origin)
	}
	if extensions.organization {
		configureReferenceOrganization(t, &c, origin)
	}
	if extensions.organizationTeams {
		c.Organization.Core.Teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 100}
		c.HTTPOrganization.TeamMemberAdd, c.HTTPOrganization.TeamMemberRemove = true, true
		c.HTTPOrganization.TeamListMine, c.HTTPOrganization.TeamMemberList = true, true
	}
	if extensions.organizationTeamCRUD {
		c.Organization.Core.Teams.LifecycleVersion = 1
		c.HTTPOrganization.TeamCreate, c.HTTPOrganization.TeamUpdate = true, true
		c.HTTPOrganization.TeamDelete, c.HTTPOrganization.TeamList = true, true
	}
	if extensions.organizationRoles {
		c.Organization.Core.Teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 100, LifecycleVersion: 1}
		c.Organization.Core.DynamicRoles = organization.DynamicRoleConfig{Version: 1, MaximumRoles: 10, TeamBindingsVersion: 1, Catalog: []organization.Permission{{ID: "document-read", Action: "document.read", ResourceType: "document"}}}
		c.HTTPOrganization.RoleCreate, c.HTTPOrganization.RoleUpdate, c.HTTPOrganization.RoleDelete, c.HTTPOrganization.RoleGet, c.HTTPOrganization.RoleList = true, true, true, true, true
		c.Organization.DirectRoleBindings = extensions.organizationBindings
		c.Organization.TeamRoleBindings = extensions.organizationTeamBindings
		c.HTTPOrganization.PermissionCheck = extensions.organizationBindings || extensions.organizationTeamBindings
	}
	if extensions.organizationExpiry {
		c.Organization.Invitations.Policy.ExpirationReasons = []identity.PolicyReason{"security-withdrawal", "administrative-cleanup"}
		c.HTTPOrganization.InvitationExpire = true
	}
	if extensions.administrativeEmailQueries {
		c.Email = &reference.EmailConfiguration{Addresses: referenceEmailQueryConfiguration()}
		c.Email.Addresses.AdministrativeAudit = &reference.EmailAddressAuditConfiguration{MaximumDuration: time.Second}
		c.HTTPEmailAddresses = &reference.HTTPEmailAddressesConfiguration{Get: true, List: true, AdministrativeTargets: true}
	}
	if extensions.factorRemoval || extensions.mfaOTPRemoval || extensions.emailRemoval || extensions.phoneRemoval != "" || extensions.phoneChange || extensions.passkeyDeletion {
		c.PasswordReset = selectedReset
		c.PasswordReset.Native.Coordinator.QueryPolicy = c.OTP.Signin.Coordinator.QueryPolicy
		c.PasswordReset.Native.Coordinator.AdmissionPolicy = c.OTP.Signin.Coordinator.QueryPolicy
		c.PasswordReset.Native.Request.RequestKeys.Policy = c.OTP.RequestKeys.Policy
		if f.factorRemovalResetHTTP {
			c.HTTPPasswordReset = selectedResetHTTP
		}
	}
	signin := c.PasswordSignin.Native
	if extensions.verificationSignin != "" {
		c.PasswordSignup.VerificationSignin = &passwordpg.VerificationSigninConfig{Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: signin.Profile.GlobalAuthorityID, PolicyNamespace: signin.Profile.PolicyNamespace, Audience: signin.Profile.Audience}, Issuance: signin.Issuance, CSRFKey: signin.CSRFKey}
		if extensions.verificationSignin == "upgrade-mfa-first" {
			c.PasswordSignup.VerificationSessionLineage = reference.MFABeforeVerification
		}
		if strings.HasPrefix(extensions.verificationSignin, "totp-") || extensions.verificationSignin == "empty-totp" {
			c.PasswordSignup.VerificationSessionLineage = reference.VerificationBeforeMFA
			if extensions.verificationSignin == "totp-original-expiry" {
				c.PasswordSignup.Native.Verification.Lifetime = 3 * time.Second
			}
			issuer := c.PasswordSignup.Issuer
			issuer.Audience = signin.Profile.Audience
			c.PasswordSignup.VerificationSignin.TOTP = &passwordpg.MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3, IssuerURL: origin, Issuer: issuer, Custody: c.PasswordSignup.Preparation}
			counters := c.PasswordSignup.Counters
			commands := *counters.CommandCounters
			commands.Policy, commands.Keys = c.Velocity.Native.Policy, c.Velocity.Native.Keys
			counters.CommandCounters = &commands
			admitted, err := commands.Policy.Admit("identity.mfa.totp-verify")
			if err != nil {
				t.Fatal(err)
			}
			counters.PolicyVersion = admitted.PolicyVersion
			c.PasswordSignup.VerificationTOTP = &reference.VerificationTOTPConfiguration{MaximumDuration: c.OTP.Timeout, ConfigurationID: "reference-verification-totp-v1", PolicyID: "verification-totp", Counters: counters, RiskKeys: c.OTP.RiskKeys, ComparisonKey: [32]byte{188}, ComparisonKeyVersion: 1, ActiveEnvelopeKeyID: "issue-envelope"}
			if strings.HasSuffix(extensions.verificationSignin, "-http") {
				c.HTTPMFA = &reference.HTTPMFAConfiguration{VerificationTOTPVerify: true, ActorID: c.HTTPPasswordSignup.ActorID, PolicyRevision: c.HTTPPasswordSignup.PolicyRevision, VerificationNamespace: "reference-verification-totp-http", VerificationKey: [32]byte{189}}
			}
		}
		if verificationExpiryClock != nil {
			c.PasswordSignup.VerificationSignin.Issuance.Clock = verificationExpiryClock
		}
		c.HTTPRegistrationVerification.Signin = strings.HasSuffix(extensions.verificationSignin, "-http")
	}
	f.removalSignin = signin
	c.Session = &reference.SessionConfiguration{Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: signin.Session, Profile: sessionpg.IssueAdmissionConfig(signin.Profile), Coordinator: signin.Coordinator, Authorization: c.OTP.RequestKeys.Policy.Authorization, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: signin.Profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{signin.Issuance.LookupKey}}, Cookie: signin.Issuance.Cookie, MaximumDuration: 3 * time.Second}, CSRFKeys: []session.CSRFKey{signin.CSRFKey}}
	c.HTTPSession = &reference.HTTPSessionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "reference-session", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
		t.Error("unexpected shared rate degradation")
		return nil
	}}
	var changeScreens *atomic.Int32
	if len(protected) != 0 && protected[0] {
		changeScreens = configureReferencePasswordProtection(t, &c, origin)
	}
	if extensions.organizationTransfer {
		configureReferenceOrganizationTransfer(t, &c, origin)
	}
	if extensions.organizationLifecycle {
		configureReferenceOrganizationLifecycle(t, &c, origin)
	}
	if extensions.passkey {
		configureReferencePasskey(t, &c)
		if extensions.passkeyKeyed {
			configureReferencePasskeyKeyed(t, &c)
		}
		if extensions.passkeySignup {
			flow := c.Passkey.Flow
			flow.Action = "identity.passkey.register-verify"
			c.Passkey.Signup = &reference.PasskeySignupConfiguration{Flow: flow, Risk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-passkey-signup", Keys: c.OTP.RiskKeys}}
		}
		if extensions.passkeyManagement {
			c.Passkey.Management = &reference.PasskeyManagementConfiguration{Primary: passwordpg.ActionPrimaryConfig{Action: "identity.passkey.update", Audience: "reference-passkey", MaximumAge: time.Minute, Transport: session.CredentialCookie}}
			c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.passkey.update", Audience: "reference-passkey"})
		}
		if extensions.passkeyDeletion {
			c.Passkey.Deletion = &reference.PasskeyDeletionConfiguration{Primary: passwordpg.ActionPrimaryConfig{Action: "identity.passkey.delete", Audience: "reference-passkey", MaximumAge: time.Minute, Transport: session.CredentialCookie}}
			c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.passkey.delete", Audience: "reference-passkey"})
		}
		if extensions.passkeyHTTP {
			c.Passkey.Flow.FlowTTL = 5 * time.Minute
			c.HTTPPasskey = &reference.HTTPPasskeyConfiguration{Registration: true, Signin: true, Inventory: true, Discoverable: extensions.passkeyDiscovery, Update: extensions.passkeyManagement, Delete: extensions.passkeyDeletion}
			if extensions.passkeySignupHTTP {
				c.HTTPPasskey.Signup = true
				c.Passkey.Signup.Flow.FlowTTL = 5 * time.Minute
			}
		}
		c.Session.Passkey = extensions.passkeySessionHTTP
		if extensions.passkeyDiscovery {
			policy := registrationRiskPolicyConfig(3, false)
			policy.PasskeyDiscovery = true
			discoveryPolicy, err := risk.NewPolicy(policy)
			if err != nil {
				t.Fatal("explicit reference passkey discovery policy", err)
			}
			c.Velocity.Native.Policy = discoveryPolicy
		}
	}
	if extensions.mfaEnrollment || extensions.passkeyTOTP {
		configureReferenceMFAEnrollment(t, &c, origin)
	}
	if extensions.passkeyTOTP {
		configureReferencePasskeyTOTP(t, &c)
		if extensions.passkeyTOTPManagement {
			c.Passkey.SessionManagement = &reference.PasskeySessionManagementConfiguration{Transport: session.CredentialCookie, TOTP: true}
			if c.HTTPPasskey != nil {
				c.HTTPPasskey.SessionUpdate = true
			}
		}
		if extensions.passkeyTOTPEnrollment {
			c.Passkey.SessionEnrollment = &reference.PasskeySessionEnrollmentConfiguration{Transport: session.CredentialCookie, TOTP: true}
			if c.HTTPPasskey != nil {
				c.HTTPPasskey.Registration = false
				c.HTTPPasskey.SessionEnrollment = true
			}
		}
		if extensions.passkeyTOTPDeletion {
			c.Passkey.SessionEnrollment = &reference.PasskeySessionEnrollmentConfiguration{Transport: session.CredentialCookie, TOTP: true}
			c.Passkey.SessionDeletion = &reference.PasskeySessionDeletionConfiguration{Transport: session.CredentialCookie, TOTP: true}
			if c.HTTPPasskey != nil {
				c.HTTPPasskey.Registration = false
				c.HTTPPasskey.SessionEnrollment, c.HTTPPasskey.SessionDeletion = true, true
			}
		}
	}
	if extensions.mfaOTPEnrollment {
		configureReferenceMFAOTPEnrollment(t, &c, origin, extensions.mfaOTPEnrollmentOnly)
		c.MFAOTPEnrollment.Listing = extensions.mfaOTPListing
		if extensions.mfaOTPActive {
			configureReferenceMFAOTPActive(t, &c, origin)
			if extensions.mfaOTPActiveCase == "challenge-expiry" {
				c.MFAOTPEnrollment.ActiveStepUp.Native.TTL = 1500 * time.Millisecond
			}
			if extensions.mfaOTPManage {
				c.MFAOTPEnrollment.Listing = true
				c.MFAOTPEnrollment.ActiveStepUp.FactorManagement = &mfapg.FactorUpdateConfig{MaximumAge: time.Minute, PrimaryMaximumAge: 5 * time.Minute}
				if extensions.mfaOTPRemoval {
					c.MFAOTPEnrollment.ActiveStepUp.FactorManagement.RemovalRecoveryPath = auth.RecoveryPathEmail
				}
			}
			if extensions.mfaOTPDisable {
				c.MFAOTPEnrollment.Listing = true
				c.MFAOTPEnrollment.ActiveStepUp.Native.AllowedPurposes = []auth.Purpose{"identity.mfa.factor-update", "identity.mfa.disable"}
				c.MFAOTPEnrollment.ActiveStepUp.Disable = &mfapg.DisableConfig{MaximumAge: time.Minute, PrimaryMaximumAge: 5 * time.Minute, RecoveryPath: auth.RecoveryPathEmail}
			}
		}
		if extensions.mfaOTPListingHTTP {
			c.HTTPMFAList = &reference.HTTPMFAListConfiguration{}
		}
	}
	if extensions.mfaListing {
		c.MFAEnrollment.Listing = true
		f.mfaListing = true
	}
	if extensions.mfaListHTTP {
		c.HTTPMFAList = &reference.HTTPMFAListConfiguration{}
		f.mfaListHTTP = true
	}
	if extensions.mfaListStandalone {
		c.HTTPSession = nil
		c.HTTPMFAList.StandaloneRate = &reference.MFAListStandaloneRateConfiguration{Namespace: "reference-mfa-list", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
			t.Error("unexpected standalone rate degradation")
			return nil
		}}
		f.mfaListStandalone = true
	}
	if extensions.activeStepUp {
		configureReferenceActiveStepUp(t, &c, origin)
		f.activeStepUp = true
	}
	if extensions.activeStepUpHTTP {
		c.HTTPMFAActiveStepUp = &reference.HTTPMFAActiveStepUpConfiguration{TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, VerificationNamespace: "reference-mfa-step-up-http", VerificationKey: [32]byte{195}}
		f.activeStepUpHTTP = true
	}
	if extensions.regeneration {
		c.MFAEnrollment.Regeneration = &mfapg.RecoveryRegenerationConfig{CodeCount: 10, MaximumAge: time.Minute}
		f.regeneration = true
	}
	if extensions.factorManagement {
		c.MFAEnrollment.FactorManagement = &mfapg.FactorUpdateConfig{MaximumAge: time.Minute, PrimaryMaximumAge: 2 * time.Minute}
		if extensions.factorReplacement {
			c.MFAEnrollment.FactorManagement.Replacement = &mfapg.TOTPReplacementConfig{RecoveryCodes: 10}
			if extensions.replacementContinuationDenial == "uri-expired-proof" {
				c.MFAEnrollment.FactorManagement.MaximumAge = 10 * time.Second
			}
		}
		if extensions.factorRemoval {
			c.MFAEnrollment.FactorManagement.RemovalRecoveryPath = auth.RecoveryPathEmail
		}
		f.factorManagement = true
	}
	if extensions.disable {
		c.MFAEnrollment.Disable = &mfapg.DisableConfig{RecoveryPath: auth.RecoveryPathEmail, MaximumAge: time.Minute, PrimaryMaximumAge: 2 * time.Minute}
	}
	if extensions.disableHTTP {
		c.HTTPMFADisable = &reference.HTTPMFADisableConfiguration{TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: c.HTTPMFAEnrollment.RateNamespace, RateKey: c.HTTPMFAEnrollment.RateKey}
		if extensions.activeStepUpHTTP {
			c.HTTPMFAActiveStepUp.Purposes = []auth.Purpose{"identity.mfa.disable"}
		}
	}
	if extensions.factorManagementHTTP {
		c.HTTPMFAFactorUpdate = &reference.HTTPMFAFactorUpdateConfiguration{TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: c.HTTPMFAEnrollment.RateNamespace, RateKey: c.HTTPMFAEnrollment.RateKey}
		if extensions.factorRemoval {
			c.HTTPMFAFactorUpdate.Actions = []mfa.FactorUpdateAction{mfa.Remove}
		}
		if extensions.factorReplacement {
			c.HTTPMFAFactorUpdate.Actions = []mfa.FactorUpdateAction{mfa.Replace}
		}
		f.factorManagementHTTP = true
		if c.HTTPMFAActiveStepUp != nil {
			c.HTTPMFAActiveStepUp.Purposes = []auth.Purpose{"identity.mfa.factor-update"}
		}
	}
	if extensions.regenerationHTTP {
		c.HTTPMFARecoveryRegeneration = &reference.HTTPMFARecoveryRegenerationConfiguration{TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: c.HTTPMFAEnrollment.RateNamespace, RateKey: c.HTTPMFAEnrollment.RateKey}
		f.regenerationHTTP = true
	}
	if extensions.passwordMFA || extensions.phoneTOTP {
		configureReferencePasswordMFA(t, &c, origin)
	}
	if extensions.passwordRecovery {
		totp := c.PasswordSignin.TOTP
		configureReferencePasswordRecovery(t, &c, origin)
		if extensions.passwordMFA {
			c.PasswordSignin.TOTP = totp
			c.HTTPMFA.PasswordTOTPVerify = true
		}
	}
	magic := len(protected) > 1 && protected[1]
	if magic {
		configureReferenceMagicLink(t, &c, origin)
		if len(protected) > 4 && protected[4] {
			domain := c.PasswordSignup.Native.RegistrationDomain
			c.MagicLink.Request.Signup = &magicpg.SignupConfig{SchemaID: "signup-fields", SchemaVersion: 1, Domain: kernel.MagicLinkRegistrationDomainConfig{ComparisonProfile: domain.ComparisonProfile, EmailPossessionPolicyVersion: 9, CurrentIdentifierKeyVersion: domain.CurrentIdentifierKeyVersion, RetainedIdentifierKeys: domain.RetainedIdentifierKeys}}
			var err error
			c.MagicLink.Request.Possession, err = email.NewMagicLinkPossessionPolicy(email.MagicLinkPossessionConfig{Address: c.PasswordSignin.Native.Address, Issuer: origin, Audience: c.MagicLink.Request.Issuer.Audience, MaximumLifetime: c.MagicLink.Request.Lifetime, Callbacks: c.MagicLink.Request.Callbacks, Version: 9})
			if err != nil {
				t.Fatal(err)
			}
			c.MagicLink.Request.Issuer.Crypto.Limits.MaxCaveats = 18
		}
		if len(protected) > 2 && protected[2] {
			c.MagicLink.Request.MFAContinuation = true
			c.MagicLink.Consume.MFA = &magicpg.MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3}
			counters := c.PasswordSignup.Counters
			counterPolicy := *counters.CommandCounters
			counterPolicy.Policy, counterPolicy.Keys = c.Velocity.Native.Policy, c.Velocity.Native.Keys
			counters.CommandCounters = &counterPolicy
			admitted, err := counterPolicy.Policy.Admit("identity.mfa.totp-verify")
			if err != nil {
				t.Fatal(err)
			}
			counters.PolicyVersion = admitted.PolicyVersion
			c.MagicLink.TOTP = &reference.MagicLinkTOTPConfiguration{MaximumDuration: c.OTP.Timeout, ConfigurationID: "reference-totp-v1", PolicyID: "magic-totp", Counters: counters, RiskKeys: c.OTP.RiskKeys, ComparisonKey: [32]byte{188}, ComparisonKeyVersion: 1, ActiveEnvelopeKeyID: "issue-envelope"}
			if len(protected) > 3 && protected[3] {
				c.HTTPMFA = &reference.HTTPMFAConfiguration{TOTPVerify: true, ActorID: c.HTTPMagicLink.ActorID, PolicyRevision: c.HTTPMagicLink.PolicyRevision, VerificationNamespace: c.HTTPMagicLink.VerificationNamespace, VerificationKey: c.HTTPMagicLink.VerificationKey}
			}
		}
	}
	messages := make(chan string, 4)
	deps.DeliverySender = nativeBrowserCodeSender{codes: messages}
	var noticeRecipients chan string
	var changeDeliveries chan emailChangeDelivery
	if extensions.emailManagementChange {
		noticeRecipients = make(chan string, 4)
		if strings.HasPrefix(extensions.emailChangeCase, "otp-change") || strings.HasPrefix(extensions.emailChangeCase, "totp-change") {
			changeDeliveries = make(chan emailChangeDelivery, 16)
		}
		deps.DeliverySender = emailChangeCaptureSender{messages: messages, recipients: noticeRecipients, deliveries: changeDeliveries}
	}
	if extensions.username {
		configureReferenceUsername(t, &c, origin, extensions.usernameTOTP)
		if extensions.usernameTOTPOnly {
			c.PasswordSignin.MFA, c.PasswordSignin.TOTP, c.PasswordSignin.Recovery, c.PasswordSignin.OTP = nil, nil, nil, nil
			c.HTTPMFA.PasswordTOTPVerify = false
		}
	}
	if extensions.emailSignin != "" {
		c.HTTPEmailSignin = &reference.HTTPEmailSigninConfiguration{ActorID: "AAAAAAAAAAAAAAAAAAAAAw", PolicyRevision: 9, TargetID: "login", Address: c.PasswordSignin.Native.Address}
	}
	if extensions.postgresBaseline {
		selectDurableReferenceAdmission(&c)
	}
	if extensions.phoneEnrollment {
		configureReferencePhone(t, &c, origin)
	}
	if extensions.phonePassword {
		c.PhoneSignin = &reference.PhoneSigninConfiguration{Policy: c.Phone.Policy}
		if extensions.phoneTOTP {
			c.PhoneSignin.TOTP = &reference.PhoneTOTPConfiguration{Challenge: *c.PasswordSignin.MFA, Completion: *c.PasswordSignin.TOTP}
			if extensions.phoneTOTPOnly {
				c.PasswordSignin.MFA, c.PasswordSignin.TOTP, c.HTTPMFA = nil, nil, nil
			}
		}
		c.HTTPPhoneSignin = &reference.HTTPPasswordSigninConfiguration{ActorID: c.HTTPPasswordSignin.ActorID, PolicyRevision: c.HTTPPasswordSignin.PolicyRevision}
	}
	if extensions.phoneOTP != "" {
		configureReferencePhoneOTPSignin(t, &c)
	}
	if extensions.phonePasswordReset {
		calls = configureReferencePhonePasswordReset(t, &c, origin)
	}
	if extensions.phoneRemoval != "" {
		calls = configureReferencePhoneRemoval(t, &c, extensions.phoneRemoval)
	}
	if extensions.phoneChange {
		calls = configureReferencePhoneChange(t, &c)
	}
	var emailUpgrade *reference.StoreConfiguration
	if extensions.emailRemoval || extensions.emailChangeCase == "graph" || extensions.emailChangeCase == "graph-upgrade" || extensions.emailChangeCase == "shared-http" || extensions.emailChangeCase == "keyed-graph" || extensions.emailChangeCase == "request-http" || extensions.emailChangeCase == "change-origin-graph" || strings.HasPrefix(extensions.emailChangeCase, "totp-change") || strings.HasPrefix(extensions.emailChangeCase, "otp-change") || strings.HasPrefix(extensions.emailChangeCase, "otp-verification") {
		var retainedTargets []passwordpg.ReauthenticationTarget
		if strings.HasPrefix(extensions.emailChangeCase, "totp-change") {
			retainedTargets = append(retainedTargets, c.PasswordVerification.Native.Targets...)
		}
		calls = configureReferenceEmailGraph(t, &c, origin, extensions.emailManagementChange)
		if strings.HasPrefix(extensions.emailChangeCase, "totp-change") {
			// Email graph supplies its own proof configuration. Add the genuine
			// enrollment target to that final configuration, not its predecessor.
			c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, retainedTargets...)
			// This selected graph has one durable risk policy. MFA counters must
			// bind that policy too, not the superseded velocity-only fixture.
			counter := *c.PasswordSignup.Counters.CommandCounters
			owners := []struct {
				config *riskpg.Config
				action risk.Action
			}{{&c.MFAEnrollment.Native.Counters, "identity.mfa.enable"}, {&c.PasswordSignin.Recovery.Counters, "identity.mfa.recovery-use"}}
			if c.PasswordSignin.TOTP != nil {
				owners = append(owners, struct {
					config *riskpg.Config
					action risk.Action
				}{&c.PasswordSignin.TOTP.Counters, "identity.mfa.totp-verify"})
			}
			for _, selected := range owners {
				admitted, err := counter.Policy.Admit(selected.action)
				if err != nil {
					t.Fatal("selected email MFA policy", err)
				}
				selected.config.CommandCounters, selected.config.PolicyVersion = &counter, admitted.PolicyVersion
			}
		}
		if strings.HasPrefix(extensions.emailChangeCase, "otp-change") {
			configureReferenceEmailOTPChange(t, &c)
			c.Email.OTPChangeInitialPrimary = extensions.emailOTPInitialPrimary && extensions.emailChangeCase != "otp-change-initial-unselected"
			if extensions.emailChangeCase == "otp-change-generic" {
				verification := *c.Email.Change
				verification.Native.Change = nil
				verification.Native.ChangeNotification = nil
				c.Email.Verification = &verification
				target := c.PasswordVerification.Native.Targets[0]
				target.Action = "identity.email.verification-send"
				c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, target)
			}
			if extensions.emailChangeCase == "otp-change-expiry" || extensions.emailChangeCase == "otp-change-final-expiry" {
				c.Email.Change.Native.Lifetime = 3 * time.Second
			}
			if extensions.emailChangeCase == "otp-change-final-expiry" {
				// Leave the real command/risk/current-session budgets longer than
				// original change validity so only the final original fence denies.
				c.OTP.Timeout = 5 * time.Second
				c.OTP.Coordinator.MaximumDuration = 5 * time.Second
				c.OTP.Coordinator.LeaseDuration = 6 * time.Second
			}
			if extensions.emailChangeCase == "otp-change-reference-https" {
				c.HTTPEmailOTPChange = &reference.HTTPEmailOTPChangeConfiguration{Origin: origin, Device: *c.HTTPPreAuth.Device, PolicyRevision: 9}
			}
		}
		if strings.HasPrefix(extensions.emailChangeCase, "otp-verification") {
			configureReferenceEmailOTP(t, &c)
			if extensions.emailChangeCase == "otp-verification-no-otp-signin" {
				c.OTP.Signin = nil
			}
			if extensions.emailChangeCase == "otp-verification-reference-https" {
				c.HTTPEmailOTPVerification = &reference.HTTPEmailOTPVerificationConfiguration{Origin: origin, Device: *c.HTTPPreAuth.Device, PolicyRevision: 9}
			}
		}
		if extensions.emailRemoval {
			configureReferenceEmailRemoval(t, &c)
			c.Email.Removal.Primary.AdministrativeTargets = extensions.administrativeEmailRemoval
			if extensions.emailChangeCase == "removal-admin-output-unknown" {
				// Exercise real lease expiry after a lost preparation-output
				// acknowledgement, without editing durable clock/provenance rows.
				c.PasswordVerification.Native.Coordinator.LeaseDuration = time.Second
			}
			if emailRemovalCreatesPrimary(extensions.emailChangeCase) {
				configureReferenceEmailRemovalPrimary(&c)
			}
			if extensions.emailChangeCase == "removal-http" || extensions.emailChangeCase == "removal-only-http" || extensions.emailChangeCase == "removal-replace-http" || extensions.emailChangeCase == "removal-admin-http" {
				c.HTTPEmailRequests = &reference.HTTPEmailRequestsConfiguration{AddressRemove: true, AdministrativeRemovalTargets: extensions.administrativeEmailRemoval, Origin: origin, PolicyRevision: 9}
			}
		}
		if extensions.emailChangeCase == "keyed-graph" || extensions.emailChangeCase == "request-http" || extensions.emailChangeCase == "change-origin-graph" || strings.HasPrefix(extensions.emailChangeCase, "otp-change") {
			keys, err := kernel.NewRequestKeyConfig("reference-managed-email", [32]byte{219}, c.OTP.RequestKeys.Policy)
			if err != nil {
				t.Fatal(err)
			}
			keyed, err := passwordpg.NewKeyedEmailManagementConfig(keys, [32]byte{220})
			if err != nil {
				t.Fatal(err)
			}
			if extensions.emailManagementChange {
				c.Email.Change.Keyed = &keyed
			} else {
				c.Email.Verification.Keyed = &keyed
			}
		}
		if extensions.emailChangeCase == "request-http" {
			c.HTTPEmailAddresses = &reference.HTTPEmailAddressesConfiguration{Get: true, List: true}
			c.HTTPEmailRequests = &reference.HTTPEmailRequestsConfiguration{VerificationSend: !extensions.emailManagementChange, ChangeRequest: extensions.emailManagementChange, ChangeConfirm: extensions.emailManagementChange, Origin: origin, ActorID: c.HTTPRegistrationVerification.ActorID, PolicyRevision: c.HTTPRegistrationVerification.PolicyRevision}
			if !extensions.emailManagementChange {
				c.HTTPRegistrationVerification.ManagedAddresses = true
			}
		}
		if extensions.emailChangeCase == "shared-http" {
			c.HTTPRegistrationVerification.ManagedAddresses = true
			c.HTTPEmailAddresses = &reference.HTTPEmailAddressesConfiguration{Get: true, List: true}
		}
		if extensions.emailChangeCase == "graph-upgrade" || extensions.emailChangeCase == "removal-upgrade" {
			selected := c
			emailUpgrade = &selected
			c.Email, c.PasswordVerification = nil, nil
		}
	} else if extensions.emailChangeCase == "queries-graph" || extensions.emailChangeCase == "queries-http" || extensions.emailChangeCase == "queries-standalone-http" || extensions.emailChangeCase == "queries-get-http" {
		c.Email = &reference.EmailConfiguration{Addresses: referenceEmailQueryConfiguration()}
		if extensions.emailChangeCase != "queries-graph" {
			c.HTTPEmailAddresses = &reference.HTTPEmailAddressesConfiguration{Get: true, List: extensions.emailChangeCase != "queries-get-http"}
			if extensions.emailChangeCase == "queries-standalone-http" {
				c.HTTPSession = nil
				c.HTTPEmailAddresses.StandaloneRate = &reference.EmailAddressStandaloneRateConfiguration{Namespace: "reference-email-reads", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
					t.Error("unexpected read-rate degradation")
					return nil
				}}
				f.emailQueriesStandalone = true
			}
		}
	}
	if extensions.administrativeEmailQueries {
		for _, mode := range []string{"missing", "zero", "over-budget"} {
			invalid, selectedEmail, selectedAddresses := c, *c.Email, *c.Email.Addresses
			selectedEmail.Addresses, invalid.Email = &selectedAddresses, &selectedEmail
			switch mode {
			case "missing":
				selectedAddresses.AdministrativeAudit = nil
			case "zero":
				selectedAddresses.AdministrativeAudit = &reference.EmailAddressAuditConfiguration{}
			case "over-budget":
				selectedAddresses.AdministrativeAudit = &reference.EmailAddressAuditConfiguration{MaximumDuration: time.Minute}
			}
			if graph, err := reference.ComposeStores(invalid, deps); err == nil {
				bounded, stop := context.WithTimeout(context.Background(), time.Second)
				_ = graph.Close(bounded)
				stop()
				t.Fatal("administrative HTTP accepted missing or unbounded required audit", mode)
			}
		}
	}
	for _, namespace := range []string{"", "other-users"} {
		invalid, selected := c, *c.PasswordSignup
		selected.Native.AuthorizationNamespace = namespace
		invalid.PasswordSignup = &selected
		if graph, err := reference.ComposeStores(invalid, deps); err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("registration accepted absent or mismatched signin authority namespace")
		}
	}
	if c.HTTPRegistrationVerification != nil && c.HTTPRegistrationVerification.ManagedAddresses {
		invalid, selectedEmail := c, *c.Email
		selectedVerification := *selectedEmail.Verification
		selectedVerification.Native.Issuer.Crypto.Issuer = "https://foreign-issuer.example"
		selectedEmail.Verification = &selectedVerification
		invalid.Email = &selectedEmail
		if graph, err := reference.ComposeStores(invalid, deps); err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("shared confirmation accepted mismatched trusted issuer namespaces")
		}
	}
	var verificationHooks *referenceVerificationHooks
	if extensions.confirmationHooks != "" {
		f.confirmationHooks = configureRemainingConfirmationHooks(t, &c, f, extensions.confirmationHooks)
	}
	if extensions.verificationHooks != "" {
		verificationHooks = configureReferenceVerificationHooks(t, &c, f, extensions.verificationHooks)
	}
	var phoneRemovalUpgrade *reference.StoreConfiguration
	var passkeyUpgrade *reference.StoreConfiguration
	if extensions.passkeyUpgrade {
		selected := c
		passkeyUpgrade, c.Passkey = &selected, nil
		// HTTP transport is enabled with the real successor owner, not on the
		// baseline graph used to create and verify the existing account.
		c.HTTPPasskey = nil
		if extensions.passkeyTOTP && extensions.passkeyHTTP {
			c.HTTPMFA = nil
		}
		baselineSession := *c.Session
		baselineSession.Passkey = false
		c.Session = &baselineSession
	}
	if extensions.phoneRemoval == "upgrade" {
		selected := c
		phoneRemovalUpgrade, c.PhoneRemoval = &selected, nil
	}
	var phoneChangeUpgrade *reference.StoreConfiguration
	if extensions.phoneChange {
		selected := c
		phoneChangeUpgrade, c.PhoneChange = &selected, nil
	}
	if extensions.phonePasswordReset && !extensions.phoneResetRollback && !extensions.completionCommitFault {
		proveReferencePhoneResetMixedSchemaRejected(t, c, deps, selectedReset)
	}
	if extensions.passkeySessionHTTP {
		invalid := c
		if passkeyUpgrade != nil {
			invalid = *passkeyUpgrade
		}
		invalid.Passkey = nil
		// Isolate common-session selection rather than the separately selected
		// HTTP owner's earlier prerequisite validation.
		invalid.HTTPPasskey = nil
		if extensions.passkeyTOTP && extensions.passkeyHTTP {
			invalid.HTTPMFA = nil
		}
		graph, err := reference.ComposeStores(invalid, deps)
		if err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("common passkey selection invented an unconfigured native issuer")
		}
		var input identity.InvalidInputError
		if !errors.As(err, &input) || input.Field != "reference_session" {
			t.Fatal("missing common passkey owner did not reach its selection guard")
		}
	}
	if extensions.passkeyHTTP {
		selected := c
		if passkeyUpgrade != nil {
			selected = *passkeyUpgrade
		}
		proveReferencePasskeyHTTPPrimarySelection(t, selected, deps)
	}
	if extensions.passkeyTOTPManagement || extensions.passkeyTOTPEnrollment || extensions.passkeyTOTPDeletion {
		invalid := c
		if passkeyUpgrade != nil {
			invalid = *passkeyUpgrade
		}
		selected := *invalid.Passkey
		selected.TOTP = nil
		if extensions.passkeyTOTPDeletion {
			// Isolate removal's dependency rather than failing first on the
			// additional-enrollment profile used to create the second key.
			selected.SessionEnrollment = nil
		}
		invalid.Passkey = &selected
		if graph, err := reference.ComposeStores(invalid, deps); err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("completed-MFA credential workflow accepted missing native TOTP owner")
		}
	}
	if extensions.passkeyDeletion {
		selected := c
		if passkeyUpgrade != nil {
			selected = *passkeyUpgrade
		}
		proveReferencePasskeyDeletionSelection(t, selected, deps)
	}
	var organizationUpgrade *reference.StoreConfiguration
	if extensions.organizationTeams {
		proveReferenceOrganizationTeamsSelection(t, c, deps)
	}
	if extensions.organizationTeamCRUD {
		proveReferenceOrganizationTeamCRUDSelection(t, c, deps)
	}
	if extensions.organizationRoles {
		proveReferenceOrganizationRolesSelection(t, c, deps)
	}
	if extensions.organizationTransfer {
		proveReferenceOrganizationTransferSelection(t, c, deps)
	}
	if extensions.organizationLifecycle {
		proveReferenceOrganizationLifecycleSelection(t, c, deps)
	}
	if extensions.organizationUpgrade {
		successor := c
		organizationUpgrade = &successor
		if extensions.organizationRoles {
			org, transport := *c.Organization, *c.HTTPOrganization
			c.Organization, c.HTTPOrganization = &org, &transport
			if !extensions.organizationTeamBindings {
				org.Core.DynamicRoles = organization.DynamicRoleConfig{}
			}
			org.DirectRoleBindings = false
			org.TeamRoleBindings = false
			transport.PermissionCheck = false
			transport.RoleCreate, transport.RoleUpdate, transport.RoleDelete, transport.RoleGet, transport.RoleList = false, false, false, false, false
		} else if extensions.organizationTeamCRUD {
			// Upgrade actual installed team membership, preserving its histories,
			// live binding and original command custody under lifecycle steps3/4.
			org, transport := *c.Organization, *c.HTTPOrganization
			c.Organization, c.HTTPOrganization = &org, &transport
			org.Core.Teams.LifecycleVersion = 0
			transport.TeamCreate, transport.TeamUpdate = false, false
			transport.TeamDelete, transport.TeamList = false, false
		} else {
			c.Organization, c.HTTPOrganization = nil, nil
		}
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatal("registration graph invalid field", invalid.Field)
		}
		t.Fatal("registration graph", err)
	}
	f.stores = stores
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workerConfigs := []deliverypg.WorkerConfig{worker}
	if extensions.organization {
		if c.Organization != nil {
			if _, err := reference.ComposeWorkers(stores, providers, worker); err == nil {
				t.Fatal("organization graph accepted missing selected invitation worker")
			}
		}
		invitationWorker := worker
		selected := c.Organization
		if organizationUpgrade != nil {
			selected = organizationUpgrade.Organization
		}
		invitationWorker.ProviderConfigVersion = selected.Invitations.ProviderVersion
		workerConfigs = append(workerConfigs, invitationWorker)
	}
	if extensions.phoneEnrollment {
		if _, err := reference.ComposeWorkers(stores, providers, worker); err == nil {
			t.Fatal("phone graph accepted no selected SMS worker")
		}
		smsWorker := worker
		smsWorker.ProviderConfigVersion = c.Phone.Issuance.ProviderVersion
		workerConfigs = append(workerConfigs, smsWorker)
	}
	workers, err := reference.ComposeWorkers(stores, providers, workerConfigs...)
	if err != nil {
		t.Fatal(err)
	}
	if extensions.phonePasswordReset {
		f.phoneResetConsumer = &phoneResetConsumer{workers: workers, messages: messages}
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	if c.Organization != nil {
		modules = append(modules, "organization/postgres")
	}
	if c.APIKey != nil {
		modules = append(modules, "identity/apikey/postgres")
	}
	if c.Passkey != nil {
		modules = append(modules, "passkey/postgres", "webauthn/postgres")
	}
	if extensions.apiKey && !extensions.apiKeyUpgrade {
		proveReferenceAPIKeyOnlyRateMigrations(t, ctx, f, c, deps, workerConfigs)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, `DO $$
DECLARE owned_role text;
BEGIN
  FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = owned_role) THEN
      EXECUTE format('DROP OWNED BY %I', owned_role);
      EXECUTE format('DROP ROLE %I', owned_role);
    END IF;
  END LOOP;
END $$`); err != nil {
			t.Error("owned audit cleanup", err)
		}
	})
	if extensions.emailChangeCase == "removal-only-http" {
		proveIndependentRemovalRateMigrations(t, ctx, f, c, deps, workerConfigs, modules)
	}
	if extensions.phoneRemoval == "independent-http" {
		proveIndependentRemovalRateMigrations(t, ctx, f, c, deps, workerConfigs, modules)
	}
	migrationRequest := applyRequest(t, ctx, stores, modules)
	migrationResult, migrationErr := stores.ReferenceMigrationApply(ctx, migrationRequest)
	if (extensions.factorReplacement || extensions.passkeyTOTP) && migrationErr != nil && migrationResult.Result.State() == reference.MigrationApplyUnknown {
		// This larger selected graph can outlive the bounded operator call on a
		// busy local database. Resume its durable exact prefix, never re-plan or
		// widen the native authentication/read budgets to get the fixture ready.
		t.Log("resuming original migration plan after bounded unknown outcome")
		migrationResult, migrationErr = stores.ReferenceMigrationApply(ctx, migrationRequest)
	}
	if out, err := migrationResult, migrationErr; err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("fresh selected registration migration", err, "state", out.Result.State(), "safe-cause", errors.Unwrap(err), "receipts", len(out.Result.Receipts()))
	}
	policies := identity.PolicySet{Authorize: c.OTP.RequestKeys.Policy.Authorization, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) { panic("unused") }, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		panic("unused")
	}, DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		panic("unused")
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		panic("unused")
	}}
	config := reference.ReferenceConfig{Profile: reference.PostgresWithValkey, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}, PublicHosts: []string{"localhost"}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Registration reference", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: &nativeServerTenant{}}}
	if extensions.postgresBaseline {
		config.Profile = reference.PostgresOnly
	}
	if extensions.apiKey {
		config.HTTP.Network.Limits.MaximumBodyBytes = 65536
		config.HTTP.Network.Limits.MaximumFields = 128
	}
	if extensions.passkeyHTTP {
		config.HTTP.Network.TenantHosts = []identityhttp.TenantHost{{Host: "identity.example", TenantID: otpTenant}}
	}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatal("registration HTTP server", invalid.Field)
		}
		t.Fatal("registration HTTP server", err)
	}
	seen := map[string]bool{}
	for _, op := range server.OpenAPI().Operations() {
		seen[op.Record.OperationID] = true
	}
	wantOperations := 8
	if c.HTTPAPIKey != nil {
		wantOperations += 3
	}
	if c.HTTPOrganization != nil {
		for _, selected := range []struct {
			op string
			on bool
		}{
			{"create", c.HTTPOrganization.Create}, {"update", c.HTTPOrganization.Update},
			{"get", c.HTTPOrganization.Get}, {"member.list", c.HTTPOrganization.MemberList},
			{"member.add", c.HTTPOrganization.MemberAdd}, {"member.update", c.HTTPOrganization.MemberUpdate},
			{"member.remove", c.HTTPOrganization.MemberRemove}, {"invitation-send", c.HTTPOrganization.InvitationSend},
			{"invitation.get", c.HTTPOrganization.InvitationGet}, {"invitation.list-mine", c.HTTPOrganization.InvitationListMine},
			{"invitation.list", c.HTTPOrganization.InvitationList},
			{"invitation.accept", c.HTTPOrganization.InvitationAccept},
			{"invitation.resend", c.HTTPOrganization.InvitationResend},
			{"invitation.cancel", c.HTTPOrganization.InvitationCancel},
			{"invitation.expire", c.HTTPOrganization.InvitationExpire},
			{"invitation.reject", c.HTTPOrganization.InvitationReject},
			{"slug-available", c.HTTPOrganization.SlugAvailable},
			{"list", c.HTTPOrganization.List},
			{"member.leave", c.HTTPOrganization.MemberLeave},
			{"owner-transfer", c.HTTPOrganization.OwnerTransfer},
			{"archive", c.HTTPOrganization.Archive}, {"restore", c.HTTPOrganization.Restore},
			{"team.member-add", c.HTTPOrganization.TeamMemberAdd}, {"team.member-remove", c.HTTPOrganization.TeamMemberRemove},
			{"team.list-mine", c.HTTPOrganization.TeamListMine}, {"team.member-list", c.HTTPOrganization.TeamMemberList},
			{"team.create", c.HTTPOrganization.TeamCreate}, {"team.update", c.HTTPOrganization.TeamUpdate},
			{"team.delete", c.HTTPOrganization.TeamDelete}, {"team.list", c.HTTPOrganization.TeamList},
			{"role.create", c.HTTPOrganization.RoleCreate}, {"role.update", c.HTTPOrganization.RoleUpdate}, {"role.delete", c.HTTPOrganization.RoleDelete}, {"role.get", c.HTTPOrganization.RoleGet}, {"role.list", c.HTTPOrganization.RoleList},
			{"permission-check", c.HTTPOrganization.PermissionCheck},
		} {
			if selected.on {
				wantOperations++
			}
			if seen["identity.organization."+selected.op] != selected.on {
				t.Fatal("organization route selection mismatch", selected.op)
			}
		}
	}
	if c.HTTPPasskey != nil {
		wantOperations += 5
		for _, operation := range []string{"register-options", "register-verify", "signin-options", "signin-verify", "list"} {
			if !seen["identity.passkey."+operation] {
				t.Fatal("selected passkey operation missing", operation)
			}
		}
		if c.HTTPPasskey.Update || c.HTTPPasskey.SessionUpdate {
			wantOperations++
		}
		if c.HTTPPasskey.Delete || c.HTTPPasskey.SessionDeletion {
			wantOperations++
		}
		if seen["identity.passkey.update"] != (c.HTTPPasskey.Update || c.HTTPPasskey.SessionUpdate) || seen["identity.passkey.delete"] != (c.HTTPPasskey.Delete || c.HTTPPasskey.SessionDeletion) {
			t.Fatal("unselected passkey management advertised")
		}
	} else {
		for operation := range seen {
			if strings.HasPrefix(operation, "identity.passkey.") {
				t.Fatal("unselected passkey HTTP advertised")
			}
		}
	}
	if c.HTTPPhoneOTPSignin != nil {
		wantOperations += 3
		for _, id := range []string{"identity.phone.send-signin", "identity.phone.signin", "identity.phone.signin.recover"} {
			if !seen[id] {
				t.Fatal("selected phone OTP operation missing", id)
			}
		}
	} else if seen["identity.phone.send-signin"] || seen["identity.phone.signin"] || seen["identity.phone.signin.recover"] {
		t.Fatal("unselected phone OTP operation advertised")
	}
	if c.HTTPPhoneSignin != nil {
		wantOperations++
		if !seen["identity.phone.password-signin"] {
			t.Fatal("selected phone/password operation missing")
		}
	} else if seen["identity.phone.password-signin"] {
		t.Fatal("unselected phone/password operation advertised")
	}
	if c.HTTPPhoneVerification != nil {
		wantOperations += 3
		for _, id := range []string{"identity.phone.send-verification", "identity.phone.verify", "identity.phone.verify.recover"} {
			if !seen[id] {
				t.Fatal("selected phone operation missing", id)
			}
		}
	} else if seen["identity.phone.send-verification"] || seen["identity.phone.verify"] || seen["identity.phone.verify.recover"] {
		t.Fatal("native phone selection implicitly advertised HTTP")
	}
	if c.HTTPEmailSignin != nil {
		wantOperations += 3
		for _, id := range []string{"identity.otp.send", "identity.otp.signin", "identity.otp.signin.recover"} {
			if !seen[id] {
				t.Fatal("selected email OTP signin route missing", id)
			}
		}
	}
	if extensions.username {
		wantOperations += 5
		for _, id := range []string{"identity.username.signup", "identity.username.signin", "identity.username.available", "identity.username.update", "identity.password.verify"} {
			if !seen[id] {
				t.Fatal("selected username route missing", id)
			}
		}
	}
	for action, selected := range map[string]bool{"identity.email.verification-send": c.HTTPEmailRequests != nil && c.HTTPEmailRequests.VerificationSend, "identity.email.change-request": c.HTTPEmailRequests != nil && c.HTTPEmailRequests.ChangeRequest, "identity.email.change-confirm": c.HTTPEmailRequests != nil && c.HTTPEmailRequests.ChangeConfirm, "identity.email.address-remove": c.HTTPEmailRequests != nil && c.HTTPEmailRequests.AddressRemove} {
		if selected {
			wantOperations++
			if !seen[action] {
				t.Fatal("selected email operation absent", action)
			}
		} else if seen[action] {
			t.Fatal("unselected email operation advertised", action)
		}
	}
	if c.HTTPEmailAddresses != nil {
		if c.HTTPEmailAddresses.Get {
			wantOperations++
			if !seen["identity.email.address-get"] {
				t.Fatal("selected address get missing")
			}
		}
		if c.HTTPEmailAddresses.List {
			wantOperations++
			if !seen["identity.email.address-list"] {
				t.Fatal("selected address list missing")
			}
		} else if seen["identity.email.address-list"] {
			t.Fatal("unselected address list advertised")
		}
	} else if seen["identity.email.address-get"] || seen["identity.email.address-list"] {
		t.Fatal("native email queries implicitly exposed HTTP")
	}
	if c.HTTPPasswordReset != nil {
		wantOperations += 2
		if !seen["identity.password.reset-request"] || !seen["identity.password.reset-complete"] {
			t.Fatal("selected recovery routes missing")
		}
	} else if seen["identity.password.reset-request"] || seen["identity.password.reset-complete"] {
		t.Fatal("unselected recovery route advertised")
	}
	if c.HTTPPhonePasswordReset != nil {
		wantOperations += 2
		if !seen["identity.phone.password-reset-request"] || !seen["identity.phone.password-reset-complete"] {
			t.Fatal("selected phone recovery routes missing")
		}
	} else if seen["identity.phone.password-reset-request"] || seen["identity.phone.password-reset-complete"] {
		t.Fatal("unselected phone recovery route advertised")
	}
	if c.HTTPSession == nil {
		wantOperations -= 2
		if seen["identity.session.get"] || seen["identity.session.signout"] {
			t.Fatal("standalone listing selected HTTP session routes")
		}
	}
	if c.HTTPMFAList != nil {
		wantOperations++
		if !seen["identity.mfa.list"] {
			t.Fatal("selected list route missing")
		}
	} else if seen["identity.mfa.list"] {
		t.Fatal("unselected list route advertised")
	}
	if c.HTTPMFAEnrollment != nil {
		wantOperations++
		if !seen["identity.mfa.enable"] {
			t.Fatal("selected enrollment route missing")
		}
		if c.HTTPMFAEnrollment.ProvisioningURI {
			wantOperations++
			if !seen["identity.mfa.totp-uri"] {
				t.Fatal("selected provisioning route missing")
			}
		} else if seen["identity.mfa.totp-uri"] {
			t.Fatal("unselected provisioning route advertised")
		}
	} else if seen["identity.mfa.enable"] {
		t.Fatal("unselected enrollment route advertised")
	}
	if c.HTTPMFA != nil && (c.HTTPMFA.TOTPVerify || c.HTTPMFA.PasswordTOTPVerify || c.HTTPMFA.UsernameTOTPVerify || c.HTTPMFA.VerificationTOTPVerify) || c.HTTPMFAEnrollment != nil && c.HTTPMFAEnrollment.Confirmation || c.HTTPMFAActiveStepUp != nil {
		wantOperations++
		if !seen["identity.mfa.totp-verify"] {
			t.Fatal("selected TOTP route missing")
		}
	} else if seen["identity.mfa.totp-verify"] {
		t.Fatal("unselected TOTP route advertised")
	}
	for _, selected := range []struct {
		enabled   bool
		operation string
	}{
		{c.HTTPMFA != nil && c.HTTPMFA.PasswordOTPSend, "identity.mfa.otp-send"},
		{c.HTTPMFA != nil && c.HTTPMFA.PasswordOTPVerify, "identity.mfa.otp-verify"},
	} {
		if selected.enabled {
			wantOperations++
		}
		if seen[selected.operation] != selected.enabled {
			t.Fatal("secondary OTP route selection mismatch", selected.operation)
		}
	}
	if c.HTTPMFARecoveryRegeneration != nil {
		wantOperations++
		if !seen["identity.mfa.recovery-regenerate"] {
			t.Fatal("selected replacement route missing")
		}
	} else if seen["identity.mfa.recovery-regenerate"] {
		t.Fatal("unselected replacement route advertised")
	}
	if c.HTTPMFAFactorUpdate != nil {
		wantOperations++
		if !seen["identity.mfa.factor-update"] {
			t.Fatal("selected factor-update route missing")
		}
	} else if seen["identity.mfa.factor-update"] {
		t.Fatal("unselected factor-update route advertised")
	}
	if magic {
		wantOperations += 2
		if !seen["identity.magic-link.request"] || !seen["identity.magic-link.consume"] {
			t.Fatal("selected magic-link routes missing")
		}
	}
	if c.HTTPMFA != nil && c.HTTPMFA.PasswordRecoveryUse {
		wantOperations++
		if !seen["identity.mfa.recovery-use"] {
			t.Fatal("selected recovery route missing")
		}
	} else if seen["identity.mfa.recovery-use"] {
		t.Fatal("unselected recovery advertised")
	}
	if changeScreens != nil {
		wantOperations += 2
		if !seen["identity.password.verify"] || !seen["identity.password.change"] {
			t.Fatal("selected protected password routes missing")
		}
	}
	if extensions.organizationTransfer {
		wantOperations++
		if !seen["identity.password.verify"] || seen["identity.password.change"] {
			t.Fatal("transfer selected unrelated password transport")
		}
	}
	if extensions.organizationLifecycle {
		wantOperations++
		if !seen["identity.password.verify"] || seen["identity.password.change"] {
			t.Fatal("lifecycle selected unrelated password transport")
		}
	}
	if extensions.disableHTTP {
		wantOperations++
		if !seen["identity.mfa.disable"] {
			t.Fatal("selected disable HTTP route missing")
		}
	} else if seen["identity.mfa.disable"] {
		t.Fatal("native disable implicitly exposed HTTP")
	}
	if c.HTTPEmailOTPVerification != nil {
		wantOperations += 3
		for _, id := range []string{"identity.otp.send", "identity.otp.email-verify", "identity.otp.email-verify.recover"} {
			if !seen[id] {
				t.Fatal("selected native email OTP route missing")
			}
		}
	} else if seen["identity.otp.email-verify"] || seen["identity.otp.email-verify.recover"] {
		t.Fatal("unselected email OTP route advertised")
	}
	if c.HTTPEmailOTPChange != nil {
		wantOperations += 3
		for _, id := range []string{"identity.otp.email-change-request", "identity.otp.email-change-confirm", "identity.otp.email-change-confirm.recover"} {
			if !seen[id] {
				t.Fatal("selected primary-change OTP route missing", id)
			}
		}
	} else if seen["identity.otp.email-change-request"] || seen["identity.otp.email-change-confirm"] || seen["identity.otp.email-change-confirm.recover"] {
		t.Fatal("native primary-change OTP implicitly advertised HTTP")
	}
	if c.HTTPPhoneRemoval != nil {
		wantOperations++
		if !seen["identity.phone.remove"] {
			t.Fatal("selected phone removal route missing")
		}
	} else if seen["identity.phone.remove"] {
		t.Fatal("native phone removal implicitly exposed HTTP")
	}
	if !seen["identity.password.signup"] || !seen["identity.email.verification-confirm"] || !seen["identity.password.signin"] || (c.HTTPSession != nil && (!seen["identity.session.get"] || !seen["identity.session.signout"])) || len(seen) != wantOperations {
		t.Fatal("selected public registration routes missing")
	}
	network.Config.Handler = server.Handler()
	var organizationHandler atomic.Pointer[http.Handler]
	if extensions.organization {
		initial := server.Handler()
		organizationHandler.Store(&initial)
		network.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			(*organizationHandler.Load()).ServeHTTP(w, r)
		})
	}
	var phoneChangeHandler atomic.Pointer[http.Handler]
	if extensions.phoneChange {
		initial := server.Handler()
		phoneChangeHandler.Store(&initial)
		// Test-only deployment handoff keeps the configured HTTPS origin stable;
		// production servers remain immutable after construction.
		network.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			(*phoneChangeHandler.Load()).ServeHTTP(w, r)
		})
	}
	network.StartTLS()
	client := network.Client()
	if extensions.passkeyHTTP {
		client.Transport = passkeyFixtureHostTransport{next: client.Transport}
	}
	client.Timeout = 5 * time.Second
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.RecoverVelocity(ctx, otpTenant); err == nil {
		t.Fatal("fresh journal fabricated coverage")
	}
	if !extensions.postgresBaseline {
		// Conditional historical coverage proof belongs only to the legacy lane.
		if _, err := f.pool.Raw().Exec(ctx, "UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '61 minutes' WHERE tenant_id=$1 AND state='replaying'", otpTenant); err != nil {
			t.Fatal(err)
		}
		wait(ctx, t, 11*time.Second)
		if _, err := stores.RecoverVelocity(ctx, otpTenant); err != nil {
			t.Fatal("native velocity activation", err)
		}
	}
	if r := server.Readiness(ctx); !r.Ready {
		t.Fatal("selected native readiness", r.Failures)
	}
	if extensions.phoneOTP != "" {
		const rename = `ALTER TABLE session_store.session_issuances RENAME CONSTRAINT session_issuances_purpose_phone_otp_v1 TO phone_otp_fixture_missing`
		if _, err := f.pool.Raw().Exec(ctx, rename); err != nil {
			t.Fatal(err)
		}
		missing := server.Readiness(ctx)
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE session_store.session_issuances RENAME CONSTRAINT phone_otp_fixture_missing TO session_issuances_purpose_phone_otp_v1`); err != nil {
			t.Fatal(err)
		}
		if missing.Ready || !server.Readiness(ctx).Ready {
			t.Fatal("readiness ignored native phone OTP successor")
		}
	}
	if extensions.username {
		if extensions.usernameTOTP {
			f.usernamePrimaryRecovery = func(challenge passwordhttp.SigninResponse, cookies []*http.Cookie) {
				proveReferenceUsernamePrimaryRecovery(t, ctx, c, deps, worker, challenge, cookies, workerConfigs[1:]...)
			}
		}
		targets := []struct{ table, constraint string }{{"identity.registration_bindings", "identity_registration_purpose_v3"}, {"identity_mfa.factor_authorities", "factor_authorities_initialized_purpose_v3"}, {"session_store.session_issuances", "session_issuances_purpose_username_v1"}}
		if extensions.phonePassword {
			targets[2].constraint = "session_issuances_purpose_phone_password_v1"
			targets = append(targets, struct{ table, constraint string }{"identity_password.signin_records", "signin_records_purpose_phone_v1"})
		}
		if extensions.phoneOTP != "" {
			targets[2].constraint = "session_issuances_purpose_phone_otp_v1"
		}
		for _, target := range targets {
			if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE "+target.table+" RENAME CONSTRAINT "+target.constraint+" TO username_fixture_missing"); err != nil {
				t.Fatal(err)
			}
			missing := server.Readiness(ctx)
			if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE "+target.table+" RENAME CONSTRAINT username_fixture_missing TO "+target.constraint); err != nil {
				t.Fatal(err)
			}
			if missing.Ready || !server.Readiness(ctx).Ready {
				t.Fatal("username readiness did not require its actual native successor", target.constraint)
			}
		}
	}
	if magic {
		targets := []struct{ table, name string }{{"session_issuances", "session_issuances_purpose_v5"}, {"sessions", "session_credential_continuation_v2"}, {"sessions", "session_record_binding_v5"}}
		if c.MagicLink.TOTP != nil {
			targets = []struct{ table, name string }{{"session_issuances", "session_issuances_purpose_v6"}, {"sessions", "session_credential_continuation_v3"}, {"sessions", "session_record_binding_v6"}}
		}
		if c.PasswordSignup.VerificationSignin != nil {
			// Verification replaces the predecessor purpose constraint. Probe
			// its actual selected successor, not the deliberately removed name.
			targets[0].name = "session_issuances_purpose_v7"
			if c.PasswordSignup.VerificationSessionLineage == reference.VerificationBeforeMFA && c.PasswordSignup.VerificationTOTP != nil {
				targets[0].name = "session_issuances_purpose_v8"
			}
		}
		for _, target := range targets {
			if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE session_store."+target.table+" RENAME CONSTRAINT "+target.name+" TO magic_fixture_missing"); err != nil {
				t.Fatal(err)
			}
			observation := server.Readiness(ctx)
			if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE session_store."+target.table+" RENAME CONSTRAINT magic_fixture_missing TO "+target.name); err != nil {
				t.Fatal(err)
			}
			if observation.Ready || !server.Readiness(ctx).Ready {
				t.Fatal("magic-link successor constraint did not control readiness")
			}
		}
	}
	if c.HTTPEmailAddresses != nil {
		f.afterEmailQueries = func(cookies []*http.Cookie, user identity.UserID, address identity.IdentifierID) {
			proveReferenceEmailQueriesHTTPS(t, ctx, f, client, network.URL, cookies, user, address, c.HTTPEmailAddresses.List, c.HTTPEmailAddresses.AdministrativeTargets)
		}
	}
	if extensions.emailChangeCase == "shared-http" || extensions.emailChangeCase == "request-http" && !extensions.emailManagementChange {
		f.afterManagedConfirmation = func(r email.VerificationConfirmRequest, target identity.IdentifierID) {
			proveReferenceSharedEmailConfirmationHTTPS(t, ctx, f, client, network.URL, origin, r, target)
		}
	}
	if strings.HasPrefix(extensions.verificationHooks, "managed-") {
		f.afterManagedConfirmation = func(r email.VerificationConfirmRequest, _ identity.IdentifierID) {
			proveManagedVerificationHooks(t, ctx, features, verificationHooks, r)
		}
	}
	if extensions.emailChangeCase == "request-http" {
		selectedFixture := f
		selectedFixture.config = c
		f.emailRequestHTTP = func(r passwordpg.EmailManagementRequest, resend, change bool) (passwordpg.EmailManagementResult, error) {
			return invokeSelectedEmailRequest(t, ctx, selectedFixture, client, network.URL, origin, r, resend, change)
		}
		if extensions.emailManagementChange {
			f.afterManagedChangeConfirmation = func(r email.ChangeConfirmRequest, token string) {
				proveSelectedEmailChangeConfirmation(t, ctx, client, network.URL, origin, r, token)
			}
		}
	}
	if extensions.organization {
		f.afterEmailSignin = func(ctx context.Context, user identity.UserID, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string), _ func([]*http.Cookie) bool) {
			selected, selectedConfig := features, c
			if organizationUpgrade != nil {
				var installed *referenceTeamUpgrade
				if extensions.organizationTeamCRUD || extensions.organizationRoles {
					populated := prepareReferenceTeamUpgrade(t, ctx, features, cookies, csrf)
					installed = &populated
				}
				// Before the explicit operator upgrade, neither advertised metadata
				// nor the actual route may expose the unselected native feature.
				for _, op := range server.OpenAPI().Operations() {
					forbidden := strings.HasPrefix(op.Record.OperationID, "identity.organization.")
					if extensions.organizationRoles {
						forbidden = slices.Contains([]string{string(organization.CreateDynamicRole), string(organization.UpdateDynamicRole), string(organization.DeleteDynamicRole), string(organization.GetDynamicRole), string(organization.ListDynamicRoles), string(organization.CheckPermission)}, op.Record.OperationID)
					} else if extensions.organizationTeamCRUD {
						forbidden = slices.Contains([]string{string(organization.CreateTeam), string(organization.UpdateTeam), string(organization.DeleteTeam), string(organization.ListTeams)}, op.Record.OperationID)
					}
					if forbidden {
						t.Fatal("unselected organization route advertised")
					}
				}
				probePath := "/v1/organization/invitation/list-mine"
				if extensions.organizationTeamCRUD {
					probePath = "/v1/organization/team/list"
				}
				if extensions.organizationRoles {
					probePath = "/v1/organization/role/list"
				}
				if extensions.organizationBindings || extensions.organizationTeamBindings {
					probePath = "/v1/organization/permission-check"
				}
				probe, err := http.NewRequestWithContext(ctx, http.MethodGet, network.URL+probePath, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(probe)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16385))
				closeErr := response.Body.Close()
				if response.StatusCode != http.StatusNotFound || readErr != nil || closeErr != nil {
					t.Fatal("unselected organization route exposed", response.StatusCode)
				}
				selectedConfig = *organizationUpgrade
				upgradeModules := append([]reference.ModuleID(nil), modules...)
				if !slices.Contains(upgradeModules, "organization/postgres") {
					upgradeModules = append(upgradeModules, "organization/postgres")
				}
				selected = upgradeReferenceEmailGraph(t, ctx, f, selectedConfig, deps, worker, upgradeModules, user, migrationRequest, workerConfigs[1:]...)
				upgraded, err := reference.NewServer(config, deps, selected)
				if err != nil {
					t.Fatal("organization upgrade HTTP composition", err)
				}
				next := upgraded.Handler()
				organizationHandler.Store(&next)
				if installed != nil {
					installed.prove(t, ctx, selected)
				}
			}
			if extensions.organizationRoles {
				proveReferenceOrganizationRoles(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf, fresh)
			} else if extensions.organizationTeamCRUD {
				proveReferenceOrganizationTeamCRUD(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf, fresh)
			} else if extensions.organizationTeams {
				proveReferenceOrganizationTeams(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf, fresh)
			} else if extensions.organizationLifecycle {
				proveReferenceOrganizationLifecycle(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf, fresh)
			} else if extensions.organizationExpiry {
				proveReferenceOrganizationExpiry(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf, fresh)
			} else if extensions.organizationTransfer {
				proveReferenceOrganizationTransfer(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf, fresh)
			} else {
				proveReferenceOrganizationHTTPS(t, ctx, f, selectedConfig, deps, selected, workers, workerConfigs, client, network.URL, origin, messages, cookies, csrf)
			}
		}
	}
	if extensions.apiKey {
		f.afterEmailSignin = func(ctx context.Context, user identity.UserID, cookies []*http.Cookie, _ string, _ func(...string) ([]*http.Cookie, string), _ func([]*http.Cookie) bool) {
			proveReferenceAPIKey(t, ctx, f, c, deps, workerConfigs, config, server, client, origin, user, cookies, extensions.apiKeyUpgrade)
		}
	}
	if extensions.passkey {
		f.afterEmailSignin = func(ctx context.Context, user identity.UserID, cookies []*http.Cookie, csrf string, _ func(...string) ([]*http.Cookie, string), _ func([]*http.Cookie) bool) {
			selected, selectedConfig := features, c
			if passkeyUpgrade != nil {
				if owner, err := features.Passkeys(); err == nil || owner != nil {
					t.Fatal("baseline enabled unselected passkey")
				}
				selected = upgradeReferencePasskey(t, ctx, stores, *passkeyUpgrade, deps, workerConfigs, modules)
				selectedConfig = *passkeyUpgrade
			}
			var sessionHandler http.Handler
			var passkeyDocument []byte
			if extensions.passkeySessionHTTP {
				selectedServer, err := reference.NewServer(config, deps, selected)
				if err != nil {
					t.Fatal("selected passkey session HTTP server", err)
				}
				sessionHandler = selectedServer.Handler()
				passkeyDocument = selectedServer.OpenAPI().JSON()
				if extensions.passkeySignup {
					proveReferencePasskeySignupReadiness(t, ctx, selectedServer, deps.PostgreSQL)
				}
			}
			if extensions.passkeyTOTP {
				proveReferencePasskeyTOTPFromEnrollment(t, ctx, f, selected, selectedConfig, client, network.URL, origin, user, cookies, csrf, extensions.passkeyDiscovery, sessionHandler, passkeyDocument)
			} else if extensions.passkeyHTTP {
				proveReferencePasskeyHTTP(t, ctx, selected, selectedConfig, user, cookies, csrf, extensions.passkeyDiscovery, sessionHandler, passkeyDocument)
			} else {
				proveReferencePasskey(t, ctx, selected, selectedConfig, user, cookies, csrf, extensions.passkeyDiscovery, sessionHandler)
			}
			if extensions.passkeySignup {
				if extensions.passkeySignupHTTP {
					proveReferencePasskeySignupHTTP(t, ctx, selected, selectedConfig, sessionHandler, passkeyDocument, deps.PostgreSQL)
				} else {
					proveReferencePasskeySignup(t, ctx, selected, selectedConfig, deps.PostgreSQL)
				}
			}
		}
	}
	if extensions.phoneEnrollment {
		f.afterEmailSignin = func(ctx context.Context, user identity.UserID, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool) {
			var afterVerified func()
			if extensions.phonePassword && extensions.phoneRemoval == "" && !extensions.phoneChange {
				afterVerified = func() {
					proveReferencePhonePasswordHTTPS(t, ctx, f, features, client, network.URL, origin, c.PasswordSignin.PreAuth.CallbackURL, *c.HTTPPreAuth.Device, user, readSession)
				}
			}
			if extensions.phoneOTP != "" && extensions.phoneRemoval == "" {
				prior := afterVerified
				afterVerified = func() {
					if prior != nil {
						prior()
					}
					proveReferencePhoneOTPHTTPS(t, ctx, f, workers, messages, client, network.URL, origin, user, readSession, extensions.phoneOTP == "persistent")
				}
			}
			proveReferencePhoneHTTPS(t, ctx, f, features, workers, messages, client, network.URL, origin, server, user, cookies, csrf, fresh, readSession, afterVerified, c.HTTPPhoneRemoval != nil, c.HTTPPhonePasswordReset != nil)
			if extensions.phoneTOTP {
				// Phone verification correctly invalidates its initiating session.
				// Obtain a real new email/password session before TOTP enrollment;
				// never revive the original session or seed factor authority.
				currentCookies, currentCSRF := fresh()
				token, err := session.ParseToken(currentCookies[0].Value)
				if err != nil {
					t.Fatal(err)
				}
				credential, err := session.NewCredential(session.CredentialCookie, token)
				if err != nil {
					t.Fatal(err)
				}
				sessions, err := features.Sessions()
				if err != nil {
					t.Fatal(err)
				}
				current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
				if err != nil || !current.Authenticated {
					t.Fatal("real phone TOTP enrollment session unavailable", err)
				}
				bindings, err := current.Session.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				proveReferenceMFAEnrollment(t, ctx, f, features, client, network.URL, origin, currentCookies, currentCSRF, bindings.SessionID, false)
			}
			if phoneChangeUpgrade != nil {
				proveReferencePhoneChangeHTTPS(t, ctx, f, *phoneChangeUpgrade, config, deps, workers, workerConfigs, modules, migrationRequest, messages, user, fresh, readSession, client, network.URL, origin, func(h http.Handler) { phoneChangeHandler.Store(&h) })
			}
			if extensions.phoneRemoval != "" {
				removalConfig, removalFeatures := c, features
				if phoneRemovalUpgrade != nil {
					removalConfig = *phoneRemovalUpgrade
					removalFeatures = upgradeReferenceEmailGraph(t, ctx, f, removalConfig, deps, worker, modules, user, migrationRequest, workerConfigs[1:]...)
				}
				rebuild := func() *reference.PhoneRemovalService {
					graph, err := reference.ComposeStores(removalConfig, deps)
					if err != nil {
						t.Fatal("phone removal reconstructed stores", err)
					}
					t.Cleanup(func() {
						bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
						defer stop()
						if err := graph.Close(bounded); err != nil {
							t.Error("phone removal reconstructed graph cleanup", err)
						}
					})
					providers, err := reference.ComposeProviders(graph)
					if err != nil {
						t.Fatal(err)
					}
					workers, err := reference.ComposeWorkers(graph, providers, workerConfigs...)
					if err != nil {
						t.Fatal(err)
					}
					features, err := reference.ComposeFeatures(graph, providers, workers)
					if err != nil {
						t.Fatal(err)
					}
					if err := features.Initialize(ctx); err != nil {
						t.Fatal("phone removal reconstructed initialization", err)
					}
					owner, err := features.PhoneRemoval()
					if err != nil {
						t.Fatal(err)
					}
					return owner
				}
				proveReferencePhoneRemoval(t, ctx, f, removalFeatures, workers, messages, client, network.URL, origin, removalConfig, user, fresh, readSession, extensions.phoneRemoval, rebuild)
			}
		}
	}
	if extensions.emailManagementResend || extensions.emailManagementChange {
		f.afterEmailSignin = func(ctx context.Context, user identity.UserID, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool) {
			managementConfig, managementFeatures := c, features
			if emailUpgrade != nil {
				managementConfig = *emailUpgrade
				managementFeatures = upgradeReferenceEmailGraph(t, ctx, f, managementConfig, deps, worker, modules, user, migrationRequest)
			}
			var change *referenceEmailChangeOptions
			if strings.HasPrefix(extensions.emailChangeCase, "otp-verification") {
				f.afterManagedPending = func(old capability.Proof, pending identity.IdentifierID, current []*http.Cookie, currentCSRF, callback string) {
					if extensions.emailChangeCase == "otp-verification-reference-https" {
						proveReferenceEmailOTPVerification(t, ctx, f, managementFeatures, workers, messages, user, pending, current, readSession, extensions.emailChangeCase, old, callback, managementConfig, currentCSRF, emailOTPHTTPSSelection{client: client, base: network.URL, origin: origin, server: server})
						return
					}
					proveReferenceEmailOTPVerification(t, ctx, f, managementFeatures, workers, messages, user, pending, current, readSession, extensions.emailChangeCase, old, callback, managementConfig, currentCSRF)
				}
			}
			if extensions.emailRemoval {
				f.emailRemovalMode = extensions.emailChangeCase
				f.afterEmailRemovalPreparation = func(token capability.Proof, pending identity.IdentifierID, r passwordpg.EmailManagementRequest, current []*http.Cookie, currentCSRF string) {
					proveReferenceEmailRemoval(t, ctx, f, managementFeatures, workers, client, network.URL, origin, messages, user, token, pending, r, current, currentCSRF, readSession, fresh)
				}
			}
			if extensions.emailManagementChange {
				change = &referenceEmailChangeOptions{readSession: readSession, recipients: noticeRecipients, mode: extensions.emailChangeCase, deliveries: changeDeliveries, initialPrimary: extensions.emailOTPInitialPrimary}
				if strings.HasPrefix(extensions.emailChangeCase, "totp-change") {
					change.totpEnrollment = func(saved []*http.Cookie, savedCSRF string, defaultRequest passwordpg.EmailManagementRequest) {
						selected := managementConfig
						e, native := *selected.Email, *selected.Email.Change
						e.TOTPChange = true
						native.Primary.Audience = selected.MFAEnrollment.ActiveStepUp.Audience
						requestKeys, err := kernel.NewRequestKeyConfig("reference-managed-email", [32]byte{219}, selected.OTP.RequestKeys.Policy)
						if err != nil {
							t.Fatal(err)
						}
						keyed, err := passwordpg.NewKeyedEmailManagementConfig(requestKeys, [32]byte{220})
						if err != nil {
							t.Fatal(err)
						}
						native.Keyed = &keyed
						profile := *native.Native.Change
						profile.CurrentAddress = email.RequirePrimaryAddress
						native.Native.Change = &profile
						e.Change, selected.Email = &native, &e
						mfa, step := *selected.MFAEnrollment, *selected.MFAEnrollment.ActiveStepUp
						step.EmailChange = true
						if extensions.emailChangeCase == "totp-change-expiry" {
							step.TTL = 5 * time.Second
						}
						mfa.ActiveStepUp, selected.MFAEnrollment = &step, &mfa
						httpSelected := extensions.emailChangeCase == "totp-change-http" || extensions.emailChangeCase == "totp-change-mfa-http"
						if httpSelected {
							selected.HTTPMFAActiveStepUp = &reference.HTTPMFAActiveStepUpConfiguration{Purposes: []auth.Purpose{"identity.email.change-request"}, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, VerificationNamespace: "reference-email-totp-step-up", VerificationKey: [32]byte{195}}
							selected.HTTPEmailRequests = &reference.HTTPEmailRequestsConfiguration{ChangeRequest: true, ChangeConfirm: true, Origin: origin, ActorID: c.HTTPRegistrationVerification.ActorID, PolicyRevision: 9}
						}
						upgraded := upgradeReferenceEmailGraph(t, ctx, f, selected, deps, worker, modules, user, migrationRequest)
						sessions, err := upgraded.Sessions()
						if err != nil {
							t.Fatal(err)
						}
						token, _ := session.ParseToken(saved[0].Value)
						credential, _ := session.NewCredential(session.CredentialCookie, token)
						current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
						if err != nil || !current.Authenticated {
							t.Fatal("genuine primary bootstrap lost session", err)
						}
						binding, _ := current.Session.Bindings()
						local := f
						local.config = selected
						local.emailTOTPChange = true
						selectedClient, selectedBase := client, network.URL
						var browserProof auth.ProofID
						if httpSelected {
							httpOwner, err := reference.NewServer(config, deps, upgraded)
							if err != nil {
								t.Fatal("selected email TOTP HTTP graph", err)
							}
							https := httptest.NewTLSServer(httpOwner.Handler())
							t.Cleanup(https.Close)
							// Keep the genuine deployment origin/Host while directing only
							// the test TCP connection to the separately selected router.
							// A second port is cross-origin to the existing CORS policy.
							transport := https.Client().Transport.(*http.Transport).Clone()
							transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
								return (&net.Dialer{}).DialContext(ctx, network, https.Listener.Addr().String())
							}
							selectedClient = &http.Client{Transport: transport}
							selectedClient.Timeout = 10 * time.Second
							t.Cleanup(selectedClient.CloseIdleConnections)
							local.activeStepUpHTTP = true
							local.afterEmailFactorHTTP = func(id auth.ProofID) { browserProof = id }
						}
						local.afterEmailFactor = func(proof auth.ReauthenticationProof, cookies []*http.Cookie, csrf string, codes []string) {
							proveReferenceEmailTOTPChange(t, ctx, local, upgraded, managementFeatures, workers, selectedClient, selectedBase, origin, messages, noticeRecipients, changeDeliveries, user, proof, cookies, csrf, codes, defaultRequest, browserProof, extensions.emailChangeCase)
						}
						proveReferenceMFAEnrollment(t, ctx, local, upgraded, selectedClient, selectedBase, origin, saved, savedCSRF, binding.SessionID, false)
					}
				}
				if extensions.emailChangeCase == "otp-change-reference-https" {
					change.httpChange = &emailOTPHTTPSSelection{client: client, base: network.URL, origin: origin, server: server}
				} else if strings.HasPrefix(extensions.emailChangeCase, "otp-change") && strings.Contains(string(server.OpenAPI().JSON()), "/v1/otp/email-change") {
					t.Fatal("native primary change implicitly exposed HTTP metadata")
				}
			}
			proveReferenceEmailManagementResend(t, ctx, f, managementConfig, deps, managementFeatures, workers, messages, origin, user, cookies, csrf, fresh, change)
		}
	}
	if extensions.verificationHooks != "" && !strings.HasPrefix(extensions.verificationHooks, "managed-") {
		proveReferenceVerificationHooks(t, ctx, f, features, workers, client, network.URL, origin, messages, verificationHooks)
		return
	}
	if extensions.verificationSignin != "" {
		f.config = c
		if extensions.verificationSignin == "upgrade" || extensions.verificationSignin == "upgrade-mfa-first" {
			f.afterVerificationSignin = func(credential session.Credential) {
				proveVerificationMFAPopulatedUpgrade(t, ctx, f, c, deps, worker, modules, config, origin, migrationRequest, credential)
			}
		}
		proveReferenceVerificationSignin(t, ctx, f, features, workers, client, network.URL, origin, messages, extensions.verificationSignin)
		return
	}
	if extensions.username {
		proveReferenceUsername(t, ctx, f, features, workers, client, network.URL, origin, messages)
		return
	}
	if extensions.phoneTOTP || extensions.mfaOTPEnrollment {
		f.config = c
	}
	proveReferenceRegistration(t, ctx, f, features, workers, client, network.URL, origin, messages, calls, competing, changeScreens, extensions.mfaEnrollment, extensions.passwordMFA, extensions.emailAddressQueries, c.Email != nil && c.Email.Addresses != nil, extensions.passwordRecovery)
	if extensions.phoneTOTP && !*f.phoneTOTPCompleted {
		t.Fatal("selected phone TOTP consumer was skipped")
	}
	if extensions.phonePasswordReset && !*f.phoneResetCompleted {
		t.Fatal("selected phone reset consumer was skipped")
	}
	if extensions.emailSignin != "" {
		proveReferenceEmailOTPSignin(t, ctx, f, features, workers, client, network.URL, origin, messages, extensions.emailSignin)
	}
	if magic {
		proveReferenceMagicLink(t, ctx, f, features, workers, client, network.URL, origin, messages, c, deps, len(protected) > 5 && protected[5])
	}
}

func proveReferenceRegistration(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, screens *atomic.Int32, competing bool, changeScreens *atomic.Int32, enrollment bool, passwordMFA bool, queryEmail bool, composedEmailQueries bool, recoveryLogin ...bool) {
	t.Helper()
	invoke := func(path string, body any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 {
			t.Fatal("bounded response")
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("credential response cacheable")
		}
		return response, payload
	}
	issue := func(method string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, p := invoke("/v1/session/preauth-issue", map[string]string{"method": method}, "", nil)
		var out sessionhttp.PreAuthResponse
		if r.StatusCode != 200 || json.Unmarshal(p, &out) != nil || !out.Issued {
			t.Fatal("original method initiation", r.StatusCode)
		}
		return out, r.Cookies()
	}
	flow, cookies := issue("signup")
	body := map[string]any{"flowID": string(flow.FlowID), "email": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}
	// Fail after password/factor/authorization initialization and issuer staging.
	// The sole native transaction must roll every business effect back together.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION registration_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic registration rollback'; END $$;
CREATE TRIGGER registration_fixture_fail BEFORE INSERT ON identity.delivery_intents FOR EACH ROW EXECUTE FUNCTION registration_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	failed, payload := invoke("/v1/password/signup", body, "registration-rollback-key", cookies)
	if failed.StatusCode == 200 || len(failed.Cookies()) != 0 || bytes.Contains(payload, []byte("synthetic-registration-password")) {
		t.Fatal("failed signup disclosed credentials or succeeded")
	}
	var effects int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users)+(SELECT count(*) FROM identity_password.credentials)+(SELECT count(*) FROM identity_mfa.factor_authorities)+(SELECT count(*) FROM authorization_subject_authorities)+(SELECT count(*) FROM identity.delivery_intents)+(SELECT count(*) FROM capability_identity_one_use)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("signup rollback leaked account/authority/credential/delivery effects", effects, err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER registration_fixture_fail ON identity.delivery_intents; DROP FUNCTION registration_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	r, p := invoke("/v1/password/signup", body, "registration-original-key", cookies)
	var signup passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(r.Cookies()) != 0 {
		t.Fatal("native public signup", r.StatusCode, signup.Error, signup.CommitOutcome)
	}
	var users, passwords, factors, deliveries, grants int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity_password.credentials),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE active_factors=0 AND version=1),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM capability_identity_one_use)`).Scan(&users, &passwords, &factors, &deliveries, &grants); err != nil || users != 1 || passwords != 1 || factors != 1 || deliveries != 1 || grants != 1 {
		t.Fatal("signup did not atomically create actual owners", err)
	}
	screened := screens.Load()
	if screened != 2 {
		t.Fatal("rollback and successful original signup were not screened exactly once each")
	}
	r, p = invoke("/v1/password/signup", body, "registration-original-key", cookies)
	var replay passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &replay) != nil || !replay.Replayed || replay.CommandID != signup.CommandID || screens.Load() != screened || len(r.Cookies()) != 0 {
		t.Fatal("keyed signup replay regenerated effects", r.StatusCode)
	}
	changed := map[string]any{"flowID": string(flow.FlowID), "email": "changed@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}
	r, _ = invoke("/v1/password/signup", changed, "registration-original-key", cookies)
	if r.StatusCode == 200 {
		t.Fatal("changed keyed signup replaced original input")
	}
	login, loginCookies := issue("password")
	loginBody := map[string]any{"flowID": string(login.FlowID), "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}
	r, _ = invoke("/v1/password/signin", loginBody, "", loginCookies)
	if r.StatusCode == 200 || len(r.Cookies()) != 0 {
		t.Fatal("unverified registration authenticated")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("actual encrypted delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("delivery absent")
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" {
		t.Fatal("invalid delivered link")
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatal("native issuer token absent")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	confirmationBody := map[string]string{"token": token, "callback": origin + "/confirm", "commandID": string(command)}
	wrong := map[string]string{"token": token, "callback": origin + "/foreign", "commandID": string(command)}
	r, p = invoke("/v1/email/verification-confirm", wrong, "", nil)
	if r.StatusCode == 200 || len(r.Cookies()) != 0 || bytes.Contains(p, []byte(token)) {
		t.Fatal("foreign callback reached confirmation")
	}
	r, p = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &confirmed) != nil || !confirmed.Confirmed || confirmed.Address == nil || confirmed.Replayed || len(r.Cookies()) != 0 || bytes.Contains(p, []byte(token)) {
		t.Fatal("public native confirmation", r.StatusCode)
	}
	r, p = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
	var repeated emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &repeated) != nil || !repeated.Confirmed || !repeated.Replayed || repeated.Address != nil || len(r.Cookies()) != 0 {
		t.Fatal("confirmation replay disclosed/reconsumed", r.StatusCode)
	}
	if confirmed.Recovery == nil {
		t.Fatal("committed confirmation lost recovery correlation")
	}
	correlation := confirmed.Recovery
	recovery, err := email.NewVerificationRecovery(identity.RecoveryQuery{CommandID: confirmed.CommandID, TenantID: correlation.TenantID, UserID: correlation.UserID, RecordID: correlation.RecordID, ActorID: correlation.ActorID, ActorKind: correlation.ActorKind, OperationID: "identity.email.verification-confirm"})
	if err != nil {
		t.Fatal(err)
	}
	confirmationOwner, err := features.RegistrationVerification()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(otpTenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(correlation.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	recovered, err := confirmationOwner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: recovery, Caller: caller})
	if err != nil || recovered.Validate() != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Recovery != recovery {
		t.Fatal("selected typed confirmation recovery", err)
	}
	foreign := caller
	foreign.Request.Tenant = "foreign-tenant"
	if _, err := confirmationOwner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: recovery, Caller: foreign}); err == nil {
		t.Fatal("foreign tenant disclosed confirmation recovery")
	}
	var verified, consumed, charges, confirmationRows int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM risk_store.counter_charges)`).Scan(&verified, &consumed, &charges); err != nil || verified != 1 || consumed != 1 || charges != 1 {
		t.Fatal("confirmation atomic effects/replay", err)
	}
	login, loginCookies = issue("password")
	var policyAuthorities int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace='users'`, otpTenant).Scan(&policyAuthorities); err != nil || policyAuthorities != 1 {
		t.Fatal("new registration has no native authorization authority for signin", policyAuthorities, err)
	}
	loginBody["flowID"] = string(login.FlowID)
	r, p = invoke("/v1/password/signin", loginBody, "", loginCookies)
	var signed passwordhttp.SigninResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &signed) != nil || signed.CommitOutcome != "committed" || signed.SessionID == "" || len(r.Cookies()) != 1 {
		t.Fatal("verified registration did not produce usable login", r.StatusCode, signed.CommitOutcome, signed.Error, signed.CommandID != "", signed.SessionID != "")
	}
	if queryEmail {
		proveReferenceEmailQueries(t, ctx, f, features, r.Cookies(), correlation.UserID, identity.IdentifierID(correlation.RecordID), composedEmailQueries)
	}
	if f.afterEmailQueries != nil {
		f.afterEmailQueries(r.Cookies(), correlation.UserID, identity.IdentifierID(correlation.RecordID))
	}
	if f.adminEmailGrant != nil && !f.adminEmailGrant.removal {
		proveAdministrativeEmailReads(t, ctx, f, features, workers, client, base, origin, messages, invoke, issue, r.Cookies(), r.Header.Get("X-CSRF-Token"), signed.SessionID, correlation.UserID)
		return
	}
	if f.emailQueriesStandalone {
		return
	} // This profile deliberately has no HTTP session/logout routes.
	if f.afterEmailSignin != nil {
		freshLogin := func(address ...string) ([]*http.Cookie, string) {
			flow, deviceCookies := issue("password")
			body := make(map[string]any, len(loginBody))
			for k, v := range loginBody {
				body[k] = v
			}
			body["flowID"] = string(flow.FlowID)
			if len(address) > 1 {
				t.Fatal("ambiguous genuine login address")
			}
			if len(address) == 1 {
				body["identifier"] = address[0]
			}
			response, payload := invoke("/v1/password/signin", body, "", deviceCookies)
			var login passwordhttp.SigninResponse
			if response.StatusCode != 200 || json.Unmarshal(payload, &login) != nil || !login.SignedIn || len(response.Cookies()) != 1 {
				t.Fatal("fresh genuine login after email authority change", response.StatusCode, login.Error)
			}
			return response.Cookies(), response.Header.Get("X-CSRF-Token")
		}
		readSession := func(cookies []*http.Cookie) bool {
			request, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/session/get", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("actual saved-session read", err)
			}
			payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
			closed := response.Body.Close()
			var current sessionhttp.GetResponse
			if err != nil || closed != nil || len(payload) > 16384 || json.Unmarshal(payload, &current) != nil {
				t.Fatal("saved-session response cleanup/shape")
			}
			if !current.Authenticated && (current.Principal != nil || current.Session != nil) {
				t.Fatal("denied session disclosed authentication")
			}
			return response.StatusCode == http.StatusOK && current.Authenticated && current.Session != nil
		}
		f.afterEmailSignin(ctx, correlation.UserID, r.Cookies(), r.Header.Get("X-CSRF-Token"), freshLogin, readSession)
		return
	}
	if f.mfaOTPEnrollment {
		proveReferenceMFAOTPEnrollment(t, ctx, f, features, workers, client, base, origin, r.Cookies(), r.Header.Get("X-CSRF-Token"), messages, identity.IdentifierID(correlation.RecordID))
		return
	}
	if enrollment {
		if f.regenerationDenials || f.factorManagementDenials || f.factorRemoval || strings.HasSuffix(f.replacementContinuationDenial, "other-session") {
			secondFlow, secondCookies := issue("password")
			secondBody := map[string]any{}
			for key, value := range loginBody {
				secondBody[key] = value
			}
			secondBody["flowID"] = string(secondFlow.FlowID)
			second, payload := invoke("/v1/password/signin", secondBody, "", secondCookies)
			var other passwordhttp.SigninResponse
			if second.StatusCode != 200 || json.Unmarshal(payload, &other) != nil || !other.SignedIn || other.SessionID == signed.SessionID || len(second.Cookies()) != 1 {
				t.Fatal("second genuine source session unavailable")
			}
			f.secondBearer, f.secondCSRF = second.Cookies()[0].Value, second.Header.Get("X-CSRF-Token")
		}
		if f.factorRemovalReset {
			f.afterFactorRemoval = func(ctx context.Context, user identity.UserID) {
				proveReferenceEmailResetAfterRemoval(t, ctx, f, features, workers, client, base, origin, loginCookies, messages, user)
			}
		}
		proveReferenceMFAEnrollment(t, ctx, f, features, client, base, origin, r.Cookies(), r.Header.Get("X-CSRF-Token"), signed.SessionID, passwordMFA, recoveryLogin...)
		return
	}
	if changeScreens != nil {
		proveReferencePasswordProtection(t, ctx, f, features, client, base, origin, append(loginCookies, r.Cookies()...), r.Header.Get("X-CSRF-Token"), changeScreens)
		return
	}
	logoutID := proveRegistrationSessionLogout(t, ctx, client, base, origin, r.Cookies(), r.Header.Get("X-CSRF-Token"), signed.SessionID, f, features)
	commandBytes, err := base64.RawURLEncoding.DecodeString(string(logoutID))
	if err != nil {
		t.Fatal("logout command identity malformed")
	}
	var revocations, audits, events int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, commandBytes).Scan(&revocations, &audits, &events); err != nil || revocations != 1 || audits != 1 || events != 1 {
		t.Fatal("logout omitted or repeated protected effects", err)
	}
	if screens.Load() != screened {
		t.Fatal("confirmation/login repeated password creation screening")
	}
	if !competing {
		// A distinct real account supplies the rollback grant. Proven abort retires
		// that grant; it must never be reissued by resetting fixture state.
		flow, cookies = issue("signup")
		body["flowID"], body["email"] = string(flow.FlowID), "rollback@example.invalid"
		r, p = invoke("/v1/password/signup", body, "confirmation-rollback-signup", cookies)
		if r.StatusCode != 200 || json.Unmarshal(p, &signup) != nil || signup.CommitOutcome != "committed" {
			t.Fatal("rollback account signup", r.StatusCode)
		}
		if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
			t.Fatal(err)
		}
		select {
		case link = <-messages:
		case <-ctx.Done():
			t.Fatal("rollback delivery absent")
		}
		u, err = url.Parse(link)
		if err != nil {
			t.Fatal("invalid rollback delivery")
		}
		token = u.Query().Get("token")
		command, err = identity.NewCommandID()
		if err != nil || token == "" {
			t.Fatal("rollback proof or command absent")
		}
		confirmationBody["token"], confirmationBody["commandID"] = token, string(command)
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION confirmation_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic confirmation rollback'; END $$;
CREATE TRIGGER confirmation_fixture_fail BEFORE INSERT ON identity.email_verifications FOR EACH ROW EXECUTE FUNCTION confirmation_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		r, p = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
		if r.StatusCode == 200 || len(r.Cookies()) != 0 || bytes.Contains(p, []byte(token)) {
			t.Fatal("failed confirmation disclosed credentials or succeeded")
		}
		// Failed protected attempts remain charged to prevent unlimited retries.
		// The first account stays verified; the failed grant has no committed use.
		var abortedCharges, released int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM identity.email_verifications),(SELECT count(*) FROM risk_store.counter_charges),(SELECT count(*) FROM risk_store.counter_charges r JOIN identity.commands c USING(command_id) WHERE c.state='aborted'),(SELECT count(*) FROM capability_identity_one_use WHERE state='released' AND uses=0)`).Scan(&verified, &consumed, &confirmationRows, &charges, &abortedCharges, &released); err != nil || verified != 1 || consumed != 1 || confirmationRows != 1 || charges != 2 || abortedCharges != 1 || released != 1 {
			t.Fatal("confirmation rollback lost atomic effects or attempt custody", verified, consumed, confirmationRows, charges, abortedCharges, released, err)
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER confirmation_fixture_fail ON identity.email_verifications; DROP FUNCTION confirmation_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		r, _ = invoke("/v1/email/verification-confirm", confirmationBody, "", nil)
		if r.StatusCode == 200 || len(r.Cookies()) != 0 {
			t.Fatal("aborted confirmation proof revived")
		}
		return
	}
	// Competing public native commands share the exact delivered grant, not a
	// test-created reservation. Only one may commit its proof and address effects.
	flow, cookies = issue("signup")
	body["flowID"], body["email"] = string(flow.FlowID), "competing@example.invalid"
	r, p = invoke("/v1/password/signup", body, "competing-confirmation-signup", cookies)
	if r.StatusCode != 200 || json.Unmarshal(p, &signup) != nil || signup.CommitOutcome != "committed" {
		t.Fatal("competing account signup", r.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("competing delivery absent")
	}
	u, err = url.Parse(link)
	if err != nil {
		t.Fatal("invalid competing delivery")
	}
	proof, err := capability.ParseProof(u.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("competing delivered proof invalid")
	}
	callback, err := url.Parse(origin + "/confirm")
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Resource.ID = ""
	caller.Request.Environment.Time = time.Now().UTC()
	type attemptResult struct {
		out email.VerificationConfirmResult
		err error
	}
	completed := make(chan attemptResult, 2)
	start := make(chan struct{})
	for range 2 {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		request := email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: proof, Callback: *callback, Network: "127.0.0.1", Caller: caller}
		request.Caller.CorrelationID = string(id)
		go func() {
			<-start
			out, err := confirmationOwner.VerificationConfirm(ctx, request)
			completed <- attemptResult{out: out, err: err}
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		select {
		case result := <-completed:
			if result.err == nil && result.out.Outcome == identity.CommitOutcomeCommitted {
				winners++
			} else if result.out.Outcome == identity.CommitOutcomeCommitted || result.out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("losing command disclosed successful effects")
			}
		case <-ctx.Done():
			t.Fatal("competing native confirmation did not terminate")
		}
	}
	if winners != 1 {
		t.Fatal("competing proof had no unique committed owner", winners)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM identity.email_verifications)`).Scan(&verified, &consumed, &confirmationRows); err != nil || verified != 2 || consumed != 2 || confirmationRows != 2 {
		t.Fatal("competing confirmation duplicated or lost protected effects", err)
	}
}

func proveRegistrationSessionLogout(t *testing.T, ctx context.Context, client *http.Client, base, origin string, cookies []*http.Cookie, csrf, sessionID string, f liveStores, features reference.FeatureSet) identity.CommandID {
	t.Helper()
	call := func(method, path, token string) (*http.Response, []byte) {
		var body io.Reader
		if method == "POST" {
			body = strings.NewReader("{}")
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if method == "POST" {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
		}
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded/cacheable session response")
		}
		return response, payload
	}
	r, p := call("GET", "/v1/session/get", "")
	var read sessionhttp.GetResponse
	if r.StatusCode != 200 || json.Unmarshal(p, &read) != nil || !read.Authenticated || read.Session == nil || read.Session.ID != sessionID {
		t.Fatal("new login session not readable", r.StatusCode)
	}
	r, _ = call("POST", "/v1/session/signout", "")
	if r.StatusCode != 403 || len(r.Cookies()) != 0 {
		t.Fatal("active logout bypassed CSRF or cleared cookie", r.StatusCode)
	}
	r, p = call("GET", "/v1/session/get", "")
	read = sessionhttp.GetResponse{}
	if r.StatusCode != 200 || json.Unmarshal(p, &read) != nil || !read.Authenticated {
		t.Fatal("CSRF denial revoked session")
	}
	if csrf == "" {
		t.Fatal("login did not deliver synchronizer token")
	}
	owner, err := features.Sessions()
	if err != nil {
		t.Fatal("selected native session port absent", err)
	}
	recoverOutcome := func(result sessionhttp.SignOutResponse, want identity.CommitOutcome) {
		t.Helper()
		if result.Recovery == nil || result.Recovery.CommandID != result.CommandID || result.Recovery.TenantID != otpTenant || result.Recovery.RecordID != sessionID {
			t.Fatal("logout lost original recovery scope")
		}
		q := result.Recovery
		query := identity.RecoveryQuery{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, AnonymousFlowID: q.AnonymousFlowID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, RecordID: q.RecordID, LinkMode: q.LinkMode}
		caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(q.ActorID), Kind: q.ActorKind}, Action: authorization.Action(q.OperationID), Tenant: authorization.TenantID(q.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}}}
		historical, err := owner.RecoverSignOut(ctx, query, caller)
		var unavailable identity.UnavailableError
		errorMatches := err == nil
		if want == identity.CommitOutcomeNotCommitted {
			// Terminal dependency-failure history preserves its original error,
			// not a fabricated successful recovery or permission to reexecute.
			errorMatches = errors.As(err, &unavailable)
		}
		if !errorMatches || historical.Outcome != want || historical.Binding.CommandID != query.CommandID || historical.Binding.RecordID != sessionID {
			t.Fatal("selected logout recovery lost terminal history", err)
		}
		foreign := caller
		foreign.Request.Tenant = "foreign-tenant"
		if _, err := owner.RecoverSignOut(ctx, query, foreign); err == nil {
			t.Fatal("foreign tenant acquired logout history")
		}
	}
	// Reject the downstream lifecycle binding after the native revocation has
	// been staged. No cookie clearing or successful effect may escape rollback.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.session_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic session rollback'; END $$;
CREATE TRIGGER session_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.session_fixture_fail()`); err != nil {
		t.Fatal("session failure fixture", err)
	}
	cleanup := func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER IF EXISTS session_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION IF EXISTS public.session_fixture_fail()`); err != nil {
			t.Error("session failure fixture cleanup", err)
		}
	}
	t.Cleanup(cleanup)
	r, p = call("POST", "/v1/session/signout", csrf)
	var aborted sessionhttp.SignOutResponse
	if json.Unmarshal(p, &aborted) != nil || r.StatusCode != 503 || aborted.CommitOutcome != "not_committed" || aborted.SignedOut || len(r.Cookies()) != 0 {
		t.Fatal("failed lifecycle falsely cleared logout", r.StatusCode, aborted.CommitOutcome, aborted.Error, "signed-out", aborted.SignedOut, "cookies", len(r.Cookies()))
	}
	cleanup()
	abortedID, err := base64.RawURLEncoding.DecodeString(string(aborted.CommandID))
	if err != nil {
		t.Fatal("aborted logout lost command identity")
	}
	var transitions, successfulAudits, lifecycle int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, abortedID, int64(audit.OutcomeSucceeded)).Scan(&transitions, &successfulAudits, &lifecycle); err != nil || transitions != 0 || successfulAudits != 0 || lifecycle != 0 {
		t.Fatal("failed lifecycle leaked successful protected effects", err)
	}
	recoverOutcome(aborted, identity.CommitOutcomeNotCommitted)
	r, p = call("GET", "/v1/session/get", "")
	read = sessionhttp.GetResponse{}
	if json.Unmarshal(p, &read) != nil || r.StatusCode != 200 || !read.Authenticated {
		t.Fatal("failed lifecycle revoked active session")
	}
	r, p = call("POST", "/v1/session/signout", csrf)
	var logout sessionhttp.SignOutResponse
	decodeErr := json.Unmarshal(p, &logout)
	if r.StatusCode != 200 || decodeErr != nil || !logout.SignedOut || logout.CommitOutcome != "committed" || len(r.Cookies()) != 1 || r.Cookies()[0].MaxAge != -1 {
		var shape map[string]json.RawMessage
		_ = json.Unmarshal(p, &shape)
		keys := make([]string, 0, len(shape))
		for key := range shape {
			keys = append(keys, key)
		}
		t.Fatal("native logout failed", r.StatusCode, logout.Error, logout.CommitOutcome, "JSON", json.Valid(p), "decode", decodeErr != nil, "fields", keys, "bytes", len(p))
	}
	recoverOutcome(logout, identity.CommitOutcomeCommitted)
	command := logout.CommandID
	r, p = call("GET", "/v1/session/get", "")
	read = sessionhttp.GetResponse{}
	if r.StatusCode != 200 || json.Unmarshal(p, &read) != nil || read.Authenticated || read.Session != nil || read.Principal != nil {
		t.Fatal("revoked session still authenticated")
	}
	r, p = call("POST", "/v1/session/signout", "")
	logout = sessionhttp.SignOutResponse{}
	if r.StatusCode != 200 || json.Unmarshal(p, &logout) != nil || !logout.SignedOut {
		t.Fatal("repeated logout was not neutral", r.StatusCode)
	}
	return command
}
