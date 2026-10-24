package reference

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// PasskeyStandaloneConfiguration selects the passkey-only deployment graph.
// The directory's bootstrap set is explicit and immutable; it is never inferred
// from configured rate scopes. Bounds retain the same native risk/audit owners
// as the existing deployment. AuditTimeout and RiskTimeout are 1ms..5s, with
// audit inside risk and risk inside Session.Native.MaximumDuration. The session
// operation retains its native 1ms..30s bounds.
// Password, OTP, delivery and password-proof management are not selected.
type PasskeyStandaloneConfiguration struct {
	BootstrapTenantIDs        []identity.TenantID
	RiskTimeout, AuditTimeout time.Duration
	RiskPolicyID              string
}

func (PasskeyStandaloneConfiguration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.PasskeyStandaloneConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment-scope export.
func (PasskeyStandaloneConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit deployment-scope export.
func (PasskeyStandaloneConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// This is a selection branch of the same sealed public graph, not another
// application constructor. Every runtime remains its existing native owner.
func (s *storeState) composeStandalonePasskeys(c StoreConfiguration, d ReferenceDependencies) error {
	invalid := identity.InvalidInputError{Field: "reference_passkey_standalone"}
	if c.Passkey == nil || c.Passkey.Standalone == nil || c.Session == nil || !c.Session.Passkey || c.DurableAdmission == nil || d.PostgreSQL == nil || d.EnvelopeKeys != nil || d.DeliverySender != nil {
		return invalid
	}
	// Unsupported mixed profiles must fail rather than silently drop selected
	// workflows, providers or HTTP metadata. The retained graph owns those modes.
	if c.OTP != nil || c.Delivery != nil || c.PasswordSignin != nil || c.PasswordSignup != nil || c.PasswordReset != nil || c.PasswordVerification != nil || c.PasswordChange != nil || c.Username != nil || c.Email != nil || c.Phone != nil || c.PhoneRemoval != nil || c.PhoneChange != nil || c.PhoneSignin != nil || c.PhoneOTPSignin != nil || c.PhonePasswordReset != nil || c.MagicLink != nil || c.Anonymous != nil || c.MFAEnrollment != nil || c.MFAOTPEnrollment != nil {
		return invalid
	}
	if c.HTTPEmailSignin != nil || c.HTTPEmailOTPVerification != nil || c.HTTPEmailOTPChange != nil || c.HTTPEmailAddresses != nil || c.HTTPEmailRequests != nil || c.HTTPPhoneVerification != nil || c.HTTPPhoneChange != nil || c.HTTPPhoneRemoval != nil || c.HTTPPhoneSignin != nil || c.HTTPPhoneOTPSignin != nil || c.HTTPPhonePasswordReset != nil || c.HTTPPasswordSignin != nil || c.HTTPPasswordSignup != nil || c.HTTPPasswordReset != nil || c.HTTPPasswordVerification != nil || c.HTTPPasswordChange != nil || c.HTTPUsername != nil || c.HTTPRegistrationVerification != nil || c.HTTPMagicLink != nil || c.HTTPAnonymous != nil || c.HTTPMFA != nil || c.HTTPMFAEnrollment != nil || c.HTTPMFAActiveStepUp != nil || c.HTTPMFARecoveryRegeneration != nil || c.HTTPMFAFactorUpdate != nil || c.HTTPMFADisable != nil || c.HTTPMFAList != nil {
		return invalid
	}
	p, e := c.Passkey.Standalone, c.Session.Native.Execution
	if len(p.BootstrapTenantIDs) > 256 || p.RiskTimeout < time.Millisecond || p.RiskTimeout > 5*time.Second || p.RiskTimeout > c.Session.Native.MaximumDuration || p.AuditTimeout < time.Millisecond || p.AuditTimeout > p.RiskTimeout || c.Passkey.Signup == nil || c.Passkey.Management != nil || c.Passkey.Deletion != nil {
		return invalid
	}
	if _, err := (kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 1016, GlobalAuthorityID: e.Profile.GlobalAuthorityID, TenantIDs: p.BootstrapTenantIDs}).Load(context.Background()); err != nil {
		return invalid
	}
	migrationConfig := featureMigrationConfig{standalonePasskey: true, sessionSchema: e.Repository.Schema, signinSchema: e.Repository.Schema, global: e.Profile.GlobalAuthorityID, tenants: slices.Clone(p.BootstrapTenantIDs), preauthIssue: true, singleSessionRevocation: true}
	if err := migrationConfig.validateNamespaces(s.config.Schema); err != nil {
		return err
	}
	sink, err := auditpg.New(d.PostgreSQL.Raw(), auditpg.Config{})
	if err != nil {
		return err
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: s.policy, Keys: s.keys, Store: velocityCounterRouter{state: s}, Clock: time.Now, Timeout: p.RiskTimeout})
	if err != nil {
		return err
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: s.policy, Counters: &counters, Clock: time.Now, Timeout: p.RiskTimeout, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: p.RiskPolicyID, Timeout: p.AuditTimeout, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, lost.Record())
		return err
	}}})
	if err != nil {
		return err
	}
	protected := c.Passkey.Protected.CommandCounters
	if protected == nil {
		return invalid
	}
	protectedCounters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: protected.Policy, Keys: protected.Keys, Store: velocityCounterRouter{state: s}, Clock: time.Now, Timeout: p.RiskTimeout})
	if err != nil {
		return err
	}
	signupEvaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: protected.Policy, Counters: &protectedCounters, Clock: time.Now, Timeout: p.RiskTimeout})
	if err != nil {
		return err
	}
	authority, err := composePasskeySessionAuthority(c, d)
	if err != nil {
		return err
	}
	sessions, err := composeSession(c, d, authority)
	if err != nil {
		return err
	}
	passkeys, err := composePasskey(c, d, nil, evaluation, &counters, authority, nil, signupEvaluation)
	if err != nil {
		return err
	}
	original, err := composePreAuthHTTP(c)
	if err != nil {
		return err
	}
	httpSessions, err := composeSessionHTTP(c, sessions, s.httpRate)
	if err != nil {
		return err
	}
	httpPasskeys, err := composePasskeyHTTP(c, passkeys, sessions, nil, original, s.httpRate, httpSessions, nil, nil)
	if err != nil {
		if httpSessions != nil {
			httpSessions.rate.Close()
		}
		return err
	}
	s.features = &featureState{migrations: migrationConfig, timeout: c.Session.Native.MaximumDuration, authorize: e.Authorization, passkey: passkeys, session: sessions, httpPreAuth: original, httpSession: httpSessions, httpPasskey: httpPasskeys}
	return nil
}
