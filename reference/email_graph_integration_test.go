//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

// Both ports below are actual native owners; this consumer interface supplies
// no stores, policy or workflow. It lets the same acceptance journey compare
// standalone composition with the graph-lifetime-bound public handle.
type emailManagementConsumer interface {
	VerificationSend(context.Context, passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error)
	VerificationResend(context.Context, passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error)
	ChangeRequest(context.Context, passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error)
	VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
	ChangeConfirm(context.Context, email.ChangeConfirmRequest) (email.ChangeConfirmResult, error)
	VerificationSendRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (passwordpg.EmailManagementResult, error)
	ChangeRequestRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (passwordpg.EmailManagementResult, error)
	VerificationRecover(context.Context, email.VerificationRecoveryRequest) (email.VerificationRecoveryResult, error)
	ChangeRecover(context.Context, email.ChangeRecoveryRequest) (email.ChangeRecoveryResult, error)
	ReadManagedVerification(context.Context, capability.Proof, authorization.DecisionContext) (email.ManagedVerificationSpec, uint32, error)
	ValidateManagedVerification(context.Context, capability.Proof, string, authorization.DecisionContext) (bool, error)
	ChangeConfirmationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
}

var _ emailManagementConsumer = (*passwordpg.EmailManagementService)(nil)
var _ emailManagementConsumer = (*reference.ManagedEmailService)(nil)

func TestReferencePostgresEmailManagementGraph(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailAddressQueries: true, emailChangeCase: "graph"})
}

func TestReferencePostgresEmailChangeGraph(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailAddressQueries: true, emailChangeCase: "graph"})
}

func TestReferencePostgresEmailKeyedChangeGraph(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailAddressQueries: true, emailChangeCase: "keyed-graph"})
}

func TestReferencePostgresEmailKeyedResendGraph(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailChangeCase: "keyed-graph"})
}

// Only adapts the invocation's test retry key; all behavior belongs to the
// graph's actual native keyed handle. Every successful call also proves replay.
type keyedEmailConsumer struct {
	*reference.ManagedEmailService
	t *testing.T
}

func (s keyedEmailConsumer) request(ctx context.Context, r passwordpg.EmailManagementRequest, mode string) (passwordpg.EmailManagementResult, error) {
	s.t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(r.Primary.CommandID))
	if err != nil {
		s.t.Fatal(err)
	}
	r.Primary.CommandID = ""
	if mode != "resend" {
		r.Primary.AddressID = ""
	}
	call := s.ManagedEmailService.VerificationSendKeyed
	if mode == "resend" {
		call = s.ManagedEmailService.VerificationResendKeyed
	}
	if mode == "change" {
		call = s.ManagedEmailService.ChangeRequestKeyed
	}
	user, address, err := s.ManagedEmailService.RequestRateSourceKeyed(ctx, r, key, mode == "resend")
	if err != nil || string(user) != string(r.Primary.Caller.Request.Subject.ID) || address == "" {
		s.t.Fatal("graph has no original keyed request rate source", err)
	}
	result, err := call(ctx, r, key)
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		replay, e := call(ctx, r, key)
		if e != nil || replay != result {
			s.t.Fatal("graph lost original keyed result", replay.Outcome, e)
		}
		u, a, e := s.ManagedEmailService.RequestRateSourceKeyed(ctx, r, key, mode == "resend")
		if e != nil || u != user || a != address {
			s.t.Fatal("graph rate source lost historical retry custody", e)
		}
	}
	return result, err
}
func (s keyedEmailConsumer) VerificationSend(ctx context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	return s.request(ctx, r, "add")
}
func (s keyedEmailConsumer) VerificationResend(ctx context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	return s.request(ctx, r, "resend")
}
func (s keyedEmailConsumer) ChangeRequest(ctx context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	return s.request(ctx, r, "change")
}

func TestReferencePostgresEmailChangeGraphUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: "graph-upgrade"})
}

// The existing HTTPS baseline remains a real credential issuer. A reconstructed
// graph opts into email only after that baseline has populated the primary; no
// helper writes selected DDL or invents an identity or password-proof owner.
func upgradeReferenceEmailGraph(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, d reference.ReferenceDependencies, worker deliverypg.WorkerConfig, modules []reference.ModuleID, user identity.UserID, original reference.ReferenceMigrationApplyRequest) reference.FeatureSet {
	t.Helper()
	stores, err := reference.ComposeStores(c, d)
	if err != nil {
		t.Fatal("selected email upgrade composition", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error("selected email upgrade cleanup", err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	// Capture version/usage metadata only, never credential bytes or hashes.
	snapshot := func() [5]int64 {
		t.Helper()
		var s [5]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT u.version,
(SELECT sum(version) FROM identity.identifiers WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT sum(verification_version) FROM identity.identifiers WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT count(*) FROM session_store.sessions WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT coalesce(sum(uses),0) FROM capability_identity_one_use)
FROM identity.users u WHERE u.tenant_id=$1 AND u.user_id=$2`, otpTenant, string(user)).Scan(&s[0], &s[1], &s[2], &s[3], &s[4]); err != nil {
			t.Fatal("populated email upgrade metadata", err)
		}
		return s
	}
	before := snapshot()
	originalCustody := func() string {
		t.Helper()
		var record string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT ROW(command_id,request_digest,idempotency_digest,job,receipts,completed)::text FROM public.golib_migration_commands WHERE command_id=$1`, string(original.CommandID)).Scan(&record); err != nil {
			t.Fatal("original baseline operator custody unavailable", err)
		}
		return record // Compared only; original bindings never enter diagnostics.
	}
	originalRecord := originalCustody()
	request := applyRequest(t, ctx, stores, modules)
	request.CommandID = "migration_email_upgrade_0001"
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("apply-email-upgrade-original-key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Plan.Steps) == 0 {
		t.Fatal("selected email history was already installed by baseline")
	}
	for range 2 {
		out, err := stores.ReferenceMigrationApply(ctx, request)
		if err != nil || out.Result.State() != reference.MigrationApplied || snapshot() != before {
			t.Fatal("populated email upgrade/retry changed original authority", err)
		}
	}
	// The complete source/catalog changed: its forward upgrade has a distinct
	// operator command. Never rewrite/adopt the original request to match it.
	if originalCustody() != originalRecord {
		t.Fatal("email upgrade rewrote original baseline operator custody")
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("upgraded email initialization", err)
	}
	return features
}

// Configuration only: no test-owned native stores, services or DDL. The graph
// constructs the real proof/management owners and operator-applies their native
// histories before genuine registration, verification and signin.
func configureReferenceEmailGraph(t *testing.T, c *reference.StoreConfiguration, origin string, change bool) *atomic.Int32 {
	t.Helper()
	p, signup := c.PasswordSignin.Native, c.PasswordSignup
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{211}, 32))
	signing, err := passwordpg.NewReauthenticationSigningKey("managed-consumer-proof", private)
	if err != nil {
		t.Fatal(err)
	}
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.email.verification-send", Audience: "reference-managed-email"}
	if change {
		target.Action = "identity.email.change-request"
	}
	verifier := p.Verifier
	verifier.Now = nil
	c.PasswordVerification = &reference.PasswordVerificationConfiguration{Native: passwordpg.ReauthenticationConfig{Repository: p.Repository, Verifier: verifier, Session: p.Session, Profile: p.Profile, LookupKeys: []session.DigestKey{p.Issuance.LookupKey}, Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-managed-email", Keys: c.OTP.RiskKeys}, Coordinator: p.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"managed-consumer-proof": private.Public().(ed25519.PublicKey)}, Issuer: p.Issuer, Environment: p.Environment, Targets: []passwordpg.ReauthenticationTarget{target}, TTL: 2 * time.Minute, IdentifierKey: bytes.Repeat([]byte{212}, 32)}, CSRFKeys: []session.CSRFKey{p.CSRFKey}}
	clear(private)
	native := signup.Native
	verification := email.RegistrationVerificationConfig{Address: p.Address, Issuer: origin, Audience: signup.Issuer.Audience, MaximumLifetime: 5 * time.Minute, Redirects: []string{origin + "/login"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {213}}}
	n := passwordpg.EmailManagementConfig{PolicyID: "managed-email", ConfigurationID: "reference-managed-email", MaximumDuration: c.OTP.Timeout, Lifetime: time.Minute, ResendInterval: 30 * time.Second, Verification: verification, Issuer: signup.Issuer, IssuanceCustody: signup.Preparation, Delivery: passwordpg.SignupDeliveryConfig{Resolver: native.Delivery.Resolver, Endpoint: native.Delivery.Endpoint, TemplateID: native.Delivery.TemplateID, TemplateVersion: native.Delivery.TemplateVersion, ProviderVersion: native.Delivery.ProviderVersion, Locales: native.Delivery.Locales, ScopeKey: native.Delivery.ScopeKey, Timeout: native.Delivery.Timeout}, Domain: kernel.EmailAttachmentDomainConfig{ComparisonProfile: native.RegistrationDomain.ComparisonProfile, CurrentIdentifierKeyVersion: native.RegistrationDomain.CurrentIdentifierKeyVersion, RetainedIdentifierKeys: native.RegistrationDomain.RetainedIdentifierKeys}, Risk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-managed-email"}, ActiveEnvelopeKeyID: native.ActiveEnvelopeKeyID}
	if change {
		n.Lifetime = 5 * time.Minute
		n.Change = &email.ChangeProfile{CurrentAddress: email.PrimaryOrSoleVerifiedAddress, Sessions: email.InvalidateIdentifierSessions}
		n.ChangeNotification = &passwordpg.EmailChangeNotificationConfig{TemplateID: "email-change-notice", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{214}, Timeout: time.Second}
		c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "email-change-notice", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: emailChangeNotice, ContentType: "text/plain", MaxRenderedBytes: 4096})
	}
	// Provider custody and the protected counter owner must share the same
	// immutable policy, including its revision, not separately built lookalikes.
	c.DurableAdmission.Policy = signup.Counters.CommandCounters.Policy
	// Authentication screening must retain that same risk revision too; the
	// authorization revision is a separate contract, not a risk-policy alias.
	c.PasswordSignup.Native.Screening.Policy = registrationRiskPolicy(t, 9, true)
	collect, calls := registrationScreening(t, c.PasswordSignup.Native.Screening.Policy)
	c.PasswordSignup.Native.Screening.Collect = collect
	selected := &reference.EmailManagementConfiguration{Native: n, Primary: passwordpg.EmailPrimaryConfig{Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie}, Counters: signup.Counters}
	c.Email = &reference.EmailConfiguration{Addresses: referenceEmailQueryConfiguration()}
	if change {
		c.Email.Change = selected
	} else {
		c.Email.Verification = selected
	}
	return calls
}
