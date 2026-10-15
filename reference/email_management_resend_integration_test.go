//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestReferencePostgresEmailManagementResend(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true})
}

// The baseline creates the account and authenticated cookie over actual HTTPS.
// This consumer composes only public native constructors and real repositories.
// Fresh logins after identifier-authority changes use the unchanged login route;
// no account/session/proof/clock rows are fabricated or promoted.
func proveReferenceEmailManagementResend(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, d reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, messages <-chan string, origin string, user identity.UserID, cookies []*http.Cookie, csrfWire string, freshLogin func(...string) ([]*http.Cookie, string), selected ...*referenceEmailChangeOptions) {
	t.Helper()
	var change *referenceEmailChangeOptions
	if len(selected) == 1 {
		change = selected[0]
	}
	if c.DurableAdmission == nil || len(cookies) != 1 {
		t.Fatal("real durable consumer graph unavailable")
	}
	var service emailManagementConsumer
	var proofOwner password.CookieVerificationService
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.email.verification-send", Audience: "reference-managed-email"}
	if change != nil {
		target.Action = "identity.email.change-request"
	}
	if c.Email != nil {
		var err error
		if change != nil {
			service, err = features.EmailChange()
		} else {
			service, err = features.EmailVerification()
		}
		if err != nil {
			t.Fatal("selected graph email owner", err)
		}
		if change != nil && c.Email.Change.Keyed != nil || change == nil && c.Email.Verification.Keyed != nil {
			service = keyedEmailConsumer{ManagedEmailService: service.(*reference.ManagedEmailService), t: t}
		}
		if f.emailRequestHTTP != nil {
			service = httpEmailConsumer{emailManagementConsumer: service, invoke: f.emailRequestHTTP}
		}
		proofOwner, err = features.CookiePasswordVerification()
		if err != nil {
			t.Fatal("selected graph original proof owner", err)
		}
		if f.emailRemovalMode == "removal-primary" {
			service, err = features.EmailChange()
			if err != nil {
				t.Fatal(err)
			}
			target.Action = "identity.email.change-request"
		}
	} else {
		history, err := (passwordpg.EmailReauthenticationMigrationSource{}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
			t.Fatal("selected email proof history", err)
		}
		prepared := kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 1012}
		admitted := kernel.AdmissionPreparationMigrationSource{Base: prepared, Version: 1013}
		counterHistory, err := (kernel.CounterPreparationMigrationSource{Base: admitted, Version: 1700}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(ctx, counterHistory[len(counterHistory)-1].UpSQL()); err != nil {
			t.Fatal("selected protected preparation history", err)
		}
		admission := c.DurableAdmission
		store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: f.pool, Schema: admission.Schema, Namespace: admission.Namespace, Policy: admission.Policy, Keys: admission.Keys, ReplayKey: admission.ReplayKey, Tenants: admission.Tenants, MaximumRecords: admission.MaximumRecords, Timeout: admission.Timeout})
		if err != nil {
			t.Fatal(err)
		}
		counted, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: c.DurableAdmission.Policy, Keys: c.DurableAdmission.Keys, Store: store, Clock: time.Now, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		sink, err := auditpg.New(f.pool.Raw(), auditpg.Config{})
		if err != nil {
			t.Fatal(err)
		}
		evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: c.DurableAdmission.Policy, Counters: &counted, Clock: time.Now, Timeout: 2 * time.Second, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: otpTenant, Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }}})
		if err != nil {
			t.Fatal(err)
		}
		p := c.PasswordSignin.Native
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{211}, 32))
		signing, err := passwordpg.NewReauthenticationSigningKey("managed-consumer-proof", private)
		if err != nil {
			t.Fatal(err)
		}
		reauth, err := passwordpg.NewReauthenticationService(f.pool, passwordpg.ReauthenticationConfig{Repository: p.Repository, Verifier: p.Verifier, Session: p.Session, Profile: p.Profile, LookupKeys: []session.DigestKey{p.Issuance.LookupKey}, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "reference-managed-email", Keys: c.OTP.RiskKeys}, Coordinator: p.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"managed-consumer-proof": private.Public().(ed25519.PublicKey)}, Issuer: p.Issuer, Environment: p.Environment, Targets: []passwordpg.ReauthenticationTarget{target}, TTL: 2 * time.Minute, IdentifierKey: bytes.Repeat([]byte{212}, 32)})
		clear(private)
		if err != nil {
			t.Fatal("public native reauthentication", err)
		}
		proofOwner, err = passwordpg.NewCookieVerificationWorkflow(reauth, []session.CSRFKey{p.CSRFKey})
		if err != nil {
			t.Fatal(err)
		}
		primary, err := passwordpg.NewEmailPrimarySource(reauth, passwordpg.EmailPrimaryConfig{Action: target.Action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: []session.CSRFKey{p.CSRFKey}})
		if err != nil {
			t.Fatal(err)
		}
		keys := d.EnvelopeKeys.(*keyring.Provider)
		crypto, err := envelope.NewService(keys)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
		if err != nil {
			t.Fatal(err)
		}
		renderer, err := delivery.NewTemplateRenderer(c.Delivery.Templates)
		if err != nil {
			t.Fatal(err)
		}
		counters, err := riskpg.NewRepository(c.PasswordSignup.Counters)
		if err != nil {
			t.Fatal(err)
		}
		signup := c.PasswordSignup
		native := signup.Native
		// Protected command counters own velocity in the sole transaction. This
		// mandatory external source must never be consulted for a substitute verdict.
		protected, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: signup.Counters.CommandCounters.Policy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "velocity", Version: "native-command-only", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
			return risk.Signal{}, errors.New("protected native velocity cannot be replaced by a provider")
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		verification := email.RegistrationVerificationConfig{Address: p.Address, Issuer: origin, Audience: signup.Issuer.Audience, MaximumLifetime: 5 * time.Minute, Redirects: []string{origin + "/login"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {213}}}
		managementConfig := passwordpg.EmailManagementConfig{PolicyID: "managed-email", ConfigurationID: "reference-managed-email", MaximumDuration: 5 * time.Second, Lifetime: time.Minute, ResendInterval: 30 * time.Second, Verification: verification, Issuer: signup.Issuer, IssuanceCustody: signup.Preparation, Delivery: passwordpg.SignupDeliveryConfig{Owner: owner, Renderer: renderer, Resolver: native.Delivery.Resolver, Endpoint: native.Delivery.Endpoint, TemplateID: native.Delivery.TemplateID, TemplateVersion: native.Delivery.TemplateVersion, ProviderVersion: native.Delivery.ProviderVersion, Locales: native.Delivery.Locales, ScopeKey: native.Delivery.ScopeKey, Timeout: native.Delivery.Timeout}, Domain: kernel.EmailAttachmentDomainConfig{ComparisonProfile: native.RegistrationDomain.ComparisonProfile, CurrentIdentifierKeyVersion: native.RegistrationDomain.CurrentIdentifierKeyVersion, RetainedIdentifierKeys: native.RegistrationDomain.RetainedIdentifierKeys}, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: protected, ConfigurationID: "reference-managed-email", Keys: c.OTP.RiskKeys}, CounterPolicy: c.PasswordSignup.Counters.CommandCounters.Policy, Counters: counters, ActiveEnvelopeKeyID: native.ActiveEnvelopeKeyID}
		if change != nil {
			configureReferenceEmailChange(t, ctx, f, &managementConfig)
		}
		service, err = passwordpg.NewEmailManagementService(primary, managementConfig, keys)
		if err != nil {
			t.Fatal("public email composition", err)
		}
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: authorization.Action(target.Action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	request := func(cookies []*http.Cookie, csrfWire string) passwordpg.EmailManagementRequest {
		t.Helper()
		secret, err := primitive.NewSecret([]byte("synthetic-registration-password"))
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Destroy()
		csrf, err := session.ParseCSRFToken(csrfWire)
		if err != nil {
			t.Fatal(err)
		}
		proofCaller := caller.Clone()
		proofCaller.Request.Action = "identity.password.verify"
		proofCaller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}
		bearer := auth.NewBearerCredential(cookies[0].Value)
		proof, err := proofOwner.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: bearer, Password: secret, Target: password.VerificationTarget{Purpose: target.Purpose, Action: target.Action, Audience: target.Audience}, Caller: proofCaller, Network: "127.0.0.1", Device: "managed-consumer"}, CSRFToken: csrf})
		if err != nil {
			t.Fatal("fresh cookie-bound password proof", err)
		}
		id, _ := identity.NewCommandID()
		return passwordpg.EmailManagementRequest{Primary: passwordpg.EmailPrimaryRequest{TenantID: otpTenant, CommandID: id, AddressID: "managed-candidate", Session: bearer, CSRFToken: csrf, Proof: proof.Proof, Caller: caller}, CallbackURL: origin + "/login", Network: "127.0.0.1"}
	}
	if change != nil {
		proveReferenceEmailChangeJourney(t, ctx, f, service, workers, messages, *change, origin, user, cookies, csrfWire, freshLogin, request)
		return
	}
	var originalVersion, originalVerification uint64
	var originalPrimary, originalVerified bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT version,verification_version,is_primary,verified FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND canonical_value='registered@example.invalid'`, otpTenant, string(user)).Scan(&originalVersion, &originalVerification, &originalPrimary, &originalVerified); err != nil || !originalVerified {
		t.Fatal("original verified signin address unavailable", err)
	}
	initial := request(cookies, csrfWire)
	initial.Address = "additional@example.invalid"
	call := service.VerificationSend
	if f.emailRemovalMode == "removal-primary" {
		initial.Address = "primary@example.invalid"
		call = service.ChangeRequest
	}
	result, err := call(ctx, initial)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine account pending add", result.Outcome, err)
	}
	initial.Primary.CommandID, initial.Primary.AddressID = result.CommandID, result.AddressID
	capture := func() capability.Proof {
		t.Helper()
		if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
			t.Fatal(err)
		}
		select {
		case body := <-messages:
			link, err := url.Parse(body)
			if err != nil {
				t.Fatal("captured managed link parse")
			}
			proof, err := capability.ParseProof(link.Query().Get("token"), capability.DefaultLimits())
			if err != nil {
				t.Fatal("captured managed proof parse")
			}
			return proof
		case <-ctx.Done():
			t.Fatal("no captured managed link")
			return capability.Proof{}
		}
	}
	old := capture()
	if f.afterEmailRemovalPreparation != nil {
		if f.emailRemovalMode == "removal-primary" {
			id, _ := identity.NewCommandID()
			callback, _ := url.Parse(initial.CallbackURL)
			caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
			out, err := service.ChangeConfirm(ctx, email.ChangeConfirmRequest{TenantID: otpTenant, CommandID: id, Token: old, Callback: *callback, Caller: caller, Network: "127.0.0.1"})
			if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("actual primary designation", err)
			}
			if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
				t.Fatal("old-address notice delivery", err)
			}
			select {
			case <-messages:
			case <-ctx.Done():
				t.Fatal("old-address notice missing")
			}
		} else if f.emailRemovalMode != "removal-pending" {
			id, _ := identity.NewCommandID()
			callback, _ := url.Parse(initial.CallbackURL)
			caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
			confirmed, err := service.VerificationConfirm(ctx, email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: old, Callback: *callback, Caller: caller, Network: "127.0.0.1"})
			if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("actual surviving-address verification", err)
			}
		}
		cookies, csrfWire = freshLogin()
		target.Action = "identity.email.address-remove"
		caller.Request.Action = "identity.email.address-remove"
		f.afterEmailRemovalPreparation(old, initial.Primary.AddressID, request(cookies, csrfWire), cookies, csrfWire)
		return
	}
	cookies, csrfWire = freshLogin()
	resend := request(cookies, csrfWire)
	resend.Primary.AddressID = initial.Primary.AddressID
	if out, err := service.VerificationResend(ctx, resend); err == nil || out.AddressID != "" {
		t.Fatal("mailbox cooldown bypassed by fresh login/proof/command")
	}
	confirmCaller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	if valid, err := service.ValidateManagedVerification(ctx, old, initial.CallbackURL, confirmCaller); err != nil || !valid {
		t.Fatal("denied resend invalidated predecessor", err)
	}
	// Actual database time advances; no signed timestamps or authority are aged.
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("bounded cooldown wait", ctx.Err())
	}
	resend = request(cookies, csrfWire)
	resend.Primary.AddressID = initial.Primary.AddressID
	var failed passwordpg.EmailManagementResult
	if f.emailRequestHTTP == nil {
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION managed_resend_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic managed resend rollback'; END $$; CREATE TRIGGER managed_resend_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION managed_resend_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		failed, err = service.VerificationResend(ctx, resend)
		if err == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.AddressID != "" {
			t.Fatal("late resend failure fabricated success", failed.Outcome, err)
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER managed_resend_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION managed_resend_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		if valid, err := service.ValidateManagedVerification(ctx, old, initial.CallbackURL, confirmCaller); err != nil || !valid {
			t.Fatal("late replacement failure invalidated original link", err)
		}
	}
	// The failed protected transaction did not consume its original primary
	// proof. A distinct command may use it while its original freshness holds.
	resend.Primary.CommandID, _ = identity.NewCommandID()
	result, err = service.VerificationResend(ctx, resend)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.IdentifierVersion != 2 || result.VerificationVersion != 2 {
		t.Fatal("authorized pending resend", result.Outcome, err)
	}
	resend.Primary.CommandID = result.CommandID
	q := identity.RecoveryQuery{CommandID: resend.Primary.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.email.verification-send", RecordID: string(resend.Primary.AddressID)}
	recovered, err := service.VerificationSendRecover(ctx, q, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.AddressID != resend.Primary.AddressID || recovered.IdentifierVersion != 2 || recovered.VerificationVersion != 2 {
		t.Fatal("proof-free resend recovery lost acknowledged successor", err)
	}
	foreign := q
	foreign.TenantID = "foreign"
	if out, err := service.VerificationSendRecover(ctx, foreign, caller); err == nil || out.AddressID != "" {
		t.Fatal("foreign recovery disclosed managed history")
	}
	next := capture()
	if valid, err := service.ValidateManagedVerification(ctx, old, initial.CallbackURL, confirmCaller); err == nil || valid {
		t.Fatal("superseded predecessor remained valid")
	}
	oldCommand, _ := identity.NewCommandID()
	oldCallback, _ := url.Parse(initial.CallbackURL)
	confirmCaller.CorrelationID = "reference-managed-confirmation"
	if out, err := service.VerificationConfirm(ctx, email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: oldCommand, Token: old, Callback: *oldCallback, Caller: confirmCaller, Network: "127.0.0.1"}); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("superseded predecessor explicitly confirmed")
	}
	for range 2 {
		if valid, err := service.ValidateManagedVerification(ctx, next, resend.CallbackURL, confirmCaller); err != nil || !valid {
			t.Fatal("successor scanner inspection", err)
		}
	}
	command, _ := identity.NewCommandID()
	confirmCaller.CorrelationID = "reference-managed-confirmation"
	callback, _ := url.Parse(resend.CallbackURL)
	confirmation := email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: command, Token: next, Callback: *callback, Caller: confirmCaller, Network: "127.0.0.1"}
	if f.afterManagedConfirmation != nil {
		f.afterManagedConfirmation(confirmation, resend.Primary.AddressID)
	} else {
		confirmed, err := service.VerificationConfirm(ctx, confirmation)
		if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine successor confirmation", confirmed.Outcome, err)
		}
		projection, err := confirmed.Address.Bindings()
		if err != nil || !projection.Verified || projection.IdentifierVersion != 3 || projection.VerificationVersion != 3 {
			t.Fatal("successor confirmation discarded original versions")
		}
	}
	var unchangedPrimary, grants, proofUses, failedGrants int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND canonical_value='registered@example.invalid' AND version=$3 AND verification_version=$4 AND is_primary=$5 AND verified=$6`, otpTenant, string(user), originalVersion, originalVerification, originalPrimary, originalVerified).Scan(&unchangedPrimary); err != nil || unchangedPrimary != 1 {
		t.Fatal("resend changed original verified signin address", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*),COALESCE(sum(uses),0) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id IN ($2,$3)`, otpTenant, string(initial.Primary.CommandID), string(resend.Primary.CommandID)).Scan(&grants, &proofUses); err != nil || grants != 2 || proofUses != 1 {
		t.Fatal("resend/inspection/confirmation repeated issuance or use", err)
	}
	if failed.CommandID != "" {
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$2`, otpTenant, string(failed.CommandID)).Scan(&failedGrants); err != nil || failedGrants != 0 {
			t.Fatal("rolled-back replacement grant survived", err)
		}
	}
}
