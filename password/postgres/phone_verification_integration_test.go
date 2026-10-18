//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type phoneRecoveryDisclosurePolicy struct {
	base  authorization.Service
	armed atomic.Bool
	calls atomic.Uint32
}

func (p *phoneRecoveryDisclosurePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if p.armed.Load() && c.Request.Action == "identity.phone.verify.recover" && p.calls.Add(1) == 2 {
		return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, ctx.Err()
	}
	return p.base.Decide(ctx, c)
}

// Every identity, password proof, session, OTP, counter, audit and delivery row
// comes from a public native owner. Only external provider/status observations
// and the external email/SMS sender are controlled seams. This is native consumer
// proof, not HTTP/reference or carrier delivery certification.
func TestNativePhoneEnrollmentIntegration(t *testing.T) {
	for _, transport := range []session.CredentialKind{session.CredentialBearer, session.CredentialCookie} {
		name := "bearer"
		if transport == session.CredentialCookie {
			name = "cookie"
		}
		t.Run(name, func(t *testing.T) {
			for _, outcome := range []string{"normal", "before-commit", "lost-commit", "late-send-factor", "late-verify-factor"} {
				t.Run(outcome, func(t *testing.T) {
					testNativeSigninPhaseIntegration(t, "phone enrollment", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
						testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, transport, outcome)
					})
				})
			}
		})
	}
}

func phoneNativeAuthenticationRisk(t *testing.T, ctx context.Context, pool *database.Pool, beforeStatus func(context.Context, risk.Context) error) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	history, err := (riskpg.DurableCounterMigrationSource{Schema: "phone_admission", Version: 1}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("phone counted admission history", err)
		}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3,
		Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour},
		Profiles: []risk.Profile{
			{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	dimensionKey, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{121}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: pool, Schema: "phone_admission", Namespace: "phone-native", Policy: policy, Keys: []risk.CounterDigestKey{dimensionKey}, ReplayKey: bytes.Repeat([]byte{122}, 32), Tenants: []string{signinTestTenant}, MaximumRecords: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{dimensionKey}, Store: store, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second,
		Sources: []risk.Source{{Name: "status", Version: "phone-test-policy-v1", Timeout: time.Second, Read: func(ctx context.Context, c risk.Context) (risk.Signal, error) {
			if beforeStatus != nil {
				if err := beforeStatus(ctx, c); err != nil {
					return risk.Signal{}, err
				}
			}
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, ctx.Err()
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
			_, err := sink.Append(ctx, lost.Record())
			return err
		}}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{123}, 32), bytes.Repeat([]byte{124}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "phone-native-risk-v1", Keys: []risk.EvidenceKey{key}}
}

func testNativePhoneEnrollment(t *testing.T, ctx context.Context, pool *database.Pool, _ *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest, transport session.CredentialKind, outcome string) {
	t.Helper()
	var beforeStatus func(context.Context, risk.Context) error
	counted := phoneNativeAuthenticationRisk(t, ctx, pool, func(ctx context.Context, c risk.Context) error {
		if beforeStatus != nil {
			return beforeStatus(ctx, c)
		}
		return nil
	})
	c.Risk, c.ConfigurationID = counted, "phone-consumer-signup-v1"
	c.AuthorizationNamespace = "users"
	signup, err := NewSignupService(pool, c, keys)
	if err != nil {
		t.Fatal(err)
	}
	registration := fresh("phone-owner@example.test", 'P')
	registered, err := signup.Signup(ctx, registration)
	if err != nil || registered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("phone consumer genuine registration", err)
	}
	query, _, err := registered.Recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	testPublicSignupVerificationOrigin(t, ctx, signup, c, registration, query.CommandID, keys)
	var policyAuthorities int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM authorization_subject_authorities a JOIN identity.identifiers i ON i.tenant_id=a.tenant_id AND i.user_id=a.subject_id WHERE a.tenant_id=$1 AND a.policy_namespace='users' AND i.kind='email' AND i.canonical_value=$2`, string(registration.TenantID), string(registration.Email)).Scan(&policyAuthorities); err != nil || policyAuthorities != 1 {
		t.Fatal("genuine registration did not initialize the selected signin policy authority", policyAuthorities, err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "signin-deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	_, signinConfig := publicSigninFixture(t, pool, c.Repository.HashPolicy, c.Screening.Primitive, c.Screening.DummyHash, c.Session, profile)
	signinConfig.Risk = counted
	signinConfig.Coordinator.LeaseDuration = 500 * time.Millisecond
	disclosurePolicy := &phoneRecoveryDisclosurePolicy{base: signinConfig.Coordinator.QueryPolicy.Authorization}
	queryPolicy := *signinConfig.Coordinator.QueryPolicy
	queryPolicy.Authorization = disclosurePolicy
	signinConfig.Coordinator.QueryPolicy = &queryPolicy
	signin, err := NewSigninService(pool, signinConfig)
	if err != nil {
		t.Fatal(err)
	}
	request, _, _, _ := nativeSigninFlow(t)
	request.TenantID, request.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
	request.Identifier, request.Password, request.Device = "phone-owner@example.test", registration.Password, "phone-browser"
	request.PreAuthID, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	browser := session.PreAuthBinding{ID: request.PreAuthID, Intent: session.PreAuthIntent{TenantID: request.TenantID, Action: "identity.password.signin", Origin: request.Origin, CallbackURL: request.CallbackURL, Nonce: [32]byte{126}, Remember: request.Remember, PolicyID: signinConfig.PolicyID, PolicyVersion: 3}, IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}
	browserToken, err := session.ParseToken(request.Cookie.Token())
	if err != nil {
		t.Fatal(err)
	}
	browserDigest, err := browserToken.PreAuthDigest(signinConfig.FlowKeys[0], browser)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: browser, Cookie: browserDigest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, c.Session, flow) != nil {
		t.Fatal("phone original browser", err)
	}
	authenticated, err := signin.Signin(ctx, request)
	if err != nil || authenticated.State != auth.SignInStateAuthenticated {
		t.Fatal("phone genuine password signin", err)
	}
	bearerWire, err := authenticated.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	original, err := authenticated.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: phonePrimaryAction, Audience: "phone-enrollment"}
	signing, err := NewReauthenticationSigningKey("phone-reauth", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	keyID, public := signing.public()
	reauthConfig := ReauthenticationConfig{Repository: signinConfig.Repository, Verifier: signinConfig.Verifier, Session: c.Session, Profile: profile, LookupKeys: []session.DigestKey{signinConfig.Issuance.LookupKey}, Risk: counted, Coordinator: signinConfig.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{keyID: public}, Issuer: signinConfig.Issuer, Environment: signinConfig.Environment, Targets: []ReauthenticationTarget{target}, TTL: time.Minute, IdentifierKey: bytes.Repeat([]byte{128}, 32)}
	proofOwner, err := NewReauthenticationService(pool, reauthConfig)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: authorization.TenantID(original.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(original.UserID)}, Action: authorization.Action(phonePrimaryAction), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(original.UserID)}}}
	proof, err := proofOwner.Verify(ctx, ReauthenticationRequest{TenantID: original.TenantID, Session: auth.NewBearerCredential(bearerWire), Password: registration.Password, Target: target, Caller: caller, Network: "192.0.2.10", Device: "phone-browser"})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("phone genuine action proof", err)
	}
	primaryConfig := ActionPrimaryConfig{Action: phonePrimaryAction, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: transport}
	csrf := session.CSRFToken{}
	if transport == session.CredentialCookie {
		primaryConfig.CSRFKeys, csrf = []session.CSRFKey{signinConfig.CSRFKey}, authenticated.CSRFToken
	}
	primary, err := NewActionPrimarySource(proofOwner, primaryConfig)
	if err != nil {
		t.Fatal(err)
	}
	var retainedProof []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(proof.Proof.Proof.ID)).Scan(&retainedProof); err != nil {
		t.Fatal("original proof before populated phone migration", err)
	}
	defer clear(retainedProof)
	for _, source := range []migrations.Source{
		kernel.IdentifierNormalizationMigrationSource{Base: kernel.MigrationSource{}, Version: 50},
		ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70},
		PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
			t.Fatal("phone selected forward history", err)
		}
	}
	var migratedProof []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(proof.Proof.Proof.ID)).Scan(&migratedProof); err != nil || !bytes.Equal(retainedProof, migratedProof) {
		clear(migratedProof)
		t.Fatal("phone migration rewrote retained signed provenance", err)
	}
	clear(migratedProof)
	for _, source := range []migrations.Source{
		otppg.MigrationSource{Schema: "phone_codes", Version: 100}, otppg.LockoutMigrationSource{Schema: "phone_codes", Version: 101},
		otppg.ConsumingMigrationSource{Schema: "phone_codes", Version: 102}, otppg.SendFamilyMigrationSource{Schema: "phone_codes", Version: 103},
		otppg.IssuanceMigrationSource{Schema: "phone_codes", Version: 104}, otppg.PhonePurposeMigrationSource{Schema: "phone_codes", Version: 105},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("phone OTP history", err)
			}
		}
	}
	codec, err := otppg.NewAttemptCodec(otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"phone-wrap": bytes.Repeat([]byte{129}, 32)}, CurrentWrappingKey: "phone-wrap", AttemptKeys: map[uint32][32]byte{1: {130}}, CodeKeys: map[uint32][32]byte{1: {131}}, CurrentCodeKeyVersion: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	templates := []delivery.Template{{ID: "phone-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Code: {{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 4096}}
	deliveryCustody := deliverypg.ContributorConfig{Deployment: "phone-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {132}}, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "sms", PolicyVersion: 1}}}
	deliveryOwner, err := deliverypg.NewContributor(deliveryCustody, signup.crypto)
	if err != nil {
		t.Fatal(err)
	}
	codeProfile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePhoneVerification, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	codePolicy, err := otp.NewAttemptPolicy(codeProfile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := otppg.NewPhoneEnrollmentIssuer(otppg.PhoneEnrollmentIssuerConfig{Store: otppg.ContributorConfig{Schema: "phone_codes", GlobalAuthorityID: profile.GlobalAuthorityID, UserPolicyNamespace: profile.PolicyNamespace, Codec: codec, LockoutKey: [32]byte{133}}, Session: otppg.SessionAdmissionConfig{Store: c.Session, Profile: profile, RetainedTokenKeys: map[uint32][]byte{1: bytes.Repeat([]byte{82}, 32)}, FreshnessLimit: 10 * time.Minute}, Delivery: deliveryOwner, Policy: codePolicy, TemplateID: "phone-code", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, Templates: templates})
	if err != nil || issuer.Initialize(ctx, pool) != nil {
		t.Fatal("actual phone issuer startup", err)
	}
	numberPolicy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("phone-native", [32]byte{134}, *signinConfig.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	configuration := PhoneVerificationConfig{PolicyID: "phone-native", ConfigurationID: "phone-native-v1", MaximumDuration: 5 * time.Second, Domain: kernel.PhoneEnrollmentDomainConfig{NormalizationProfile: numberPolicy.Profile().ID, NormalizationVersion: numberPolicy.Profile().Version, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {135}}, ReuseCooldown: 30 * 24 * time.Hour}, RequestKeys: requestKeys, IntentKey: [32]byte{136}, IdentifierKey: [32]byte{137}, Risk: counted, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, Issuer: issuer, CurrentAttemptKeyVersion: 1}
	service, err := NewPhoneVerificationService(primary, numberPolicy, configuration, keys)
	if err != nil {
		t.Fatal("native phone composition", err)
	}
	if err := service.Initialize(ctx); err != nil {
		t.Fatal("native phone retained key initialization", err)
	}
	number, err := numberPolicy.Canonicalize(ctx, "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := identity.NewIdempotencyKey([]byte("phone-native-original-enrollment"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := phone.NewEnrollmentRequest(phone.EnrollmentRequestSpec{TenantID: original.TenantID, UserID: original.UserID, Number: number, Session: auth.NewBearerCredential(bearerWire), Proof: proof.Proof, Caller: caller, CSRFToken: csrf, IdempotencyKey: idempotency, Network: "192.0.2.10", Device: "phone-browser"})
	if err != nil {
		t.Fatal(err)
	}
	if transport == session.CredentialCookie {
		bad, err := enrollment.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		bad.CSRFToken, err = session.NewCSRFToken()
		if err != nil {
			t.Fatal(err)
		}
		wrongRequest, err := phone.NewEnrollmentRequest(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.SendVerification(ctx, wrongRequest); err == nil {
			t.Fatal("foreign synchronizer issued an SMS challenge")
		}
		var effects int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM phone_codes.challenges)+(SELECT count(*) FROM identity.identifiers WHERE kind='phone')`).Scan(&effects); err != nil || effects != 0 {
			t.Fatal("denied enrollment left a pending phone or challenge", err)
		}
	}
	withdrawFactor := func(ctx context.Context, c risk.Context) error {
		if c.Operation != "identity.phone.send-verification" && c.Operation != "identity.phone.verify" {
			return nil
		}
		// Withdraw real current authority after preliminary admission, while the
		// native risk source is outside the protected transaction. This changes
		// no proof, session, factor enrollment or OTP challenge fixture.
		tag, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(original.TenantID), string(original.UserID))
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("phone test could not withdraw its existing factor authority")
		}
		return err
	}
	if outcome == "late-send-factor" {
		beforeStatus = withdrawFactor
	}
	for range 2 {
		destination, err := service.PhoneEnrollmentDestination(ctx, enrollment)
		if err != nil || !destination.Equal(number) {
			t.Fatal("native rate source did not authenticate original enrollment destination", err)
		}
	}
	var rateCommands, ratePhones, rateCodes int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE purpose=$1),(SELECT count(*) FROM identity.identifiers WHERE kind='phone'),(SELECT count(*) FROM phone_codes.challenges)`, phonePrimaryAction).Scan(&rateCommands, &ratePhones, &rateCodes); err != nil || rateCommands != 0 || ratePhones != 0 || rateCodes != 0 {
		t.Fatal("preliminary rate-source read allocated enrollment, phone or challenge", err)
	}
	sent, err := service.SendVerification(ctx, enrollment)
	if outcome == "late-send-factor" {
		if err == nil {
			t.Fatal("late factor withdrawal admitted phone enrollment")
		}
		var phones, codes, consumed int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE kind='phone'),(SELECT count(*) FROM phone_codes.challenges),(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND consumed_command_id IS NOT NULL)`, string(proof.Proof.Proof.ID)).Scan(&phones, &codes, &consumed); err != nil || phones != 0 || codes != 0 || consumed != 0 {
			t.Fatal("late enrollment denial retained a phone, challenge or consumed proof", err)
		}
		return
	}
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Logf("phone validation failed at owned field: %s", invalid.Field)
		}
		if binding, bindingErr := sent.Bindings(); bindingErr == nil {
			t.Logf("phone send returned a bound outcome: %v; replayed=%t", binding.Outcome, binding.Replayed)
		}
		var retained, started, generated, planned int
		diagnosticErr := pool.Raw().QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE preparation_started_generation IS NOT NULL), count(*) FILTER (WHERE preparation_ciphertext IS NOT NULL), count(*) FILTER (WHERE command_plan IS NOT NULL) FROM identity.commands WHERE purpose=$1`, phonePrimaryAction).Scan(&retained, &started, &generated, &planned)
		t.Logf("phone send custody counts retained=%d started=%d generated=%d planned=%d; query error=%v", retained, started, generated, planned, diagnosticErr)
		t.Fatal("actual phone send", err)
	}
	send, err := sent.Bindings()
	if err != nil || send.Outcome != identity.CommitOutcomeCommitted || send.IdentifierID == "" || send.Replayed {
		t.Fatal("phone send did not commit one pending candidate", err)
	}
	replayed, err := service.SendVerification(ctx, enrollment)
	if err != nil {
		t.Fatal("phone original send retry", err)
	}
	replay, err := replayed.Bindings()
	if err != nil || !replay.Replayed || replay.Binding != send.Binding || replay.IdentifierID != send.IdentifierID {
		t.Fatal("phone retry replaced original send", err)
	}
	if destination, err := service.PhoneEnrollmentDestination(ctx, enrollment); err != nil || !destination.Equal(number) {
		t.Fatal("spent-proof retry lost original rate destination", err)
	}
	changed, err := enrollment.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	changed.Number, err = numberPolicy.Canonicalize(ctx, "+12025550124")
	if err != nil {
		t.Fatal(err)
	}
	conflicting, err := phone.NewEnrollmentRequest(changed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SendVerification(ctx, conflicting)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatal("same enrollment key did not conflict on a changed phone number")
	}
	if destination, err := service.PhoneEnrollmentDestination(ctx, conflicting); !errors.As(err, &conflict) {
		t.Fatal("rate lookup adopted changed same-key input")
	} else if _, e := destination.Record(); e == nil {
		t.Fatal("conflicting rate lookup returned destination custody")
	}
	var pendingVerified, pendingPrimary bool
	var pendingVersion, pendingVerificationVersion uint64
	if err := pool.Raw().QueryRow(ctx, `SELECT verified,is_primary,version,verification_version FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2`, string(original.TenantID), string(send.IdentifierID)).Scan(&pendingVerified, &pendingPrimary, &pendingVersion, &pendingVerificationVersion); err != nil || pendingVerified || pendingPrimary || pendingVersion != 1 || pendingVerificationVersion != 1 {
		t.Fatal("sending an SMS prematurely established phone ownership", err)
	}
	// The actual encrypted worker, not private challenge SQL, supplies the code.
	workerPolicy := delivery.DefaultConfig()
	workerPolicy.Production, workerPolicy.DedupeTTL = true, 25*time.Hour
	authorize, err := authorization.NewDecisionService(signupVerificationWorkerPolicy{3})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: deliveryCustody, Coordinator: c.Coordinator, PolicyID: "phone-worker", PolicyVersion: 3, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{138}, Policies: map[uint64]delivery.Config{1: workerPolicy}, StateTracking: true}, signup.crypto, authorize, templates)
	if err != nil {
		t.Fatal("native SMS queue composition", err)
	}
	var code string
	calls := 0
	worker, err := queue.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 3, CorrelationID: "phone-worker", Request: authorization.Request{Tenant: authorization.TenantID(original.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "phone-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "phone-worker"}}}, ProviderConfigVersion: 2}, signupVerificationSender(func(_ context.Context, attempt delivery.Attempt) (delivery.DeliveryResult, error) {
		if attempt.Recipient != "+12025550123" || !strings.HasPrefix(string(attempt.Body), "Code: ") {
			t.Error("phone worker did not retain exact SMS recipient/content")
		}
		calls++
		code = strings.TrimPrefix(string(attempt.Body), "Code: ")
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal("native SMS worker composition", err)
	}
	processed, err := worker.ProcessOne(ctx)
	if err != nil || !processed.Claimed || calls != 1 || len(code) != 6 {
		t.Fatal("actual encrypted SMS delivery", err)
	}
	completionFlow, err := otp.NewSessionSendFlow(original.SessionID, auth.NewBearerCredential(bearerWire))
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Action = "identity.phone.verify"
	if transport == session.CredentialCookie {
		wrongCSRF, err := session.NewCSRFToken()
		if err != nil {
			t.Fatal(err)
		}
		originalCode, err := auth.NewOneTimeCode(code)
		if err != nil {
			t.Fatal(err)
		}
		bad, err := phone.NewVerificationRequest(phone.VerificationRequestSpec{TenantID: original.TenantID, UserID: original.UserID, Caller: caller, Flow: completionFlow, SendCommandID: send.Binding.CommandID, Code: originalCode, CSRFToken: wrongCSRF})
		if err != nil {
			t.Fatal(err)
		}
		if lifetime, err := service.PhoneVerificationLifetime(ctx, bad); err == nil || lifetime != 0 {
			t.Fatal("foreign synchronizer disclosed original rate lifetime")
		}
		if _, err := service.Verify(ctx, bad); err == nil {
			t.Fatal("foreign synchronizer consumed a phone challenge")
		}
		var debits int
		if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts+failed_attempts FROM phone_codes.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(original.TenantID), string(send.Binding.CommandID)).Scan(&debits); err != nil || debits != 0 {
			t.Fatal("foreign synchronizer charged the original challenge", err)
		}
	}
	wrong := []byte(code)
	wrong[0] = '0' + (wrong[0]-'0'+1)%10
	wrongCode, err := auth.NewOneTimeCode(string(wrong))
	clear(wrong)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := phone.NewVerificationRequest(phone.VerificationRequestSpec{TenantID: original.TenantID, UserID: original.UserID, Caller: caller, Flow: completionFlow, SendCommandID: send.Binding.CommandID, Code: wrongCode, CSRFToken: csrf})
	if err != nil {
		t.Fatal(err)
	}
	originalLifetime, err := service.PhoneVerificationLifetime(ctx, completion)
	if err != nil || originalLifetime <= 0 || originalLifetime > 5*time.Minute {
		t.Fatal("native source did not authenticate the issued challenge lifetime", err)
	}
	if repeated, err := service.PhoneVerificationLifetime(ctx, completion); err != nil || repeated != originalLifetime {
		t.Fatal("rate lookup renewed or shortened original issuance metadata", err)
	}
	var rateAttempts int
	if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts+failed_attempts FROM phone_codes.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(original.TenantID), string(send.Binding.CommandID)).Scan(&rateAttempts); err != nil || rateAttempts != 0 {
		t.Fatal("lifetime lookup compared or charged the supplied wrong code", err)
	}
	if outcome == "late-verify-factor" {
		beforeStatus = withdrawFactor
	}
	denied, err := service.Verify(ctx, completion)
	if err == nil {
		t.Fatal("wrong SMS code verified a phone")
	}
	if result, e := denied.Bindings(); e == nil && result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("wrong code returned committed verification")
	}
	var attempts, failures int
	var verified bool
	if outcome == "late-verify-factor" {
		if err := pool.Raw().QueryRow(ctx, `SELECT c.used_attempts,c.failed_attempts,i.verified FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$2 WHERE c.tenant_id=$1 AND c.challenge_id=$3`, string(original.TenantID), string(send.IdentifierID), string(send.Binding.CommandID)).Scan(&attempts, &failures, &verified); err != nil || attempts != 0 || failures != 0 || verified {
			t.Fatal("late factor withdrawal charged OTP or verified phone", err)
		}
		return
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT c.used_attempts,c.failed_attempts,i.verified FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$2 WHERE c.tenant_id=$1 AND c.challenge_id=$3`, string(original.TenantID), string(send.IdentifierID), string(send.Binding.CommandID)).Scan(&attempts, &failures, &verified); err != nil || attempts != 1 || failures != 1 || verified {
		t.Fatal("wrong-code denial was not one atomic charge without verification", err)
	}
	actualCode, err := auth.NewOneTimeCode(code)
	code = ""
	if err != nil {
		t.Fatal(err)
	}
	completion, err = phone.NewVerificationRequest(phone.VerificationRequestSpec{TenantID: original.TenantID, UserID: original.UserID, Caller: caller, Flow: completionFlow, SendCommandID: send.Binding.CommandID, Code: actualCode, CSRFToken: csrf})
	if err != nil {
		t.Fatal(err)
	}
	verification := service
	var fault *signinCommitFault
	if outcome != "normal" {
		fault = &signinCommitFault{before: outcome == "before-commit", marker: "UPDATE identity.identifiers SET kind="}
		faulted, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
		if err != nil {
			t.Fatal("phone isolated commit-fault connection", err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if faulted.Close(cleanup) != nil {
				t.Error("phone fault pool cleanup")
			}
		}()
		faultProofOwner, err := NewReauthenticationService(faulted, reauthConfig)
		if err != nil {
			t.Fatal(err)
		}
		faultPrimary, err := NewActionPrimarySource(faultProofOwner, primaryConfig)
		if err != nil {
			t.Fatal(err)
		}
		verification, err = NewPhoneVerificationService(faultPrimary, numberPolicy, configuration, keys)
		if err != nil {
			t.Fatal(err)
		}
	}
	confirmed, err := verification.Verify(ctx, completion)
	if fault != nil {
		ambiguous, resultErr := confirmed.Bindings()
		if err == nil || resultErr != nil || !fault.hit.Load() || ambiguous.Outcome != identity.CommitOutcomeUnknown || ambiguous.Identifier != (identity.IdentifierProjection{}) {
			t.Fatal("phone interrupted commit did not withhold projection with original unknown custody", err)
		}
		caller.Request.Action = "identity.phone.verify.recover"
		recovery, err := phone.NewVerificationRecoveryRequest(phone.VerificationRecoveryRequestSpec{TenantID: original.TenantID, UserID: original.UserID, Caller: caller, Flow: completionFlow, Recovery: ambiguous.Recovery, CSRFToken: csrf})
		if err != nil {
			t.Fatal(err)
		}
		for attempt := range 3 {
			history, err := service.RecoverVerification(ctx, recovery)
			reconciled, resultErr := history.Bindings()
			expected := identity.CommitOutcomeCommitted
			if outcome == "before-commit" {
				expected = identity.CommitOutcomeNotCommitted
			}
			if outcome == "before-commit" && attempt == 0 && err == nil && resultErr == nil && reconciled.Outcome == identity.CommitOutcomeInProgress {
				if reconciled.Binding != ambiguous.Binding || !reconciled.Replayed || reconciled.Identifier != (identity.IdentifierProjection{}) || reconciled.RetryAfter <= 0 || reconciled.RetryAfter > time.Second {
					t.Fatal("pending phone recovery lost its original bounded lease custody")
				}
				wait := time.NewTimer(reconciled.RetryAfter)
				select {
				case <-wait.C:
				case <-ctx.Done():
					wait.Stop()
					t.Fatal(ctx.Err())
				}
				continue
			}
			if err != nil || resultErr != nil || reconciled.Outcome != expected || reconciled.Binding != ambiguous.Binding || !reconciled.Replayed || reconciled.Identifier != (identity.IdentifierProjection{}) {
				t.Fatalf("phone original interrupted-commit recovery: outcome=%v expected=%v matching-binding=%t replayed=%t projection-omitted=%t result-error=%v error=%v", reconciled.Outcome, expected, reconciled.Binding == ambiguous.Binding, reconciled.Replayed, reconciled.Identifier == (identity.IdentifierProjection{}), resultErr, err)
			}
		}
		var finalized, actualVerified bool
		if err := pool.Raw().QueryRow(ctx, `SELECT c.state='finalized',i.verified FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$2 WHERE c.tenant_id=$1 AND c.challenge_id=$3`, string(original.TenantID), string(send.IdentifierID), string(send.Binding.CommandID)).Scan(&finalized, &actualVerified); err != nil || finalized != (outcome == "lost-commit") || actualVerified != finalized {
			t.Fatal("phone interrupted commit split OTP use from identifier verification", err)
		}
		return
	}
	if err != nil {
		t.Fatal("actual consuming phone confirmation", err)
	}
	result, err := confirmed.Bindings()
	projection, projectionErr := result.Identifier.Bindings()
	value, display, valuePresent := result.Identifier.Values()
	if err != nil || projectionErr != nil || valuePresent || value != "" || display != "" || result.Outcome != identity.CommitOutcomeCommitted || result.Replayed || projection.IdentifierID != send.IdentifierID || !projection.Verified {
		t.Fatal("phone confirmation lost its verified projection", err)
	}
	var state string
	var identifierVersion, verificationVersion uint64
	if err := pool.Raw().QueryRow(ctx, `SELECT c.state,c.used_attempts,c.failed_attempts,i.version,i.verification_version,i.verified FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$2 WHERE c.tenant_id=$1 AND c.challenge_id=$3`, string(original.TenantID), string(send.IdentifierID), string(send.Binding.CommandID)).Scan(&state, &attempts, &failures, &identifierVersion, &verificationVersion, &verified); err != nil || state != "finalized" || attempts != 2 || failures != 1 || identifierVersion != 2 || verificationVersion != 2 || !verified {
		t.Fatal("OTP consumption and phone verification did not commit atomically", err)
	}
	caller.Request.Action = "identity.phone.verify.recover"
	recovery, err := phone.NewVerificationRecoveryRequest(phone.VerificationRecoveryRequestSpec{TenantID: original.TenantID, UserID: original.UserID, Caller: caller, Flow: completionFlow, Recovery: result.Recovery, CSRFToken: csrf})
	if err != nil {
		t.Fatal(err)
	}
	historical, err := service.RecoverVerification(ctx, recovery)
	if err != nil {
		t.Fatal("phone original code-free recovery", err)
	}
	historyResult, err := historical.Bindings()
	if err != nil || !historyResult.Replayed || historyResult.Outcome != identity.CommitOutcomeCommitted || historyResult.Binding != result.Binding || historyResult.Identifier != (identity.IdentifierProjection{}) {
		t.Fatal("phone recovery repeated execution or disclosed projection", err)
	}
	disclosurePolicy.armed.Store(true)
	withdrawn, err := service.RecoverVerification(ctx, recovery)
	_, disclosed := withdrawn.Bindings()
	if err == nil || disclosed == nil || disclosurePolicy.calls.Load() != 2 {
		t.Fatal("post-query disclosure withdrawal returned phone history or missed the final policy check")
	}
	disclosurePolicy.armed.Store(false)
	if transport == session.CredentialCookie {
		bad, err := recovery.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		bad.CSRFToken, err = session.NewCSRFToken()
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := phone.NewVerificationRecoveryRequest(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.RecoverVerification(ctx, foreign); err == nil {
			t.Fatal("foreign synchronizer disclosed original phone recovery")
		}
	}
}
