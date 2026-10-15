//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Native API contract, not whole M04 acceptance: authority rows are explicit
// native fixture data. No fake domain/transaction/issuer/delivery implementation
// substitutes for their real owners. Provider status is the external risk seam.
func testNativeEmailManagement(t *testing.T, ctx context.Context, pool *database.Pool, sourceConfig passwordpg.ReauthenticationConfig, input passwordpg.ReauthenticationRequest, modes ...string) {
	t.Helper()
	var history migrations.Source = kernel.IdentifierMutationMigrationSource{Base: kernel.MigrationSource{}, Version: 14}
	history = kernel.PreparationMigrationSource{Base: history, Version: 15}
	history = kernel.AdmissionPreparationMigrationSource{Base: history, Version: 16}
	history = kernel.CounterPreparationMigrationSource{Base: history, Version: 17}
	rows, err := history.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[len(rows)-4:] {
		if _, err := pool.Raw().Exec(ctx, row.UpSQL()); err != nil {
			t.Fatal("managed preparation install", err)
		}
	}
	for _, source := range []migrations.Source{mfapg.MigrationSource{Version: 1}, riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "managed_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4}, deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 18}, passwordpg.EmailReauthenticationMigrationSource{}} {
		items, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			// Default kernel/password prefixes were installed by this native
			// fixture's real runner; retain their original immutable bytes.
			if _, ok := source.(deliverypg.MigrationSource); ok && item.Version() != 18 {
				continue
			}
			if _, ok := source.(passwordpg.EmailReauthenticationMigrationSource); ok && item.Version() != 9 {
				continue
			}
			if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
				t.Fatal("managed owner install", err)
			}
		}
	}
	verificationCounters, err := (riskpg.VerificationCounterMigrationSource{Schema: "managed_risk", Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, verificationCounters[0].UpSQL()); err != nil {
		t.Fatal("selected verification-counter history", err)
	}
	files := issuerpg.Migrations()
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal("issuer install", err)
		}
	}
	seed, _ := identity.NewCommandID()
	seedWire, _ := base64.RawURLEncoding.DecodeString(string(seed))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.password.signup',$3,1,decode('01','hex'))`, seedWire, string(input.TenantID), make([]byte, 32)); err != nil {
		t.Fatal("explicit factor reconciliation claim", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.password.signup')`, seedWire, string(input.TenantID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$2,1,0,$3,'identity.password.signup')`, string(input.TenantID), string(input.Caller.Request.Subject.ID), seedWire); err != nil {
		t.Fatal(err)
	}
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.email.verification-send", Audience: "email-management"}
	sourceConfig.Targets = append(sourceConfig.Targets, target)
	source, err := passwordpg.NewReauthenticationService(pool, sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	input.Target = target
	issued, err := source.Verify(ctx, input)
	if err != nil {
		t.Fatal("native original password comparison", err)
	}
	primary, err := passwordpg.NewEmailPrimarySource(source, passwordpg.EmailPrimaryConfig{Action: target.Action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status"}},
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal("managed risk policy", err)
	}
	key, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{71}, 32))
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{72}, 32), bytes.Repeat([]byte{73}, 32))
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "managed_risk", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": bytes.Repeat([]byte{74}, 32)}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}}})
	if err != nil {
		t.Fatal(err)
	}
	var riskUnavailable atomic.Bool
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "status", Version: "managed-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
		if riskUnavailable.Load() {
			return risk.Signal{}, errors.New("synthetic provider outage")
		}
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, nil
	}}, {Name: "velocity", Version: "native-counter-only", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
		return risk.Signal{}, errors.New("provider velocity must not replace protected native counters")
	}}}})
	if err != nil {
		t.Fatal("managed provider evaluator", err)
	}
	keys, err := keyring.New(map[string][]byte{"managed-output": bytes.Repeat([]byte{75}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "managed-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {76}}, ActiveEnvelopeKeyID: "managed-output", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "capture", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://managed.example.test"
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "managed-verification", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	normalization, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "mailboxes", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 254})
	signer, _ := capability.NewHMACSHA256Signer("managed-signer", bytes.Repeat([]byte{77}, 32))
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{77}, 32))
	resolver, _ := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "managed-signer", Verifier: verifier}})
	c := passwordpg.EmailManagementConfig{PolicyID: "managed-email", ConfigurationID: "managed-test-v1", MaximumDuration: 10 * time.Second, Lifetime: time.Minute, ActiveEnvelopeKeyID: "managed-output", CounterPolicy: policy, Counters: counters, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "managed-test-v1", Keys: []risk.EvidenceKey{evidence}}, Domain: kernel.EmailAttachmentDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {78}}}, Verification: email.RegistrationVerificationConfig{Address: email.AddressPolicy{MaximumBytes: 254, Canonicalization: normalization, PreserveDisplay: true}, Issuer: origin, Audience: "managed-email", MaximumLifetime: time.Minute, Redirects: []string{origin + "/done"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {79}}}, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "managed-email", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {80}}, PreparationTimeout: time.Second}, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "managed-test", ActiveEnvelopeKey: "issuer-output", EnvelopeKeys: map[string][]byte{"issuer-output": bytes.Repeat([]byte{81}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "managed-signer", HMAC: bytes.Repeat([]byte{77}, 32)}}, Clock: time.Now}, Delivery: passwordpg.SignupDeliveryConfig{Owner: owner, Renderer: renderer, Resolver: resolver, Endpoint: origin + "/verify", TemplateID: "managed-verification", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{82}, Timeout: time.Second}}
	c.ResendInterval = 30 * time.Second
	service, err := passwordpg.NewEmailManagementService(primary, c, keys)
	if err != nil {
		t.Fatal("managed service construction", err)
	}
	id, _ := identity.NewCommandID()
	request := passwordpg.EmailManagementRequest{Primary: passwordpg.EmailPrimaryRequest{TenantID: input.TenantID, CommandID: id, AddressID: "managed-address", Session: input.Session, Proof: issued.Proof, Caller: input.Caller}, Address: "New@example.test", CallbackURL: origin + "/done", Network: "192.0.2.1"}
	if len(modes) == 1 && modes[0] == "keyed" {
		testNativeKeyedEmailManagement(t, ctx, pool, service, sourceConfig, c, keys, request, &riskUnavailable)
		return
	}
	result, err := service.VerificationSend(ctx, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.AddressID != request.Primary.AddressID || result.IdentifierVersion != 1 || result.VerificationVersion != 1 {
		t.Fatal("native managed request", result.Outcome, err)
	}
	var addresses, issuedLinks, messages int
	commandBytes, _ := base64.RawURLEncoding.Strict().DecodeString(string(id))
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='managed-address' AND canonical_value='New@example.test' AND NOT verified AND NOT is_primary),(SELECT count(*) FROM capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$3 AND subject_id=$2),(SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1 AND command_id=$4)`, string(input.TenantID), string(input.Caller.Request.Subject.ID), string(id), commandBytes).Scan(&addresses, &issuedLinks, &messages); err != nil || addresses != 1 || issuedLinks != 1 || messages != 1 {
		t.Fatal("managed atomic address/issuance/delivery", err)
	}
	workerHistory, err := (deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 18, WorkerVersion: 19, PolicyVersion: 20, KeyedVersion: 21, StateVersion: 22}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range workerHistory {
		if item.Version() > 18 {
			if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
				t.Fatal("worker profile install", err)
			}
		}
	}
	authorize, err := authorization.NewDecisionService(managedEmailWorkerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	workerPolicy := delivery.DefaultConfig()
	workerPolicy.SenderTimeout = time.Second
	workerPolicy.SenderConcurrency = 1
	workerPolicy.DedupeTTL = 25 * time.Hour
	public, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "managed-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {76}}, ActiveEnvelopeKeyID: "managed-output", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "capture", PolicyVersion: 1}}}, Coordinator: sourceConfig.Coordinator, PolicyID: "managed-email", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 2 * time.Second, NamespaceKey: [32]byte{83}, Policies: map[uint64]delivery.Config{1: workerPolicy}, StateTracking: true}, crypto, authorize, []delivery.Template{{ID: "managed-verification", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal("owned public worker composition", err)
	}
	sender, err := delivery.NewCaptureSender(delivery.CaptureConfig{TenantID: delivery.TenantID(input.TenantID), MaxAttempts: 2, MaxBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	worker, err := public.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "managed-worker", Request: authorization.Request{Tenant: authorization.TenantID(input.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "managed-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "managed-worker"}}}, ProviderConfigVersion: 1}, sender)
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.ProcessOne(ctx)
	if err != nil || !processed.Claimed || processed.Completion.State != delivery.StateAccepted {
		t.Fatal("captured provider-boundary processing", err)
	}
	captured, err := sender.Snapshot(ctx)
	if err != nil || len(captured) != 1 || captured[0].Recipient != "New@example.test" {
		t.Fatal("new-address delivery was absent or retargeted", err)
	}
	link, err := url.Parse(captured[0].Body)
	if err != nil || link.Scheme != "https" || link.Host != "managed.example.test" || link.Path != "/verify" {
		t.Fatal("fixed verification endpoint changed")
	}
	grant, err := capability.Verify(ctx, link.Query().Get("token"), resolver, capability.VerifyOptions{Issuer: origin, Now: time.Now().UTC(), Limits: capability.DefaultLimits()})
	if err != nil || grant.Payload().Subject != string(input.Caller.Request.Subject.ID) || grant.Payload().Resource != "managed-address" || grant.Payload().Caveats["email.profile"] != "management-v1" || grant.Payload().Caveats["email.confirm_operation"] != "identity.email.verification-confirm" {
		t.Fatal("actual delivered link lost original scope", err)
	}
	reader, supported := any(service).(interface {
		ReadManagedVerification(context.Context, capability.Proof, authorization.DecisionContext) (email.ManagedVerificationSpec, uint32, error)
	})
	if !supported {
		t.Fatal("native management owner cannot read original link intent for confirmation")
	}
	proof, err := capability.ParseProof(link.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal("captured proof parse", err)
	}
	originIssuer, err := issuerpg.NewIssuer(c.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, original, version, err := originIssuer.ReadIssuanceOrigin(ctx, pool, proof, "identity.identifier.verify"); err != nil || original != id || version != 1 {
		t.Fatal("actual issuer origin read", err)
	}
	// Current service-account disclosure authority is deliberately distinct
	// from the historical human request actor and needs no original session.
	caller := input.Caller.Clone()
	caller.PolicyRevision = 9
	caller.CorrelationID = "managed-link-inspection"
	caller.Request.Tenant = authorization.TenantID(input.TenantID)
	caller.Request.Subject = authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "managed-confirmation"}
	caller.Request.Action = "identity.email.verification-confirm"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(input.Caller.Request.Subject.ID)}
	var before string
	if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1`, commandBytes).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		original, replay, err := reader.ReadManagedVerification(ctx, proof, caller)
		policy, policyErr := email.NewManagedVerificationPolicy(c.Verification)
		if err != nil || policyErr != nil || replay != 1 || original.Binding.CommandID != id || original.Binding.ActorID != identity.ActorID(input.Caller.Request.Subject.ID) || original.IdentifierID != "managed-address" || original.Payload.CanonicalAddress.Record().Value != "New@example.test" || !original.IssuedAt.Equal(grant.Payload().IssuedAt) || !original.ExpiresAt.Equal(grant.Payload().ExpiresAt) || policy.Authorize(grant, original, time.Now().UTC()) != nil {
			t.Fatal("inspection lost original authenticated intent", err)
		}
	}
	rateSource, supported := any(service).(interface {
		ManagedVerificationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
	})
	if !supported {
		t.Fatal("managed confirmation has no native subject/challenge rate source")
	}
	for range 2 {
		user, challenge, lifetime, err := rateSource.ManagedVerificationRateSource(ctx, proof, origin+"/done", caller)
		if err != nil || user != identity.UserID(grant.Payload().Subject) || challenge != grant.Payload().ID || lifetime != grant.Payload().ExpiresAt.Sub(grant.Payload().IssuedAt) {
			t.Fatal("managed rate source changed original signed identity/lifetime", err)
		}
	}
	if user, challenge, lifetime, err := rateSource.ManagedVerificationRateSource(ctx, proof, origin+"/other", caller); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("foreign callback disclosed managed rate metadata")
	}
	cancelled, stopRate := context.WithCancel(ctx)
	stopRate()
	if user, challenge, lifetime, err := rateSource.ManagedVerificationRateSource(cancelled, proof, origin+"/done", caller); !errors.Is(err, context.Canceled) || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("cancelled managed rate read disclosed metadata or lost cancellation")
	}
	var after string
	if err := pool.Raw().QueryRow(ctx, `SELECT row_to_json(j)::text FROM identity.commands j WHERE command_id=$1`, commandBytes).Scan(&after); err != nil || after != before {
		t.Fatal("inspection mutated original preparation", err)
	}
	for _, alter := range []func(*authorization.DecisionContext){
		func(d *authorization.DecisionContext) { d.Request.Tenant = "foreign" },
		func(d *authorization.DecisionContext) { d.Request.Action = "identity.email.change-confirm" },
		func(d *authorization.DecisionContext) { d.Request.Resource.ID = "foreign" },
		func(d *authorization.DecisionContext) { d.PolicyRevision++ },
	} {
		other := caller.Clone()
		alter(&other)
		original, replay, err := reader.ReadManagedVerification(ctx, proof, other)
		if err == nil || original.IdentifierID != "" || replay != 0 {
			t.Fatal("foreign current authority disclosed original intent")
		}
	}
	inspector, supported := any(service).(interface {
		ValidateManagedVerification(context.Context, capability.Proof, string, authorization.DecisionContext) (bool, error)
	})
	if !supported {
		t.Fatal("native management owner has no scanner-safe current-state validation")
	}
	for range 2 {
		if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err != nil || !valid {
			t.Fatal("scanner-safe inspection denied the original link", err)
		}
	}
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/other", caller); err == nil || valid {
		t.Fatal("inspection accepted a substituted callback")
	}
	riskUnavailable.Store(true)
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err == nil || valid {
		t.Fatal("inspection accepted unavailable current provider policy")
	}
	riskUnavailable.Store(false)
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id=$1 AND user_id=$2`, string(input.TenantID), string(input.Caller.Request.Subject.ID)); err != nil {
		t.Fatal(err)
	}
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err == nil || valid {
		t.Fatal("inspection promoted stale original factor policy")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1 WHERE tenant_id=$1 AND user_id=$2`, string(input.TenantID), string(input.Caller.Request.Subject.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`, string(input.TenantID), string(input.Caller.Request.Subject.ID)); err != nil {
		t.Fatal(err)
	}
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err == nil || valid {
		t.Fatal("inspection accepted a currently blocked account")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, string(input.TenantID), string(input.Caller.Request.Subject.ID)); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext FROM identity.commands WHERE command_id=$1`, commandBytes).Scan(&ciphertext); err != nil || len(ciphertext) == 0 {
		t.Fatal("committed output fixture", err)
	}
	defer clear(ciphertext)
	corrupt := bytes.Clone(ciphertext)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$1 WHERE command_id=$2`, corrupt, commandBytes); err == nil {
		t.Fatal("committed original preparation admitted ciphertext substitution")
	}
	clear(corrupt)
	otherConfig := c
	otherConfig.ConfigurationID = "foreign-configuration"
	otherService, err := passwordpg.NewEmailManagementService(primary, otherConfig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if original, replay, err := otherService.ReadManagedVerification(ctx, proof, caller); err == nil || original.IdentifierID != "" || replay != 0 {
		t.Fatal("foreign configuration decrypted original intent")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if valid, err := inspector.ValidateManagedVerification(cancelled, proof, origin+"/done", caller); !errors.Is(err, context.Canceled) || valid {
		t.Fatal("cancelled inspection admitted the proof")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE capability_identity_one_use SET state='revoked' WHERE tenant_id=$1 AND capability_id=$2`, string(input.TenantID), grant.Payload().ID); err != nil {
		t.Fatal(err)
	}
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err == nil || valid {
		t.Fatal("inspection accepted a revoked issued proof")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE capability_identity_one_use SET state='issued' WHERE tenant_id=$1 AND capability_id=$2`, string(input.TenantID), grant.Payload().ID); err != nil {
		t.Fatal(err)
	}
	// Fixture restorations do not create new evidence: the real public read
	// must still admit the exact original link and return no metadata.
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err != nil || !valid {
		t.Fatal("original inspection changed after denial checks", err)
	}
	var used int
	if err := pool.Raw().QueryRow(ctx, `SELECT uses FROM capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(input.TenantID), grant.Payload().ID).Scan(&used); err != nil || used != 0 {
		t.Fatal("inspection consumed the delivered proof", err)
	}
	if again, err := worker.ProcessOne(ctx); err != nil || again.Claimed {
		t.Fatal("committed delivery invoked the sender again", err)
	}
	if again, err := service.VerificationSend(ctx, request); err == nil || again.AddressID != "" {
		t.Fatal("used/stale original proof admitted a second request")
	}
	finalCapture, err := sender.Snapshot(ctx)
	if err != nil || len(finalCapture) != 1 {
		t.Fatal("denial/repeated worker produced another message", err)
	}
	confirmer, supported := any(service).(interface {
		VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
	})
	if !supported {
		t.Fatal("native managed link has no atomic explicit confirmation")
	}
	confirmID, _ := identity.NewCommandID()
	callback, _ := url.Parse(origin + "/done")
	confirmation := email.VerificationConfirmRequest{TenantID: input.TenantID, CommandID: confirmID, Token: proof, Callback: *callback, Caller: caller, Network: "192.0.2.1"}
	if len(modes) != 0 && (modes[0] == "credential" || modes[0] == "authorization") {
		if modes[0] == "credential" {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=8 WHERE tenant_id=$1 AND user_id=$2 AND credential_id='reauth-password'`, string(input.TenantID), string(input.Caller.Request.Subject.ID)); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=9 WHERE tenant_id=$1 AND subject_id=$2 AND policy_namespace='users'`, string(input.TenantID), string(input.Caller.Request.Subject.ID)); err != nil {
				t.Fatal(err)
			}
		}
		if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err == nil || valid {
			t.Fatal("inspection admitted invalidated source authority")
		}
		if out, err := confirmer.VerificationConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("invalidated original authority confirmed managed address")
		}
		var pending bool
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT NOT verified AND version=1 AND verification_version=1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id='managed-address'),uses FROM capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(input.TenantID), grant.Payload().ID).Scan(&pending, &used); err != nil || !pending || used != 0 {
			t.Fatal("denied original authority changed domain/proof state", err)
		}
		return
	}
	if len(modes) != 0 && modes[0] == "rollback" {
		// A real SQL failure after the provisional directory write must roll back
		// that write and the preceding capability use together. This is a disposable
		// failure seam, not a substitute domain store or an authority bypass.
		if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_managed_verification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.verified AND NOT OLD.verified THEN RAISE EXCEPTION 'synthetic late verification failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_managed_verification AFTER UPDATE ON identity.identifiers FOR EACH ROW EXECUTE FUNCTION public.reject_managed_verification()`); err != nil {
			t.Fatal(err)
		}
		failed := confirmation
		failed.CommandID, _ = identity.NewCommandID()
		failedResult, failedErr := confirmer.VerificationConfirm(ctx, failed)
		if failedErr == nil || failedResult.Outcome == identity.CommitOutcomeCommitted || failedResult.Address != (identity.IdentifierProjection{}) {
			t.Fatal("late failure committed verification")
		}
		var pending bool
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT NOT verified AND version=1 AND verification_version=1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id='managed-address'),uses FROM capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(input.TenantID), grant.Payload().ID).Scan(&pending, &used); err != nil || !pending || used != 0 {
			t.Fatal("late failure retained proof/directory effects", err)
		}
		if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_managed_verification ON identity.identifiers; DROP FUNCTION public.reject_managed_verification()`); err != nil {
			t.Fatal(err)
		}
		// Existing participant policy terminally releases this failed attempt; zero
		// uses does not authorize resurrecting it. A future resend supplies a new
		// explicitly authorized grant. Recovery must conserve the observed rollback.
		recoveryOwner, supported := any(service).(interface {
			VerificationRecover(context.Context, email.VerificationRecoveryRequest) (email.VerificationRecoveryResult, error)
		})
		if !supported {
			t.Fatal("missing rollback recovery")
		}
		recovered, _ := recoveryOwner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: failedResult.Recovery, Caller: caller})
		if recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Validate() != nil {
			t.Fatal("rollback recovery fabricated commit")
		}
		return
	}
	httpMode := len(modes) == 1 && modes[0] == "http"
	if httpMode {
		confirmation.Network = "127.0.0.1"
		proveManagedEmailHTTP(t, ctx, pool, service, confirmation, link.Query().Get("token"), origin)
	}
	confirmed, err := confirmer.VerificationConfirm(ctx, confirmation)
	if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted || confirmed.Validate() != nil || confirmed.Replayed != httpMode {
		t.Fatal("atomic managed confirmation", confirmed.Outcome, err)
	}
	if !httpMode {
		address, err := confirmed.Address.Bindings()
		if err != nil || address.IdentifierVersion != 2 || address.VerificationVersion != 2 {
			t.Fatal("managed confirmation lost verified successor", err)
		}
	} else if confirmed.Address != (identity.IdentifierProjection{}) {
		t.Fatal("HTTP confirmation replay disclosed address twice")
	}
	var verified bool
	var proofState string
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT verified FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id='managed-address'),uses,state FROM capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(input.TenantID), grant.Payload().ID).Scan(&verified, &used, &proofState); err != nil || !verified || used != 1 || proofState != "finalized" {
		t.Fatal("verification and proof use did not commit together", err)
	}
	if valid, err := inspector.ValidateManagedVerification(ctx, proof, origin+"/done", caller); err == nil || valid {
		t.Fatal("completed proof remained scanner-valid")
	}
	replayed, err := confirmer.VerificationConfirm(ctx, confirmation)
	if err != nil || !replayed.Replayed || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Address != (identity.IdentifierProjection{}) {
		t.Fatal("confirmation exact replay repeated disclosure or mutation", err)
	}
	changed := confirmation
	changed.Caller = confirmation.Caller.Clone()
	changed.Caller.CorrelationID = "another-trusted-attempt"
	if out, err := confirmer.VerificationConfirm(ctx, changed); err != nil || !out.Replayed || out.Outcome != identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("new transport correlation changed original command intent", err)
	}
	changed.Network = "192.0.2.2"
	if out, err := confirmer.VerificationConfirm(ctx, changed); err == nil || out.Outcome != identity.CommitOutcomeConflict || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("correlation restoration bypassed changed protected intent", err)
	}
	if user, challenge, lifetime, err := rateSource.ManagedVerificationRateSource(ctx, proof, origin+"/done", caller); err != nil || user != identity.UserID(grant.Payload().Subject) || challenge != grant.Payload().ID || lifetime != grant.Payload().ExpiresAt.Sub(grant.Payload().IssuedAt) {
		t.Fatal("original replay lost immutable challenge rate identity", err)
	}
	recoveryOwner, supported := any(service).(interface {
		VerificationRecover(context.Context, email.VerificationRecoveryRequest) (email.VerificationRecoveryResult, error)
	})
	if !supported {
		t.Fatal("managed confirmation has no proof-free recovery")
	}
	recovered, err := recoveryOwner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: confirmed.Recovery, Caller: caller})
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Validate() != nil {
		t.Fatal("original committed recovery lost outcome", err)
	}
	confirmation.CommandID, _ = identity.NewCommandID()
	if out, err := confirmer.VerificationConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("consumed original link admitted another confirmation")
	}
}

// Real HTTPS and native PostgreSQL owners, including the strict shared HTTP
// counter backend. Only the external delivery/risk provider seams are controlled
// by the enclosing fixture. This does not claim full reference graph composition.
func proveManagedEmailHTTP(t *testing.T, ctx context.Context, pool *database.Pool, service *passwordpg.EmailManagementService, confirmation email.VerificationConfirmRequest, token, origin string) {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("native HTTP rate history", err)
		}
	}
	backend, err := ratepg.OpenStrict(ctx, pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal("native HTTP rate backend", err)
	}
	rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "managed-http", Key: [32]byte{83}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 8192, MaximumDecodedBytes: 8192, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "managed.example.test", TenantID: confirmation.TenantID}}}
	feature, err := emailhttp.NewManagedConfirmationFeature(emailhttp.ManagedConfirmationConfig{Network: network, Service: service, Rate: rate, Origin: identityhttp.Origin(origin), ActorID: identity.ActorID(confirmation.Caller.Request.Subject.ID), PolicyRevision: confirmation.Caller.PolicyRevision, Now: time.Now, MaximumDuration: 10 * time.Second})
	if err != nil {
		t.Fatal("native managed HTTP selection", err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(ctx, identityhttp.DocumentConfig{Title: "Managed email", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || !bytes.Contains(doc.JSON(), []byte("/v1/email/verification-confirm")) {
		t.Fatal("selected managed HTTP metadata", err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = 15 * time.Second
	defer client.CloseIdleConnections()
	for _, mode := range []string{"origin", "callback", "fresh", "replay"} {
		callback, requestOrigin := confirmation.Callback.String(), origin
		want := 200
		if mode == "origin" {
			requestOrigin, want = "https://foreign.example", 403
		}
		if mode == "callback" {
			callback, want = origin+"/other", 403
		}
		wire, err := json.Marshal(map[string]string{"token": token, "callback": callback, "commandID": string(confirmation.CommandID)})
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/email/verification-confirm", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "managed.example.test"
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("managed HTTPS request", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		clear(wire)
		var out emailhttp.ConfirmationResponse
		if json.Unmarshal(body, &out) != nil {
			t.Fatal("managed HTTPS response schema", mode)
		}
		if readErr != nil || closeErr != nil || len(body) > 16384 || response.StatusCode != want || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, []byte(token)) {
			t.Fatal("managed HTTPS status/custody", mode, response.StatusCode, out.CommitOutcome, out.Error)
		}
		clear(body)
		if want == 200 {
			if !out.Confirmed || out.CommitOutcome != "committed" || out.CommandID != confirmation.CommandID || out.Replayed != (mode == "replay") || (out.Address == nil) != (mode == "replay") {
				t.Fatal("managed HTTPS lost original outcome")
			}
			if out.Address != nil && (out.Address.IdentifierID != "managed-address" || out.Address.Primary || out.Address.Email != "New@example.test" || out.Address.IdentifierVersion != 2 || out.Address.VerificationVersion != 2) {
				t.Fatal("managed HTTPS changed verified projection")
			}
		} else {
			var unchanged bool
			if err := pool.Raw().QueryRow(ctx, `SELECT NOT verified AND version=1 AND verification_version=1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id='managed-address'`, string(confirmation.TenantID)).Scan(&unchanged); err != nil || !unchanged || out.Confirmed || out.Address != nil {
				t.Fatal("denied HTTPS request changed/disclosed address", err)
			}
		}
	}
	var dimensions int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.rate_limit_states`).Scan(&dimensions); err != nil || dimensions != 3 {
		t.Fatal("native HTTP subject/challenge/IP dimensions absent", err)
	}
}

type managedEmailWorkerPolicy struct{}

func (managedEmailWorkerPolicy) Decide(_ context.Context, request authorization.Request) (authorization.Decision, error) {
	outcome := authorization.Deny
	if request.Action == "identity.delivery.process" && request.Subject.Kind == authorization.SubjectServiceAccount && request.Subject.ID == "managed-worker" && request.Resource.Type == "identity.delivery-worker" && request.Resource.ID == "managed-worker" {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 9}, nil
}
