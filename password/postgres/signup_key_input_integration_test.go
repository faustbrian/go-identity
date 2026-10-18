//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	delivery "github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type signupNativeKeyInput interface {
	prepareSignupKeyInput(context.Context, kernel.RequestKeyPreparationBinding, password.SignupRequest, identity.RequestIntent, signupKeyPreparation) ([]byte, error)
}

// Only registry invocation wiring is supplied by this fixture. Production
// kernel mapping, primary flow read, fields, address and authenticated input
// preparation are real. No account, credential, delivery or risk is simulated.
type signupKeyInputFixture struct {
	signupMaterialPhase
	request password.SignupRequest
	config  signupKeyPreparation
}

func (*signupKeyInputFixture) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordSignupOperation()}
}
func (p *signupKeyInputFixture) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, i identity.RequestIntent) ([]byte, error) {
	owner, ok := any(p.repository).(signupNativeKeyInput)
	if !ok {
		return nil, password.ErrPasswordWork
	}
	return owner.prepareSignupKeyInput(ctx, k, p.request, i, p.config)
}

func testNativeSignupKeyInput(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, base kernel.DirectoryAuthorityMigrationSource, storage sessionpg.Config, withUsername bool, consumers ...nativeSignupConsumer) {
	t.Helper()
	history, err := (kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: base, Version: 14}, Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() >= 14 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("original input mapping install", err)
			}
		}
	}
	r, flow, key, _ := nativeSignupFlow(t)
	// The outer signin fixture already owns person@example.test. Start this
	// original creation with an unoccupied address; the next invocation tests
	// neutral acceptance against the account actually created here.
	r.Email = password.SignupAddressInput("prepared@example.test")
	r.TenantID, r.Caller.Request.Tenant = signinTestTenant, signinTestTenant
	r.Caller.Request.Subject.ID = signinTestActor
	r.IdempotencyKey, _ = identity.NewIdempotencyKey(bytes.Repeat([]byte{'J'}, 32))
	s, _ := flow.Bindings()
	s.Binding.ID, _ = identity.NewPreAuthTransactionID()
	s.Binding.Intent.TenantID = r.TenantID
	s.Binding.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	s.Binding.ExpiresAt = s.Binding.IssuedAt.Add(5 * time.Minute)
	r.PreAuthID = s.Binding.ID
	token, _ := session.ParseToken(r.Cookie.Token())
	s.Cookie, _ = token.PreAuthDigest(key, s.Binding)
	flow, err = session.NewPreAuthTransaction(s)
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
		t.Fatal("original flow install")
	}
	// This versioned declaration differs from the preceding material fixture's
	// self-write schema. It must not reuse that durable schema ID/version.
	schema := identity.AttributeSchema{ID: "signup-prepared-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "native-default"}}}}}
	decision := signinPublicPolicy{}
	fields, err := identity.NewAttributeProcessor(schema, decision, func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
		return s, nil
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 3, ValidateCanonicalUserID: func(_ context.Context, user identity.UserID) error {
		if len(user) != 22 {
			return password.ErrPasswordWork
		}
		return nil
	}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	normalization, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "signup-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	address, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization, PreserveDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := keyring.New(map[string][]byte{"input": bytes.Repeat([]byte{79}, 32)})
	crypto, _ := envelope.NewService(keys)
	repository, _ := NewRepository(pool, Config{MaximumDuration: time.Second, HashPolicy: policy})
	if _, ok := any(repository).(signupNativeKeyInput); !ok {
		t.Fatal("native signup has no owned primary/keyed input preparation")
	}
	var selections atomic.Int32
	config := signupKeyPreparation{profile: [32]byte{2}, crypto: crypto, envelopeKey: "input", policyID: "login", policyVersion: 3, schemaID: schema.ID, schemaVersion: schema.Version, comparison: "email-v1", fields: fields, address: address, flowStorage: storage, flowKeys: []session.DigestKey{key}, origins: []string{r.Origin}, callbacks: []string{r.CallbackURL}, selectUser: func(context.Context) (identity.UserID, error) {
		selections.Add(1)
		id, e := identity.NewSubjectID()
		return identity.UserID(id), e
	}}
	phase := &signupKeyInputFixture{signupMaterialPhase: signupMaterialPhase{repository: repository}, request: r, config: config}
	domain, _ := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}})
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, phase})
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 3, Authorization: decision}
	requestKeys, err := kernel.NewRequestKeyConfig("native-signup-input", [32]byte{3}, query)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {4}}, QueryPolicy: &query, AdmissionPolicy: &query}, requestKeys)
	if err != nil {
		t.Fatal(err)
	}
	registration := password.RegistrationPolicy{Enabled: true, MinimumBytes: 8, MaximumBytes: 128, RequireVerifiedEmail: true}
	intent, err := repository.signupRequestIntent(ctx, r, [32]byte{1}, config.profile, registration)
	if err != nil {
		t.Fatal(err)
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: "identity.password.signup"}
	feature := kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: passwordSignupOperation()}
	bound, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, r.Caller, feature, phase)
	if err != nil {
		t.Fatal("original primary preparation denied", err)
	}
	b, selected, original, at, err := repository.restoreSignupInput(ctx, crypto, bound, config.profile, wire, intent)
	originalSpec, _ := original.Bindings()
	if err != nil || b.CommandID != bound.Admission.CommandID || b.ActorID != signinTestActor || originalSpec != s || len(selected.Creation.Attributes) != 1 || selected.Creation.Attributes[0].Value.Scalar.String != "native-default" || selected.Creation.Binding.UserID == "" || at.Before(s.Binding.IssuedAt) {
		t.Fatal("original native preparation changed frozen identity/flow", err)
	}
	// Consume the actual email-owned shape with the real registration issuer.
	// No fabricated authenticated session or hand-written generic payload is used.
	verificationPolicy, err := email.NewRegistrationVerificationPolicy(email.RegistrationVerificationConfig{Address: email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization, PreserveDisplay: true}, Issuer: "https://issuer.example.test", Audience: "email", MaximumLifetime: 5 * time.Minute, Redirects: []string{r.CallbackURL}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {62}}})
	if err != nil {
		t.Fatal(err)
	}
	issued := at.UTC().Truncate(time.Second)
	signingKey := bytes.Repeat([]byte{88}, 32)
	signer, _ := capability.NewHMACSHA256Signer("email-signing", signingKey)
	verifier, _ := capability.NewHMACSHA256Verifier(signingKey)
	resolver, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://issuer.example.test", ID: "email-signing", Verifier: verifier}})
	issuer, err := issuerpg.NewIssuer(issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://issuer.example.test", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "email", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {61}}, PreparationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	verificationConfig := signupVerificationPreparation{address: address, policy: verificationPolicy, issuer: issuer, lifetime: 10 * time.Minute}
	verification, prepared, err := repository.prepareSignupVerification(ctx, b, selected, original, at, verificationConfig)
	if err != nil {
		t.Fatal("real registration issuer rejected email-owned intent", err)
	}
	if verification.Binding != b || !verification.IssuedAt.Equal(issued) || !verification.ExpiresAt.Equal(originalSpec.Binding.ExpiresAt.UTC().Truncate(time.Second)) {
		t.Fatal("native verification renewed original time or flow expiry")
	}
	for _, change := range []func(*identity.CommandBinding, *kernel.PasswordRegistrationIntent, *time.Time, *signupVerificationPreparation){
		func(b *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, _ *time.Time, _ *signupVerificationPreparation) {
			b.AnonymousFlowID = "AgICAgICAgICAgICAgICAg"
		},
		func(b *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, _ *time.Time, _ *signupVerificationPreparation) {
			b.PolicyVersion++
		},
		func(_ *identity.CommandBinding, s *kernel.PasswordRegistrationIntent, _ *time.Time, _ *signupVerificationPreparation) {
			s.Creation.Binding.ActorID = "foreign"
		},
		func(_ *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, at *time.Time, _ *signupVerificationPreparation) {
			*at = originalSpec.Binding.ExpiresAt
		},
		func(_ *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, _ *time.Time, c *signupVerificationPreparation) {
			c.lifetime = 0
		},
		func(_ *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, _ *time.Time, c *signupVerificationPreparation) {
			c.policy = nil
		},
	} {
		badBinding, badSelection, badTime, badConfig := b, selected, at, verificationConfig
		change(&badBinding, &badSelection, &badTime, &badConfig)
		spec, batch, err := repository.prepareSignupVerification(ctx, badBinding, badSelection, original, badTime, badConfig)
		_, planErr := batch.Plan()
		if err == nil || spec.Binding.CommandID != "" || planErr == nil {
			t.Fatal("substituted signup verification retained generated authority")
		}
	}
	issuancePlan, err := prepared.Plan()
	if err != nil || issuancePlan.RegistrationUserID != selected.Creation.Binding.UserID || len(issuancePlan.Grants) != 1 || issuancePlan.Grants[0].CapabilityID == "" || b.UserID != "" {
		t.Fatal("email issuance lost new-user/original-flow separation", err)
	}
	// Later public attempts retain their own primary issue time, not the first
	// fixture's frozen second. Real issuer validity must follow the same clock.
	issuanceCodec, err := issuerpg.NewIssuancePreparationCodec(issuer, issuerpg.IssuancePreparationConfig{Deployment: "signup-test", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{89}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "email-signing", HMAC: signingKey}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	deliveryOwner, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "signup-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {67}}, ActiveEnvelopeKeyID: "input", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "registration-verify", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Verify: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://auth.example.test"}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	deliveryConfig := signupDeliveryPreparation{owner: deliveryOwner, renderer: renderer, resolver: resolver, policy: verificationPolicy, endpoint: "https://auth.example.test/email/verify", template: "registration-verify", templateVersion: 1, providerVersion: 1, locales: []string{"en"}, scopeKey: [32]byte{68}, timeout: time.Second}
	var deliveryWire []byte
	var originalDelivery kernel.DeliveryPlan
	issuanceWire, err := issuanceCodec.CheckpointPreparation(ctx, prepared, 1, func(ctx context.Context, _ uint16, token []byte) error {
		for _, change := range []func(*email.RegistrationVerificationSpec, *[]byte, *time.Time, *signupDeliveryPreparation){
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint = "http://auth.example.test/email/verify"
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint = "https://auth.example.test/email/verify#fragment"
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint = "https://user@auth.example.test/email/verify"
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint += "?token="
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint += "?bad=%"
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint = "https://foreign.example.test/email/verify"
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.endpoint = strings.Repeat("x", 2049)
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.template = "missing"
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.templateVersion++
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.providerVersion++
			},
			func(_ *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, c *signupDeliveryPreparation) {
				c.scopeKey = [32]byte{}
			},
			func(s *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, _ *signupDeliveryPreparation) {
				s.Payload.SubjectID = "foreign"
			},
			func(s *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, _ *signupDeliveryPreparation) {
				s.VerificationVersion++
			},
			func(s *email.RegistrationVerificationSpec, _ *[]byte, _ *time.Time, _ *signupDeliveryPreparation) {
				s.Payload.Redirect.Path = "/different"
			},
			func(_ *email.RegistrationVerificationSpec, token *[]byte, _ *time.Time, _ *signupDeliveryPreparation) {
				(*token)[len(*token)-1] ^= 1
			},
			func(s *email.RegistrationVerificationSpec, _ *[]byte, now *time.Time, _ *signupDeliveryPreparation) {
				*now = s.ExpiresAt
			},
		} {
			changedSpec, changedToken, changedNow, changedConfig := verification, bytes.Clone(token), issued, deliveryConfig
			change(&changedSpec, &changedToken, &changedNow, &changedConfig)
			bad, err := repository.prepareSignupDelivery(ctx, changedSpec, changedToken, changedNow, changedConfig)
			clear(changedToken)
			_, planErr := bad.Plan()
			if err == nil || planErr == nil {
				t.Fatal("substituted signup message retained sendable custody")
			}
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		bad, err := repository.prepareSignupDelivery(cancelled, verification, token, issued, deliveryConfig)
		_, planErr := bad.Plan()
		if !errors.Is(err, context.Canceled) || planErr == nil {
			t.Fatal("cancelled signup delivery retained custody or lost attribution")
		}
		message, err := repository.prepareSignupDelivery(ctx, verification, token, issued, deliveryConfig)
		if err != nil {
			t.Logf("delivery boundary: cancelled=%t deadline=%t link_budget=%t", errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), len(token) <= 2048-len(deliveryConfig.endpoint)-7)
			return err
		}
		originalDelivery, err = message.Plan()
		if err != nil {
			return err
		}
		deliveryWire, err = deliveryOwner.CheckpointPreparation(ctx, message, 1)
		return err
	})
	if err != nil {
		t.Fatal("real signed email grant changed its owned bindings", err)
	}
	fieldsForOutput, err := kernel.PasswordRegistrationFields(selected)
	if err != nil {
		t.Fatal(err)
	}
	originalCommand, err := identity.NewFeaturePasswordSignupInputCommand(identity.FeatureCommandSpec{Binding: b, Operation: passwordSignupOperation(), Fields: fieldsForOutput}, r.Password, r.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	primitiveService, _ := primitive.New(policy)
	hash, err := primitiveService.Hash(ctx, []byte("synthetic-signup-output"))
	if err != nil {
		t.Fatal(err)
	}
	riskConfig := signinTestRisk(t)
	admission := signinTestAdmissionWithConfig(t, ctx, b, riskConfig).Prepared()
	output := signupGeneratedOutput{Schema: 1, Hash: hash.String(), Admission: signupStoredAdmission(admission), Facts: append(admission.Signals, risk.Signal{Tenant: string(b.TenantID), Operation: "identity.password.signup", Attempt: string(b.CommandID), Name: "hibp", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: issued, ExpiresAt: issued.Add(time.Minute)}), Issuance: issuancePlan, IssuanceWire: issuanceWire, DeliveryWire: deliveryWire}
	sealed, err := repository.sealSignupOutput(ctx, crypto, "input", originalCommand, 1, config.profile, issuer, output)
	if err != nil || bytes.Contains(sealed, []byte(hash.String())) || bytes.Contains(sealed, []byte(r.Email)) {
		_, aadErr := signupOutputAAD(originalCommand, 1, config.profile)
		_, projectionErr := json.Marshal(signupOutputProjection(output))
		t.Logf("output boundary: aad_valid=%t shape_valid=%t json_valid=%t current_hash=%t issuer_plan_valid=%t", aadErr == nil, repository.validateSignupOutput(originalCommand, issuer, output) == nil, projectionErr == nil, signinCurrentHash(hash, policy), issuer.ValidateCapabilityIssuance(b, issuancePlan) == nil)
		t.Fatal("native generation output missing or disclosed verifier", err)
	}
	restored, err := repository.restoreSignupOutput(ctx, crypto, originalCommand, 1, config.profile, issuer, sealed)
	// Persistence preserves instants and signed data, not process-local time
	// locations/monotonic representations. Compare the complete canonical frame
	// and require the real risk owner to authenticate the restored original.
	want, wantErr := json.Marshal(signupOutputProjection(output))
	got, gotErr := json.Marshal(signupOutputProjection(restored))
	if err != nil || wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		t.Fatal("original verifier/facts/issuance changed on restart", err)
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(riskConfig)
	if err != nil {
		t.Fatal(err)
	}
	restoredAdmission, err := custody.Restore(ctx, risk.PreparedAuthenticationAdmission(restored.Admission), admission.Scope, risk.Subject{Network: "192.0.2.1", Device: "synthetic-device", IdentifierDigest: strings.Repeat("a", 64)})
	if err != nil || restoredAdmission.Check(ctx) != nil {
		t.Fatal("actual risk owner rejected restored original admission", err)
	}
	for _, change := range []func(*signupGeneratedOutput){
		func(out *signupGeneratedOutput) { out.Facts[0].State = risk.SignalDeny },
		func(out *signupGeneratedOutput) { out.Facts = out.Facts[1:] },
		func(out *signupGeneratedOutput) { out.Facts[len(out.Facts)-1].Name = "substitute" },
	} {
		bad := output
		bad.Facts = append([]risk.Signal(nil), output.Facts...)
		change(&bad)
		if wire, err := repository.sealSignupOutput(ctx, crypto, "input", originalCommand, 1, config.profile, issuer, bad); err == nil || wire != nil {
			t.Fatal("changed original screening facts could be sealed")
		}
	}
	recoveredIssuance, err := issuanceCodec.RestorePreparation(ctx, b, 1, restored.Issuance, restored.IssuanceWire)
	if err != nil {
		t.Fatal("actual issuer rejected restored original output", err)
	}
	if recoveredIssuance.TransferForDelivery(ctx, 0, func(context.Context, []byte) error { t.Error("restoration revealed bearer"); return nil }) == nil {
		t.Fatal("restored generation could redeliver original bearer")
	}
	restoredDelivery, err := deliveryOwner.RestorePreparation(ctx, b, 1, restored.DeliveryWire)
	if err != nil {
		t.Fatal("actual delivery owner rejected original encrypted message", err)
	}
	restoredPlan, err := restoredDelivery.Plan()
	originalPlanJSON, originalPlanErr := json.Marshal(originalDelivery)
	restoredPlanJSON, restoredPlanErr := json.Marshal(restoredPlan)
	if err != nil || originalPlanErr != nil || restoredPlanErr != nil || len(restoredPlan.Intents) != 1 || !bytes.Equal(originalPlanJSON, restoredPlanJSON) || !restoredPlan.Intents[0].ExpiresAt.Equal(verification.ExpiresAt) || restoredPlan.Intents[0].SubjectID != b.AnonymousFlowID {
		t.Fatal("delivery recovery replaced original effect, subject or expiry", err)
	}
	// The native original-generation owner, not application glue, must compose
	// HIBP-before-hash, verification issuance, encrypted delivery and one output.
	hashes, hibpCalls := 0, 0
	observedPrimitive, err := primitive.New(policy, primitive.WithObserver(signupHashObservation(func(event primitive.Observation) {
		if event.Operation == primitive.OperationHash {
			hashes++
			if hibpCalls != 1 {
				t.Error("signup hashed before the original HIBP decision")
			}
		}
	})))
	if err != nil {
		t.Fatal(err)
	}
	screeningPolicy := signupScreeningPolicy(t)
	generationConfig := signupGenerationPreparation{screening: password.HashPreparationConfig{Primitive: observedPrimitive, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: hash, Policy: screeningPolicy, Now: time.Now, Collect: func(ctx context.Context, scope risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
		hibpCalls++
		if hashes != 0 || borrowed.Len() != r.Password.Len() {
			t.Error("original screening received a replaced password or ran after hashing")
		}
		fact, err := screeningPolicy.PasswordSignal(ctx, scope, risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)})
		return []risk.Signal{fact}, err
	}}, verification: verificationConfig, delivery: deliveryConfig, codec: issuanceCodec, crypto: crypto, envelopeKey: "input", profile: config.profile}
	generated, err := repository.generateSignupOutput(ctx, originalCommand, selected, original, at, restoredAdmission, 2, generationConfig)
	if err != nil || len(generated) == 0 || hashes != 1 || hibpCalls != 1 {
		t.Logf("generation boundary: hashes=%d hibp_calls=%d", hashes, hibpCalls)
		t.Fatal("native original generation did not compose signup", err)
	}
	generatedOutput, err := repository.restoreSignupOutput(ctx, crypto, originalCommand, 2, config.profile, issuer, generated)
	if err != nil || len(generatedOutput.DeliveryWire) == 0 {
		t.Fatal("native generation omitted encrypted delivery", err)
	}
	if err := r.Password.Use(func(raw []byte) error {
		_, err := primitiveService.Verify(ctx, raw, generatedOutput.Hash)
		return err
	}); err != nil {
		t.Fatal("native generation changed the raw password", err)
	}
	if _, err := issuanceCodec.RestorePreparation(ctx, b, 2, generatedOutput.Issuance, generatedOutput.IssuanceWire); err != nil {
		t.Fatal("native generated original issuance could not restore", err)
	}
	if _, err := deliveryOwner.RestorePreparation(ctx, b, 2, generatedOutput.DeliveryWire); err != nil {
		t.Fatal("native generated original message could not restore", err)
	}
	if withUsername || len(consumers) > 0 {
		installNativeSignupExecutionHistory(t, ctx, pool, base)
		testNativePublicSignup(t, ctx, pool, policy, config, schema, keys, generationConfig, riskConfig, r, withUsername, consumers...)
		return
	}
	t.Run("native generated execution", func(t *testing.T) {
		testNativeSignupGeneratedExecution(t, ctx, pool, repository, domain, r, selected, original, key, storage, at, generationConfig, riskConfig, base)
	})
	t.Run("public signup", func(t *testing.T) {
		testNativePublicSignup(t, ctx, pool, policy, config, schema, keys, generationConfig, riskConfig, r, false)
	})
	for _, change := range []func(*identity.Command, *uint64, *[32]byte, *[]byte){
		func(_ *identity.Command, generation *uint64, _ *[32]byte, _ *[]byte) { *generation++ },
		func(_ *identity.Command, _ *uint64, profile *[32]byte, _ *[]byte) { profile[0]++ },
		func(_ *identity.Command, _ *uint64, _ *[32]byte, wire *[]byte) { (*wire)[len(*wire)-1] ^= 1 },
		func(command *identity.Command, _ *uint64, _ *[32]byte, _ *[]byte) {
			spec, _ := command.PasswordSignupInputFeature()
			spec.Binding.PolicyVersion++
			*command, _ = identity.NewFeaturePasswordSignupInputCommand(spec, r.Password, r.Cookie)
		},
	} {
		command, generation, profile, ciphertext := originalCommand, uint64(1), config.profile, bytes.Clone(sealed)
		change(&command, &generation, &profile, &ciphertext)
		bad, err := repository.restoreSignupOutput(ctx, crypto, command, generation, profile, issuer, ciphertext)
		if err == nil || bad.Hash != "" || bad.IssuanceWire != nil {
			t.Fatal("changed generation output retained authority")
		}
	}
	// Even loss of the live flow cannot cause a matching replay to reselect a
	// user, run field preparation or substitute a newer primary observation.
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM signin_sessions.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(r.TenantID), string(r.PreAuthID)); err != nil {
		t.Fatal(err)
	}
	phase.config.selectUser = func(context.Context) (identity.UserID, error) {
		t.Error("matching replay reselected account")
		return "", password.ErrPasswordWork
	}
	again, replay, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, r.Caller, feature, phase)
	if err != nil || again != bound || !bytes.Equal(replay, wire) || selections.Load() != 1 {
		t.Fatal("original immutable mapping did not replay", err)
	}
	r.Email = "different@example.test"
	changed, err := repository.signupRequestIntent(ctx, r, [32]byte{1}, config.profile, registration)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, changed, r.Caller, feature, phase)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatal("changed signup input did not conflict")
	}
	var created int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(selected.Creation.Binding.UserID)).Scan(&created); err != nil || created != 0 {
		t.Fatal("request preparation created account")
	}
}
