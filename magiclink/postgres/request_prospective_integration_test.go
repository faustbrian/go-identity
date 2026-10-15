//go:build integration

package magiclinkpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Real signing/rendering/encrypted owner custody without a database mutation.
// Protected native collision/creation/session effects have separate PG evidence.
func TestProspectiveRequestPreparationRetainsOriginalCreation(t *testing.T) {
	ctx := context.Background()
	p, selected := signedRequestScopeFixture(t)
	spec, _ := p.original.Feature()
	spec.Binding.TenantID = requestTestTenant
	p.original, _ = identity.NewFeatureCommand(spec)
	f, _ := p.flow.Bindings()
	f.Binding.Intent.TenantID = requestTestTenant
	p.flow, _ = session.NewPreAuthTransaction(f)
	selected.recipient.Query.TenantID = requestTestTenant
	existingRecipient := selected.recipient
	existingRecipient.User.TenantID = requestTestTenant
	b := spec.Binding
	b.AnonymousFlowID, b.OperationID, b.UserID = "", "identity.user.create", selected.recipient.User.ID
	b.SchemaID, b.SchemaVersion = "signup-fields", 1
	i := selected.recipient.Identifier
	i.Version, i.Verified, i.Primary = 1, false, false
	creation := kernel.MagicLinkRegistrationIntent{Creation: identity.CreateUserCommand{Binding: b, Status: identity.StatusActive}, Identifier: i, ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 9}
	selected.prospective, selected.factor = &creation, 0
	selected.global, selected.tenant = 1, 1
	selected.recipient = kernel.RecipientRecord{Query: selected.recipient.Query, Suppressed: true}
	p.request.Intent = magiclink.SignupIfAllowed
	p.canonical, p.selected = i.CanonicalValue, selected
	config := p.service.config()
	limits := capability.DefaultLimits()
	limits.MaxCaveats = 18
	signer, _ := capability.NewHMACSHA256Signer("magic-test", bytes.Repeat([]byte{93}, 32))
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{93}, 32))
	resolver, _ := capability.NewKeySet([]capability.Key{{Issuer: config.IssuerURL, ID: "magic-test", Verifier: verifier}})
	config.Issuer = issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: config.IssuerURL, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: limits}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {97}}, PreparationTimeout: time.Second}
	config.IssuanceCustody = issuerpg.IssuancePreparationConfig{Deployment: "magic-test", ActiveEnvelopeKey: "magic-issuer", EnvelopeKeys: map[string][]byte{"magic-issuer": bytes.Repeat([]byte{98}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "magic-test", HMAC: bytes.Repeat([]byte{93}, 32)}}, Clock: time.Now}
	keys, _ := keyring.New(map[string][]byte{"magic-mail": bytes.Repeat([]byte{91}, 32)})
	crypto, _ := envelope.NewService(keys)
	mail, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "magic-mail", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {92}}, ActiveEnvelopeKeyID: "magic-mail", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "magic-link", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Sign in: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://app.test"}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	config.Delivery = RequestDeliveryConfig{Owner: mail, Renderer: renderer, Endpoint: "https://app.test/magic", TemplateID: "magic-link", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{100}, Timeout: time.Second}
	config.ActiveEnvelopeKeyID, config.Risk = "magic-mail", requestTestRisk(t)
	p.service.config = func() RequestConfig { return config }
	p.service.crypto = crypto
	p.service.issuer, err = issuerpg.NewIssuer(config.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	p.service.codec, err = issuerpg.NewIssuancePreparationCodec(p.service.issuer, config.IssuanceCustody)
	if err != nil {
		t.Fatal(err)
	}
	p.service.custody, err = risk.NewAuthenticationAdmissionCustody(config.Risk)
	if err != nil {
		t.Fatal(err)
	}
	p.subject = risk.Subject{Network: "192.0.2.1", Device: "synthetic-device", IdentifierDigest: strings.Repeat("a", 64)}
	scope := risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}
	evaluation, err := config.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.subject, Attribution: &risk.DecisionAttribution{CommandID: spec.Binding.CommandID, CorrelationID: spec.Binding.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(spec.Binding.CommandID)}})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := p.service.custody.Prepare(ctx, evaluation, scope, p.subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.generateDelivery(ctx, 1, admission); err == nil {
		t.Fatal("prospective issuance bypassed absent email possession policy")
	}
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "mailboxes", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	policyConfig := email.MagicLinkPossessionConfig{Address: email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization}, Issuer: config.IssuerURL, Audience: config.Issuer.Audience, MaximumLifetime: config.Lifetime, Callbacks: []string{p.request.Callback}, Version: 9}
	config.Possession, err = email.NewMagicLinkPossessionPolicy(policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	selectedPolicy := config.Possession
	for name, change := range map[string]func(*email.MagicLinkPossessionConfig){
		"wrong revision":   func(c *email.MagicLinkPossessionConfig) { c.Version++ },
		"foreign issuer":   func(c *email.MagicLinkPossessionConfig) { c.Issuer = "https://foreign.test" },
		"foreign audience": func(c *email.MagicLinkPossessionConfig) { c.Audience = "foreign" },
		"foreign callback": func(c *email.MagicLinkPossessionConfig) { c.Callbacks = []string{"https://app.test/foreign"} },
		"shorter lifetime": func(c *email.MagicLinkPossessionConfig) { c.MaximumLifetime = 30 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			changed := policyConfig
			change(&changed)
			config.Possession, err = email.NewMagicLinkPossessionPolicy(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.generateDelivery(ctx, 1, admission); err == nil {
				t.Fatal("real issuance bypassed selected mailbox acceptance")
			}
		})
	}
	config.Possession = selectedPolicy
	artifacts, err := p.generateDelivery(ctx, 1, admission)
	if err != nil {
		t.Fatal("prospective real issuer/delivery preparation unavailable", err)
	}
	defer clear(artifacts.issuanceWire)
	defer clear(artifacts.deliveryWire)
	wire, err := p.sealOutput(ctx, 1, selected, admission, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	restored, err := p.restoreOutput(ctx, 1, wire)
	if err != nil || restored.selected.prospective == nil || !reflect.DeepEqual(*restored.selected.prospective, creation) {
		t.Fatal("original prospective creation lost on encrypted restoration", err)
	}
	before, _ := artifacts.issuance.Plan()
	after, _ := restored.issuance.Plan()
	if !reflect.DeepEqual(before, after) || restored.selected.issued != selected.issued || restored.selected.expires != selected.expires || restored.selected.factor != 0 || !restored.selected.recipient.Suppressed {
		t.Fatal("restoration regenerated token, timeline or phantom authority")
	}
	if _, err := p.restoreOutput(ctx, 2, wire); err == nil {
		t.Fatal("foreign generation restored")
	}

	t.Run("signin origin and legacy restoration", func(t *testing.T) {
		p.request.Intent = magiclink.SignInOnly
		selected.prospective, selected.factor, selected.recipient = nil, 7, existingRecipient
		p.selected = selected
		artifacts, err := p.generateDelivery(ctx, 1, admission)
		if err != nil {
			t.Fatal("real signin preparation failed", err)
		}
		defer clear(artifacts.issuanceWire)
		defer clear(artifacts.deliveryWire)
		wire, err := p.sealOutput(ctx, 1, selected, admission, artifacts)
		if err != nil || !bytes.HasPrefix(wire, []byte(requestOriginPrefix)) {
			t.Fatal("signin lacks closed origin codec", err)
		}
		defer clear(wire)
		restored, err := p.restoreOutput(ctx, 1, wire)
		if err != nil || !reflect.DeepEqual(restored.selected.recipient, existingRecipient) {
			t.Fatal("signin origin lost original recipient", err)
		}
		before, _ := artifacts.issuance.Plan()
		after, _ := restored.issuance.Plan()
		if !reflect.DeepEqual(before, after) {
			t.Fatal("signin origin changed original signed custody")
		}
		// Reproduce the exact old codec, rather than relabel a new ciphertext.
		aad, err := p.outputAAD(1, false)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := envelope.ParseEnvelope(wire[len(requestOriginPrefix):])
		if err != nil {
			t.Fatal(err)
		}
		plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
		defer clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		var original storedOutput
		if json.Unmarshal(plain, &original) != nil || original.Schema != 2 || original.RequestSpec == nil {
			t.Fatal("complete command not retained inside authenticated origin")
		}
		defer clear(original.IssuanceWire)
		defer clear(original.DeliveryWire)
		original.Schema, original.RequestSpec = 1, nil
		legacyPlain, err := json.Marshal(original)
		defer clear(legacyPlain)
		if err != nil {
			t.Fatal(err)
		}
		legacyAAD, err := p.legacyOutputAAD(1)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: legacyPlain, Context: legacyAAD, KeyReference: config.ActiveEnvelopeKeyID})
		if err != nil {
			t.Fatal(err)
		}
		legacyWire, err := legacy.MarshalBinary()
		defer clear(legacyWire)
		if err != nil {
			t.Fatal(err)
		}
		restored, err = p.restoreOutput(ctx, 1, legacyWire)
		if err != nil || !reflect.DeepEqual(restored.selected.recipient, existingRecipient) {
			t.Fatal("legacy retry ciphertext no longer restores", err)
		}
		for _, candidate := range [][]byte{wire[len(requestOriginPrefix):], append([]byte(requestOriginPrefix), legacyWire...)} {
			if _, err := p.restoreOutput(ctx, 1, candidate); err == nil {
				t.Fatal("codec relabeling changed authenticated profile")
			}
		}
	})
}
