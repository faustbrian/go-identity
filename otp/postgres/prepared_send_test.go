package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func preparedSendFixture(t *testing.T) (*Contributor, identity.Command, kernel.CommandPlan) {
	t.Helper()
	phase, generated, _ := issuancePhaseFixture(t)
	custody, _, err := phase.store.authenticateIssuance(context.Background(), generated)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := custody.challenge.Bindings()
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "verification", Body: "{{.code}}", ContentType: "text/plain"}})
	if err != nil {
		t.Fatal(err)
	}
	config := preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: s.Policy, Verifier: phase.store.codec.verifier, Renderer: renderer, TemplateID: "otp-code", TemplateVersion: 1, LocaleChain: []string{"en"}}, provider: 1, contributors: []kernel.ContributorDescriptor{phase.store.Descriptor(), phase.delivery.Descriptor()}, templates: preparedSendTemplates("{{.code}}")}
	p, err := newPreparedSendContributor(phase.store, phase.delivery, config)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := generated.Feature()
	bearer, _ := generated.SessionToken()
	command, err := p.mapPreparedSendRequest(context.Background(), sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: custody.authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt}, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.preparedSendPlan(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, command, plan
}

func TestPreparedSendStableOwnerGeneratesAndRestoresOriginal(t *testing.T) {
	p, original, declaration := preparedSendFixture(t)
	var stable kernel.FeaturePreparationContributor = p
	if err := stable.ValidateFeaturePreparation(original, declaration); err != nil {
		t.Fatal(err)
	}
	wire, err := stable.GenerateFeaturePreparation(context.Background(), original, 1)
	if err != nil || len(wire) == 0 {
		t.Fatal("generation did not produce retained custody", err)
	}
	bearer, _ := original.SessionToken()
	if bytes.Contains(wire, []byte(bearer.Token())) {
		t.Fatal("output retained bearer")
	}
	generated, final, err := stable.RestoreFeaturePreparation(context.Background(), original, 1, wire)
	if err != nil || final.Delivery == nil {
		t.Fatal("restoration lost final effect", err)
	}
	if err := p.ValidateFeatureCommand(generated, final); err != nil {
		t.Fatal("stable owner rejected generated command", err)
	}
	if !reflect.DeepEqual(declaration.Audits, final.Audits) || !reflect.DeepEqual(append(declaration.Contributors, p.send.delivery.Descriptor()), final.Contributors) || *declaration.Lifecycle != *final.Lifecycle {
		t.Fatal("restoration rewrote original declaration")
	}
	second, secondPlan, err := stable.RestoreFeaturePreparation(context.Background(), original, 1, wire)
	a, _ := generated.Feature()
	b, _ := second.Feature()
	if err != nil || !reflect.DeepEqual(a, b) || !reflect.DeepEqual(final, secondPlan) {
		t.Fatal("retry remapped retained output", err)
	}
	if _, _, err := stable.RestoreFeaturePreparation(context.Background(), original, 2, wire); err == nil {
		t.Fatal("renewed generation accepted")
	}
	// No request-specific preparation handle survives restart composition.
	fresh, err := newPreparedSendContributor(p, issuanceDeliveryOwner(t), preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: p.send.policy, Renderer: p.send.renderer, TemplateID: p.send.template, TemplateVersion: p.send.templateVersion, LocaleChain: p.send.locales}, provider: p.send.provider, contributors: p.send.contributors, templates: preparedSendTemplates("{{.code}}")})
	if err != nil {
		t.Fatal(err)
	}
	resumed, resumedPlan, err := fresh.RestoreFeaturePreparation(context.Background(), original, 1, wire)
	resumedSpec, _ := resumed.Feature()
	if err != nil || !reflect.DeepEqual(a, resumedSpec) || !reflect.DeepEqual(final, resumedPlan) {
		t.Fatal("fresh owner did not conserve original output", err)
	}
	if _, err := stable.ApplyFeature(context.Background(), kernel.Work{}, generated); err == nil {
		t.Fatal("unowned final Work accepted")
	}
}

func TestPreparedSendRejectsChangedOriginalAndCancellation(t *testing.T) {
	p, original, _ := preparedSendFixture(t)
	wire, err := p.GenerateFeaturePreparation(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := original.Feature()
	bearer, _ := original.SessionToken()
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Bytes[len(s.Fields[0].Value.Bytes)-1] ^= 1 },
		func(s *identity.FeatureCommandSpec) { s.Fields[1].Value.Bytes[0] ^= 1 },
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other" },
	} {
		s, _ := original.Feature()
		change(&s)
		c, err := identity.NewFeatureSessionCommand(s, bearer)
		if err == nil {
			if _, _, err := p.RestoreFeaturePreparation(context.Background(), c, 1, wire); err == nil {
				t.Fatal("changed request adopted output")
			}
		}
	}
	wrong, err := identity.NewFeatureSessionCommand(spec, auth.NewBearerCredential("unrelated"))
	if err == nil {
		if _, _, err := p.RestoreFeaturePreparation(context.Background(), wrong, 1, wire); err == nil {
			t.Fatal("output invented bearer possession")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.GenerateFeaturePreparation(ctx, original, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("generation lost cancellation", err)
	}
	if _, _, err := p.RestoreFeaturePreparation(ctx, original, 1, wire); !errors.Is(err, context.Canceled) {
		t.Fatal("restoration lost cancellation", err)
	}
	r, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	r.expiresAt = r.expiresAt.Add(-time.Microsecond)
	changed, err := p.mapPreparedSendRequest(context.Background(), r, spec.Binding, bearer)
	if err != nil {
		t.Fatal("valid changed request could not be mapped", err)
	}
	if _, _, err := p.RestoreFeaturePreparation(context.Background(), changed, 1, wire); err == nil {
		t.Fatal("valid changed original expiry adopted retained output")
	}
	alteredRenderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "verification", Body: "different {{.code}}", ContentType: "text/plain"}})
	if err != nil {
		t.Fatal(err)
	}
	altered, err := newPreparedSendContributor(p, p.send.delivery, preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: p.send.policy, Renderer: alteredRenderer, TemplateID: p.send.template, TemplateVersion: p.send.templateVersion, LocaleChain: p.send.locales}, provider: p.send.provider, contributors: p.send.contributors, templates: preparedSendTemplates("different {{.code}}")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := altered.RestoreFeaturePreparation(context.Background(), original, 1, wire); err == nil {
		t.Fatal("changed same-version template reinterpreted original output")
	}
}

func TestPreparedSendRejectsTemplateProbeCollision(t *testing.T) {
	p, original, _ := preparedSendFixture(t)
	wire, err := p.GenerateFeaturePreparation(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, _ := p.send.policy.Bindings()
	template := delivery.Template{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "verification", Body: strings.Repeat(profile.Alphabet[:1], profile.Length), ContentType: "text/plain"}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	alternative, err := newPreparedSendContributor(p, p.send.delivery, preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: p.send.policy, Renderer: renderer, TemplateID: p.send.template, TemplateVersion: p.send.templateVersion, LocaleChain: p.send.locales}, provider: p.send.provider, contributors: p.send.contributors, templates: []delivery.Template{template}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := alternative.RestoreFeaturePreparation(context.Background(), original, 1, wire); err == nil {
		t.Fatal("probe-equivalent literal template adopted original request")
	}
	r, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := original.Feature()
	bearer, _ := original.SessionToken()
	if _, err := alternative.mapPreparedSendRequest(context.Background(), r, spec.Binding, bearer); err == nil {
		t.Fatal("literal-only OTP template admitted new generation input")
	}
	var previous []byte
	var prior identity.Command
	for _, body := range []string{"{{.code}}0", "0{{.code}}"} {
		owner, err := newPreparedSendContributor(p, p.send.delivery, preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: p.send.policy, TemplateID: p.send.template, TemplateVersion: p.send.templateVersion, LocaleChain: p.send.locales}, provider: p.send.provider, contributors: p.send.contributors, templates: preparedSendTemplates(body)})
		if err != nil {
			t.Fatal(err)
		}
		request, err := owner.mapPreparedSendRequest(context.Background(), r, spec.Binding, bearer)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil {
			if _, _, err := owner.RestoreFeaturePreparation(context.Background(), prior, 1, previous); err == nil {
				t.Fatal("probe-equivalent substitution position adopted original request")
			}
			continue
		}
		previous, err = owner.GenerateFeaturePreparation(context.Background(), request, 1)
		if err != nil {
			t.Fatal(err)
		}
		prior = request
	}
}

func preparedSendTemplates(body string) []delivery.Template {
	return []delivery.Template{{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "verification", Body: body, ContentType: "text/plain"}}
}

func TestPreparedSendRejectsSubmittedCode(t *testing.T) {
	p, original, declaration := preparedSendFixture(t)
	spec, _ := original.Feature()
	bearer, _ := original.SessionToken()
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	submitted, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateFeaturePreparation(submitted, declaration); err == nil {
		t.Fatal("Send accepted a submitted code instead of code-free intent")
	}
	if _, err := p.GenerateFeaturePreparation(context.Background(), submitted, 1); err == nil {
		t.Fatal("Send generated output for a code-bearing request")
	}
}
