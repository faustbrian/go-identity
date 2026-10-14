package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func captchaUseCommandFixture(t *testing.T, flow risk.FlowContextInput, checkedAt ...time.Time) (risk.CaptchaEvidenceUse, risk.EvidenceKey, risk.CaptchaEvidenceIssuerConfig, identity.FeatureCommandSpec) {
	t.Helper()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	issue, key, cfg := captchaConfiguredFixture(t, flow, now, 2, 1)
	record, err := issue.Materialize(now.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	checked := now.Add(2 * time.Microsecond)
	if len(checkedAt) != 0 {
		checked = checkedAt[0]
	}
	cfg.Clock = func() time.Time { return checked }
	issuer, err := risk.NewCaptchaEvidenceIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f, err := risk.NewFlowContext(flow)
	if err != nil {
		t.Fatal(err)
	}
	b := captchaCommandBinding(issue.Prepared())
	b.CommandID, b.OperationID, b.RecordID, b.PolicyVersion = "AgICAgICAgICAgICAgICAg", string(flow.Operation), "protected-target", 17
	b.SchemaID, b.SchemaVersion = "protected-fixture-v1", 1
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: CaptchaIssueOperation(identity.FeatureSubjectUser).SubjectRequirement}
	if flow.AnonymousFlow != "" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	use, err := issuer.PrecheckUse(context.Background(), issue, risk.CaptchaEvidenceUseRequest{CommandID: string(b.CommandID), Actor: string(b.ActorID), Flow: f, Reference: record.Reference}, record)
	if err != nil {
		t.Fatal(err)
	}
	return use, key, cfg, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{uintField("expected-version", 4), textField("target", "protected-target")}}
}

func TestCaptchaUseNativePreservesSignedNanoseconds(t *testing.T) {
	checked := time.Date(2026, 10, 6, 12, 0, 0, 2001, time.UTC)
	use, key, _, spec := captchaUseCommandFixture(t, captchaFlowFixture(), checked)
	command, plan, err := MapCaptchaUse(use, spec)
	if err != nil {
		t.Fatal("valid nanosecond precheck cannot map", err)
	}
	claim, err := restoreCaptchaUseCommand(command, []risk.EvidenceKey{key}, 3)
	if err != nil || claim.Prepared().CheckedAt != checked || plan.CheckedAt != checked || !reflect.DeepEqual(claim.Prepared(), use.Prepared()) {
		t.Fatal("signed precision changed", err)
	}
	if claim.Validate(checked.Add(-time.Nanosecond)) == nil || claim.Validate(checked) != nil {
		t.Fatal("submicrosecond boundary changed")
	}
	for _, value := range []identity.FeatureValue{
		{Kind: identity.FeatureTime, Time: checked.Truncate(time.Microsecond)},
		{Kind: identity.FeatureText, Text: ""},
		{Kind: identity.FeatureText, Text: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{Kind: identity.FeatureText, Text: "2026-10-06T12:00:00.000002001+00:00"},
		{Kind: identity.FeatureText, Text: "2026-10-06T12:00:00.000002002Z"},
	} {
		native, _ := command.Feature()
		for i := range native.Fields {
			if native.Fields[i].Name == "captcha.use-checked-at" {
				native.Fields[i].Value = value
			}
		}
		altered, err := identity.NewFeatureCommand(native)
		if err != nil {
			t.Fatal("fixture did not reach closed codec", err)
		}
		if _, err := restoreCaptchaUseCommand(altered, []risk.EvidenceKey{key}, 3); err == nil {
			t.Fatal("altered/ambiguous signed instant accepted")
		}
	}
}

func TestCaptchaUseNativeMappingConservesProtectedCommand(t *testing.T) {
	for _, variant := range []string{"pre-auth-anonymous", "pre-auth-subject", "authenticated", "admin-subject", "admin-anonymous", "admin-session"} {
		t.Run(variant, func(t *testing.T) {
			flow := captchaFlowFixture()
			switch variant {
			case "pre-auth-subject":
				flow.Subject, flow.AnonymousFlow = "subject", ""
			case "authenticated":
				flow.Kind, flow.Subject, flow.AnonymousFlow, flow.PreAuthTransaction, flow.Session = risk.FlowAuthenticated, "subject", "", "", "session"
			case "admin-subject", "admin-anonymous", "admin-session":
				flow.Kind, flow.PreAuthTransaction, flow.Actor = risk.FlowAdministrator, "", "administrator"
				if variant != "admin-anonymous" {
					flow.Subject, flow.AnonymousFlow = "subject", ""
				}
				if variant == "admin-session" {
					flow.Session = "admin-session"
				}
			}
			use, key, _, spec := captchaUseCommandFixture(t, flow)
			command, plan, err := MapCaptchaUse(use, spec)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := command.Feature()
			if got.Binding != spec.Binding || got.Operation != spec.Operation {
				t.Fatal("protected native binding replaced")
			}
			for _, expected := range spec.Fields {
				found := false
				for _, field := range got.Fields {
					if reflect.DeepEqual(field, expected) {
						found = true
					}
				}
				if !found {
					t.Fatal("protected target/version field lost")
				}
			}
			claim, err := restoreCaptchaUseCommand(command, []risk.EvidenceKey{key}, 3)
			if err != nil || !reflect.DeepEqual(claim.Prepared(), use.Prepared()) {
				t.Fatal("consuming custody changed", err)
			}
			if plan != captchaUsePlan(use.Prepared()) || plan.PolicyVersion == spec.Binding.PolicyVersion {
				t.Fatal("risk and authorization policy conflated")
			}
			// Projection ownership must survive subsequent caller mutations.
			spec.Fields[0].Value.Uint64++
			again, _ := command.Feature()
			if !reflect.DeepEqual(got, again) {
				t.Fatal("command shares caller fields")
			}
		})
	}
}

func TestCaptchaUseNativeMappingRejectsSubstitution(t *testing.T) {
	use, key, _, spec := captchaUseCommandFixture(t, captchaFlowFixture())
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = "foreign" },
		func(s *identity.FeatureCommandSpec) {
			s.Binding.OperationID = "identity.password.reset"
			s.Operation.OperationID = s.Binding.OperationID
		},
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, textField("captcha.foreign", "foreign"))
		},
	} {
		wrong := spec
		wrong.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		mutate(&wrong)
		if _, _, err := MapCaptchaUse(use, wrong); err == nil {
			t.Fatal("native substitution accepted")
		}
	}
	if _, _, err := MapCaptchaUse(risk.CaptchaEvidenceUse{}, spec); err == nil {
		t.Fatal("zero use accepted")
	}
	command, _, err := MapCaptchaUse(use, spec)
	if err != nil {
		t.Fatal(err)
	}
	native, _ := command.Feature()
	for _, name := range []string{"captcha.use-signature", "captcha.signature", "captcha.proof", "captcha.use-evidence", "captcha.request", "captcha.issuance-command"} {
		altered, _ := command.Feature()
		for i := range altered.Fields {
			if altered.Fields[i].Name == name {
				if altered.Fields[i].Value.Kind == identity.FeatureBytes {
					altered.Fields[i].Value.Bytes[0] ^= 1
				} else {
					altered.Fields[i].Value.Text = "AwMDAwMDAwMDAwMDAwMDAw"
				}
			}
		}
		c, err := identity.NewFeatureCommand(altered)
		if err == nil {
			if _, err := restoreCaptchaUseCommand(c, []risk.EvidenceKey{key}, 3); err == nil {
				t.Fatal("altered native custody accepted", name)
			}
		}
	}
	native.Fields = append(native.Fields, textField("captcha.unknown", "foreign"))
	c, err := identity.NewFeatureCommand(native)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreCaptchaUseCommand(c, []risk.EvidenceKey{key}, 3); err == nil {
		t.Fatal("open custody schema accepted")
	}
	if _, err := restoreCaptchaUseCommand(command, []risk.EvidenceKey{key}, 4); err == nil {
		t.Fatal("foreign risk policy accepted")
	}
}

func TestCaptchaUseNativeSelectedProfileAndPlan(t *testing.T) {
	use, key, cfg, spec := captchaUseCommandFixture(t, captchaFlowFixture())
	command, plan, err := MapCaptchaUse(use, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Native admission must never execute caller code, including clocks.
	cfg.Clock = func() time.Time { panic("native admission called clock") }
	cfg.Verify = func(context.Context, risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
		panic("native admission called provider")
	}
	custody, err := risk.NewCaptchaEvidenceCustody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	repositoryConfig := Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", CaptchaCustody: []risk.CaptchaEvidenceCustody{custody}}
	r, err := NewRepository(repositoryConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateCaptchaUseCommand(command, plan); err != nil {
		t.Fatal("current native use rejected", err)
	}
	for _, mutate := range []func(*identitypostgres.CaptchaEvidencePlan){
		func(p *identitypostgres.CaptchaEvidencePlan) { p.IssuanceCommandID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.KeyVersion++ },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.PolicyVersion++ },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.OriginalSignature[0] ^= 1 },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.EvidenceDigest[0] ^= 1 },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.Signature[0] ^= 1 },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.IssuedAt = p.IssuedAt.Add(time.Microsecond) },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.CheckedAt = p.CheckedAt.Add(time.Microsecond) },
		func(p *identitypostgres.CaptchaEvidencePlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
	} {
		wrong := plan
		mutate(&wrong)
		if !errors.Is(r.ValidateCaptchaUseCommand(command, wrong), risk.ErrInvalidEvidenceExecution) {
			t.Fatal("substituted plan admitted")
		}
	}
	cfg.Hostnames = []string{"foreign.example"}
	foreign, err := risk.NewCaptchaEvidenceCustody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	repositoryConfig.CaptchaCustody = []risk.CaptchaEvidenceCustody{foreign}
	other, err := NewRepository(repositoryConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(other.ValidateCaptchaUseCommand(command, plan), risk.ErrInvalidEvidenceExecution) {
		t.Fatal("signature accepted foreign current profile")
	}
	if (&Repository{}).ValidateCaptchaUseCommand(command, plan) == nil || (*Repository)(nil).ValidateCaptchaUseCommand(command, plan) == nil {
		t.Fatal("zero native custody admitted")
	}
	if r.ValidateCaptchaUseCommand(identity.Command{}, plan) == nil {
		t.Fatal("zero command admitted")
	}
	// Restoring historical custody preserves expiry; it cannot renew it.
	claim, err := restoreCaptchaUseCommand(command, []risk.EvidenceKey{key}, 3)
	if err != nil || claim.Validate(plan.ExpiresAt) == nil || claim.Validate(plan.CheckedAt) != nil {
		t.Fatal("historical validity interval changed", err)
	}
}
