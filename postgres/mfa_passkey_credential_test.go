package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestMFAPasskeyCredentialRequiresProtectedNativeScope(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context()} {
		if now, err := (Work{}).RequireMFAPasskeyPreparationCredential(ctx, nil, identity.Command{}, CredentialAdmission{}); err == nil || !now.IsZero() {
			t.Fatal("unowned preparation exposed credential authority")
		}
		if now, err := (Work{}).RequireMFAPasskeyCredential(ctx, nil, CredentialAdmission{}); err == nil || !now.IsZero() {
			t.Fatal("unowned completion exposed credential authority")
		}
		if now, err := (MFATOTPAttemptWork{}).RequirePasskeyCredential(ctx, nil, CredentialAdmission{}); err == nil || !now.IsZero() {
			t.Fatal("unowned counted attempt exposed credential authority")
		}
	}
}

func TestMFAPasskeyCredentialKeepsOriginalAnonymousCommand(t *testing.T) {
	b, p := mfaCompletionPlanFixture(t, "totp-verify")
	expected := CredentialAdmission{Credential: identity.CredentialRef{ID: "passkey-a", TenantID: b.TenantID, UserID: p.MFACompletion.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
	selected, err := mfaPasskeyCredentialBinding(b, *p.MFACompletion, expected)
	if err != nil || selected.UserID != p.MFACompletion.UserID || b.UserID != "" {
		t.Fatal("selected eligibility changed original anonymous binding", err)
	}
	selected.UserID = ""
	if selected != b {
		t.Fatal("credential eligibility retargeted another command field")
	}
	for _, mutate := range []func(*identity.CommandBinding, *CredentialAdmission){
		func(b *identity.CommandBinding, _ *CredentialAdmission) { b.UserID = p.MFACompletion.UserID },
		func(b *identity.CommandBinding, _ *CredentialAdmission) { b.AnonymousFlowID = "" },
		func(b *identity.CommandBinding, _ *CredentialAdmission) { b.OperationID = "identity.mfa.otp-verify" },
		func(b *identity.CommandBinding, _ *CredentialAdmission) { b.SchemaID = "mfa-totp-step-up" },
		func(b *identity.CommandBinding, _ *CredentialAdmission) { b.SchemaVersion++ },
		func(_ *identity.CommandBinding, c *CredentialAdmission) { c.Credential.UserID = "other-user" },
		func(_ *identity.CommandBinding, c *CredentialAdmission) { c.Credential.TenantID = "other-tenant" },
		func(_ *identity.CommandBinding, c *CredentialAdmission) {
			c.Credential.Kind = identity.CredentialPassword
		},
		func(_ *identity.CommandBinding, c *CredentialAdmission) { c.Credential.Owner = "identity/password" },
		func(_ *identity.CommandBinding, c *CredentialAdmission) { c.UserAuthorityVersion = 0 },
		func(_ *identity.CommandBinding, c *CredentialAdmission) { c.IdentifierAuthorityVersion = 0 },
		func(_ *identity.CommandBinding, c *CredentialAdmission) { c.CredentialAuthorityVersion = 0 },
	} {
		input, credential := b, expected
		mutate(&input, &credential)
		if selected, err := mfaPasskeyCredentialBinding(input, *p.MFACompletion, credential); err == nil || selected != (identity.CommandBinding{}) {
			t.Fatal("unrelated credential or command admitted")
		}
	}
}

func TestMFAPasskeyPreparationRejectsForeignPhaseOrCommand(t *testing.T) {
	b, p := mfaCompletionPlanFixture(t, "totp-verify")
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
	for _, mode := range []string{"nil-context", "foreign-owner", "returned", "foreign-command", "missing-plan", "foreign-binding", "apply", "consumed", "finalized", "missing-continuation", "wrong-purpose", "wrong-child", "multiple-uses"} {
		t.Run(mode, func(t *testing.T) {
			owner := &mfaCompletionValidationParticipant{}
			capability := *p.Capability
			plan := &admittedKernelPlan{binding: b, feature: p.Feature, mfaCompletion: p.MFACompletion, capability: &capability}
			w := Work{state: &workState{ctx: t.Context(), binding: b, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featurePreparationCommand: &command, featurePreparationPlan: plan}}
			candidate, submitted, ctx := owner, command, context.Context(t.Context())
			switch mode {
			case "nil-context":
				ctx = nil
			case "foreign-owner":
				candidate = &mfaCompletionValidationParticipant{}
			case "returned":
				w.state.featureInvocation = nil
			case "foreign-command":
				submitted = identity.Command{}
			case "missing-plan":
				w.state.featurePreparationPlan = nil
			case "foreign-binding":
				plan.binding.UserID = "other-user"
			case "apply":
				w.state.featureApplying = true
			case "consumed":
				w.state.mfaConsumed = true
			case "finalized":
				w.state.mfaFinalized = true
			case "missing-continuation":
				plan.mfaCompletion = nil
			case "wrong-purpose":
				capability.Purpose = "identity.magic-link.consume"
			case "wrong-child":
				capability.CapabilityID = "other-child"
			case "multiple-uses":
				capability.MaxUses = 2
			}
			if now, err := w.RequireMFAPasskeyPreparationCredential(ctx, candidate, submitted, CredentialAdmission{}); err == nil || !now.IsZero() || w.state.failed == nil || w.state.sqlStarted {
				t.Fatal("foreign preparation acquired credential authority or escaped poisoned Work")
			}
		})
	}
}
