package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

// This fixture exercises only the private successor mapper. It neither creates
// a usable Work nor proves a persisted reset or authenticated OTP invocation.
func phoneResetSuccessorFixture(t *testing.T) (Work, identity.CommandBinding, CredentialAdmission) {
	t.Helper()
	command, plan := phoneResetPlanFixture(t)
	spec, _ := command.PhonePasswordResetFeature()
	intent, err := decodeCredentialReset(spec)
	if err != nil {
		t.Fatal(err)
	}
	replacement := intent.Replacement
	successor := replacement.Credential
	successor.Version++
	receipt := &CredentialReplacementReceipt{Credential: successor,
		BeforeUserVersion: replacement.ExpectedUserVersion, AfterUserVersion: replacement.ExpectedUserVersion + 1,
		BeforeAuthorityVersion: replacement.ExpectedAuthorityVersion, AfterAuthorityVersion: replacement.ExpectedAuthorityVersion + 1,
		BeforeCredentialVersion: replacement.Credential.Version}
	w := Work{state: &workState{binding: spec.Binding, feature: plan.Feature,
		resetIntent: &intent, replacementIntent: &replacement, replacementReceipt: receipt, resetApplied: true}}
	return w, spec.Binding, CredentialAdmission{Credential: replacement.Credential,
		UserAuthorityVersion: 3, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: replacement.ExpectedAuthorityVersion}
}

func TestPhoneResetMapsOnlyItsOwnPersistedPasswordSuccessor(t *testing.T) {
	w, binding, original := phoneResetSuccessorFixture(t)
	want := original
	want.Credential = w.state.replacementReceipt.Credential
	want.CredentialAuthorityVersion = w.state.replacementReceipt.AfterAuthorityVersion
	got, err := otpMutationCredential(w, binding, original)
	if err != nil || got != want {
		t.Fatal("OTP finalization cannot recognize its own reset successor", err)
	}
	before := UserAuthorityAdmission{UserAuthorityVersion: original.UserAuthorityVersion,
		IdentifierAuthorityVersion: original.IdentifierAuthorityVersion, CredentialAuthorityVersion: original.CredentialAuthorityVersion}
	after := before
	after.CredentialAuthorityVersion = want.CredentialAuthorityVersion
	if got, err := otpMutationUser(w, binding, before); err != nil || got != after {
		t.Fatal("reset mapped an aggregate version to a security epoch or lost its credential successor", err)
	}
	if original.Credential.Version != w.state.replacementReceipt.BeforeCredentialVersion || original.CredentialAuthorityVersion != w.state.replacementReceipt.BeforeAuthorityVersion {
		t.Fatal("mapping mutated the original admission")
	}
	for name, mutate := range map[string]func(*workState, *identity.CommandBinding, *CredentialAdmission){
		"foreign invocation":         func(_ *workState, b *identity.CommandBinding, _ *CredentialAdmission) { b.CommandID = "foreign" },
		"foreign user":               func(_ *workState, b *identity.CommandBinding, _ *CredentialAdmission) { b.UserID = "foreign" },
		"foreign credential":         func(_ *workState, _ *identity.CommandBinding, a *CredentialAdmission) { a.Credential.ID = "foreign" },
		"newer original reference":   func(_ *workState, _ *identity.CommandBinding, a *CredentialAdmission) { a.Credential.Version++ },
		"newer original epoch":       func(_ *workState, _ *identity.CommandBinding, a *CredentialAdmission) { a.CredentialAuthorityVersion++ },
		"missing receipt":            func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) { s.replacementReceipt = nil },
		"missing reset intent":       func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) { s.resetIntent = nil },
		"missing replacement intent": func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) { s.replacementIntent = nil },
		"different reset intent": func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) {
			s.resetIntent.Replacement.ExpectedAuthorityVersion++
		},
		"foreign receipt": func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) {
			s.replacementReceipt.Credential.TenantID = "foreign"
		},
		"skipped credential version": func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) {
			s.replacementReceipt.Credential.Version++
		},
		"skipped credential epoch": func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) {
			s.replacementReceipt.AfterAuthorityVersion++
		},
		"skipped aggregate version": func(s *workState, _ *identity.CommandBinding, _ *CredentialAdmission) {
			s.replacementReceipt.AfterUserVersion++
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, b, admission := phoneResetSuccessorFixture(t)
			mutate(candidate.state, &b, &admission)
			if _, err := otpMutationCredential(candidate, b, admission); err == nil {
				t.Fatal("reset mapped a foreign or unproven successor")
			}
		})
	}
	w.state.resetApplied = false
	if got, err := otpMutationCredential(w, binding, original); err != nil || got != original {
		t.Fatal("pre-mutation OTP check renewed original authority")
	}
	w, binding, original = phoneResetSuccessorFixture(t)
	w.state.feature.Operation = credentialResetOperation()
	if got, err := otpMutationCredential(w, binding, original); err != nil || got != original {
		t.Fatal("ordinary emailed reset borrowed the phone successor mapping")
	}
}
