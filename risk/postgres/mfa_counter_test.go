package postgres

import (
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestNativeMFACompletionCounterPreparationPreservesOpaqueInput(t *testing.T) {
	testNativeMFACompletionCounterPreparation(t, "totp")
}

func TestNativeRecoveryCompletionCounterPreparationPreservesOpaqueInput(t *testing.T) {
	testNativeMFACompletionCounterPreparation(t, "recovery-code")
}

func TestNativeOTPCompletionCounterPreparationPreservesOpaqueInput(t *testing.T) {
	testNativeMFACompletionCounterPreparation(t, "otp")
}

func testNativeMFACompletionCounterPreparation(t *testing.T, method string) {
	t.Helper()
	recovery := method == "recovery-code"
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := protectedCommand(t, "mfa-tenant").Feature()
	s.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	if recovery {
		s.Operation.OperationID, s.Operation.SchemaID = "identity.mfa.recovery-use", "mfa-recovery-use"
		s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	} else if method == "otp" {
		s.Operation.OperationID, s.Operation.SchemaID = "identity.mfa.otp-verify", "mfa-otp-verify"
		s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	}
	s.Binding.UserID, s.Binding.RecordID, s.Binding.AnonymousFlowID = "", "", "bbbbbbbbbbbbbbbbbbbbbg"
	code, _ := auth.NewOneTimeCode("123456")
	cookie := auth.NewBearerCredential(strings.Repeat("A", 43))
	original, err := identity.NewFeatureOneTimeCodePreAuthCommand(s, code, cookie)
	recoveryCode, _ := auth.NewRecoveryCode("synthetic-recovery-code")
	if recovery {
		original, err = identity.NewFeatureRecoveryCodePreAuthCommand(s, recoveryCode, cookie)
	}
	if err != nil {
		t.Fatal(err)
	}
	child := kernel.CapabilityPlan{CapabilityID: "AgICAgICAgICAgICAgICAg", Purpose: "identity.mfa.complete", MaxUses: 1}
	completion := kernel.MFACompletionPlan{ID: identity.CommandID(child.CapabilityID), UserID: "subject", ScopeDigest: [32]byte{1}, PolicyVersion: 9, FactorVersion: 3, ContinuationVersion: 1}
	subject := risk.Subject{User: "subject", Network: "127.0.0.1"}
	at := time.Now().UTC().Truncate(time.Microsecond)
	mapped, plan, err := r.PrepareMFACompletionCommandCounters(original, subject, child, completion, at)
	if err != nil || r.ValidateCommandCounters(mapped, plan) != nil {
		t.Fatal("native MFA counters missing", err)
	}
	gotCode, ok := mapped.OneTimeCode()
	gotDigest, gotErr := gotCode.CommandDigest([32]byte{1}, "fixture-original-code")
	wantDigest, wantErr := code.CommandDigest([32]byte{1}, "fixture-original-code")
	if recovery {
		got, has := mapped.RecoveryCode()
		a, ae := got.KeyedDigest([32]byte{1}, []byte("fixture-original-recovery"))
		b, be := recoveryCode.KeyedDigest([32]byte{1}, []byte("fixture-original-recovery"))
		if !has || ok || ae != nil || be != nil || a != b {
			t.Fatal("counter mapping lost or coerced recovery code")
		}
	} else if !ok || gotErr != nil || wantErr != nil || gotDigest != wantDigest {
		t.Fatal("counter mapping lost original code")
	}
	if got, ok := mapped.PreAuthCookie(); !ok || got != cookie {
		t.Fatal("counter mapping lost original browser")
	}
	if _, _, err := r.PrepareCommandCounters(original, subject, at); err == nil {
		t.Fatal("ordinary mutation admitted anonymous MFA")
	}
	foreign := completion
	foreign.UserID = "other"
	if _, _, err := r.PrepareMFACompletionCommandCounters(original, subject, child, foreign, at); err == nil {
		t.Fatal("foreign continuation subject admitted")
	}
	child.CapabilityID = "AwMDAwMDAwMDAwMDAwMDAw"
	if _, _, err := r.PrepareMFACompletionCommandCounters(original, subject, child, completion, at); err == nil {
		t.Fatal("foreign child admitted")
	}
}
