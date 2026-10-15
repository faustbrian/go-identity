package mfapostgres

import (
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestRecoveryComparisonPreservesEnrollmentBindingAndSingleUse(t *testing.T) {
	keys, err := NewRecoveryVerificationKeys(map[uint32][32]byte{1: {1}})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewRecoveryCode("synthetic-recovery-code")
	m := RecoverySetMetadata{TenantID: "AAAAAAAAAAAAAAAAAAAAAQ", UserID: "AAAAAAAAAAAAAAAAAAAAAg", FactorID: "AAAAAAAAAAAAAAAAAAAAAw", SetID: "AAAAAAAAAAAAAAAAAAAAAw", SetVersion: 1, RowVersion: 1, KeyVersion: 1, CodeCount: 1}
	binding, err := enrollmentRecoveryBinding(PendingTOTPMetadata{TenantID: m.TenantID, UserID: m.UserID, FactorID: m.FactorID})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := code.KeyedDigest([32]byte{1}, binding)
	if err != nil {
		t.Fatal(err)
	}
	rows := []recoveryCodeRow{{set: m, digest: digest}}
	index, found, err := compareRecoveryCodes(t.Context(), keys, code, rows)
	if err != nil || !found || index != 0 {
		t.Fatal("existing enrollment digest did not verify unchanged", err)
	}
	rows[0].consumed = true
	if _, found, err := compareRecoveryCodes(t.Context(), keys, code, rows); err != nil || found {
		t.Fatal("consumed recovery code authenticated", err)
	}
	rows[0].consumed = false
	for _, change := range []func(*RecoverySetMetadata){
		func(m *RecoverySetMetadata) { m.TenantID = "AAAAAAAAAAAAAAAAAAAABA" },
		func(m *RecoverySetMetadata) { m.UserID = "AAAAAAAAAAAAAAAAAAAABA" },
		func(m *RecoverySetMetadata) { m.FactorID = "AAAAAAAAAAAAAAAAAAAABA" },
		func(m *RecoverySetMetadata) { m.SetID = "AAAAAAAAAAAAAAAAAAAABA" },
		func(m *RecoverySetMetadata) { m.SetVersion++ },
	} {
		changed := append([]recoveryCodeRow(nil), rows...)
		change(&changed[0].set)
		if _, found, err := compareRecoveryCodes(t.Context(), keys, code, changed); err != nil || found {
			t.Fatal("foreign/rotated set authenticated existing code", err)
		}
	}
	rows[0].set.KeyVersion = 2
	if _, _, err := compareRecoveryCodes(t.Context(), keys, code, rows); err == nil {
		t.Fatal("missing retained key treated as ordinary bad code")
	}
	if _, err := NewRecoveryVerificationKeys(map[uint32][32]byte{1: {}}); err == nil {
		t.Fatal("zero key admitted")
	}
	if _, _, err := compareRecoveryCodes(nil, keys, code, rows); err == nil {
		t.Fatal("nil context admitted")
	}
}

func TestRecoveryStorageRequiresActualNativeCustody(t *testing.T) {
	if _, err := (LockedRecoveryAttempt{}).MatchedSet(); err == nil {
		t.Fatal("zero comparison disclosed selected set")
	}
	if _, _, err := CompareRecoveryAttempt(t.Context(), kernel.MFARecoveryAttemptWork{}, nil, RecoveryVerificationKeys{}); err == nil {
		t.Fatal("zero counted work compared recovery credentials")
	}
	if err := RecordRecoveryAttemptDenial(t.Context(), kernel.MFARecoveryAttemptWork{}, nil, LockedRecoveryAttempt{}); err == nil {
		t.Fatal("zero counted work charged recovery budget")
	}
	if _, err := LockRecoveryCompletion(t.Context(), kernel.Work{}, nil, identity.Command{}, RecoveryVerificationKeys{}); err == nil {
		t.Fatal("zero protected work locked recovery credentials")
	}
	if err := RecordRecoveryCompletion(t.Context(), kernel.Work{}, nil, LockedRecoveryCompletion{}); err == nil {
		t.Fatal("zero protected work consumed recovery code")
	}
}
