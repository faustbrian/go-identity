package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func mfaLoginRequestSeed(t testing.TB) (sendRequestRecord, identity.CommandBinding) {
	t.Helper()
	_, original, _, correlation := mfaAttemptRecordFixture(t)
	s, _ := mfaIssuanceRecordSeed(t).Bindings()
	b, _ := s.Continuation.Bindings()
	op := mfaLoginSendOperation()
	binding := original.Binding
	binding.OperationID, binding.SchemaID, binding.RecordID = op.OperationID, op.SchemaID, "BQUFBQUFBQUFBQUFBQUFBQ"
	b.Scope.AuthorizationBinding, b.Scope.ChallengeID = [32]byte{}, string(binding.CommandID)
	continuation, err := otp.NewContinuation(b.Scope, b.Authorization, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery{TenantID: binding.TenantID, UserID: correlation.SubjectID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: correlation.SubjectID, TenantID: binding.TenantID, Status: identity.StatusActive, Version: 1},
		Identifier:           identity.Identifier{ID: "email", UserID: correlation.SubjectID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Verified: true, Version: 1},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: s.IssuedAt, Version: 1},
		UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1, ObservedAt: s.IssuedAt}
	return sendRequestRecord{continuation: continuation, policy: s.Policy, authority: AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: binding.TenantID}, GlobalVersion: 1, TenantVersion: 1}}, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt, recipient: &recipient}, binding
}

func TestMFALoginSendRecordRejectsTruncationAndScopeSubstitution(t *testing.T) {
	record, binding := mfaLoginRequestSeed(t)
	wire, err := encodeSendRequestRecord(record, binding)
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := decodeSendRequestRecord(wire, binding); err != nil {
		t.Fatal("valid MFA send profile rejected", err)
	} else if again, err := encodeSendRequestRecord(restored, binding); err != nil || !bytes.Equal(again, wire) {
		t.Fatal("MFA send bytes changed on restoration", err)
	}
	for n := range len(wire) {
		if _, err := decodeSendRequestRecord(wire[:n], binding); err == nil {
			t.Fatal("truncated MFA send admitted")
		}
	}
	if _, err := decodeSendRequestRecord(append(bytes.Clone(wire), 0), binding); err == nil {
		t.Fatal("trailing MFA send admitted")
	}
	foreign := binding
	foreign.TenantID = "foreign"
	if _, err := decodeSendRequestRecord(wire, foreign); err == nil {
		t.Fatal("foreign tenant adopted MFA send custody")
	}
	if _, _, err := decodeAuthorityRecord(wire, binding); err == nil {
		t.Fatal("code-free MFA send became a consuming attempt")
	}
}

func FuzzMFALoginSendRecord(f *testing.F) {
	record, binding := mfaLoginRequestSeed(f)
	seed, err := encodeSendRequestRecord(record, binding)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := decodeSendRequestRecord(seed, binding); err != nil {
		f.Fatal("fuzz seed does not exercise valid MFA send", err)
	}
	f.Add(seed)
	f.Add([]byte(mfaSendRecipientRequestPrefix))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8193 {
			return
		}
		restored, err := decodeSendRequestRecord(data, binding)
		if err != nil {
			return
		}
		canonical, err := encodeSendRequestRecord(restored, binding)
		if err != nil || !bytes.Equal(data, canonical) {
			t.Fatal("noncanonical MFA send admitted")
		}
	})
}
