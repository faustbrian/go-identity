package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// These trusted-storage projections do not authenticate an assertion or TOTP.
// The separate native completion must prove both before persisting this record.
func passkeyMFAProjectionFixture(t *testing.T, csrf bool) (identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	command, password := mfaCompletionMappingProfile(t, csrf, true)
	spec, err := password.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	actual, _, _ := passkeySessionFixture(t)
	passkey, _ := actual.Bindings()
	originalAuthentication := spec.Authentication
	spec.Authentication = passkey.Authentication
	spec.Authentication.Proof.ID = originalAuthentication.Proof.ID
	spec.Authentication.Proof.IssuedAt = originalAuthentication.Proof.IssuedAt
	spec.Authentication.Proof.ExpiresAt = originalAuthentication.Proof.ExpiresAt
	spec.Authentication.Proof.Purpose = session.PasskeyMFAPrimaryPurpose
	authority, _ := spec.Authority.Bindings()
	passkeyAuthority, _ := passkey.Authority.Bindings()
	authority.Passkey = passkeyAuthority.Passkey
	spec.Authority, err = session.NewAuthoritySnapshot(authority)
	if err != nil {
		t.Fatal(err)
	}
	var record session.Session
	if csrf {
		record, err = session.NewSessionWithPasskeyMFAAndCSRF(spec, password.MFAAuthentication(), password.CSRFState())
	} else {
		record, err = session.NewSessionWithPasskeyMFA(spec, password.MFAAuthentication())
	}
	if err != nil {
		t.Fatal(err)
	}
	return command, record
}

func TestPasskeyMFANativeProjectionPreservesOriginalCustody(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		command, original := passkeyMFAProjectionFixture(t, csrf)
		encoded, _, err := encodeRecord(original)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := decodeRecord(encoded)
		if err != nil {
			t.Fatal("completed passkey/TOTP stored record denied", err)
		}
		got, _, err := encodeRecord(restored)
		if err != nil || !bytes.Equal(encoded, got) {
			t.Fatal("stored projection lost original primary, factor or synchronizer", err)
		}
		command.Fields, err = MFATOTPCompletionSessionFields(original)
		if err != nil {
			t.Fatal("passkey/TOTP command projection denied", err)
		}
		frozen, err := identity.NewFeatureCommand(command)
		if err != nil {
			t.Fatal(err)
		}
		restored, err = MFATOTPCompletionSession(frozen)
		if err != nil {
			t.Fatal("completed passkey/TOTP command denied", err)
		}
		got, _, err = encodeRecord(restored)
		if err != nil || !bytes.Equal(encoded, got) {
			t.Fatal("command projection lost original primary, factor or synchronizer", err)
		}
		for i := range command.Fields {
			partial := command
			partial.Fields = append(command.Fields[:i:i], command.Fields[i+1:]...)
			input, err := identity.NewFeatureCommand(partial)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MFATOTPCompletionSession(input); err == nil {
				t.Fatal("partial passkey/TOTP projection downgraded original custody")
			}
		}
		if _, err := MFAOTPCompletionSessionFields(original); err == nil {
			t.Fatal("passkey/TOTP projection relabeled as secondary OTP")
		}
		if _, err := MFARecoveryCompletionSessionFields(original); err == nil {
			t.Fatal("passkey/TOTP projection relabeled as recovery code")
		}
	}
}
