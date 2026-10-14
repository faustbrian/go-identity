package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestMFAPasswordTOTPCompletionEffectIsExplicitAndNative(t *testing.T) {
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	p := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "identity", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewMFAPasswordTOTPCompletionEffect(c, p)
	if err != nil || effect == nil {
		t.Fatal("password completion profile unavailable", err)
	}
	if _, err := effect.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedTOTPCompletion{}); err == nil {
		t.Fatal("session persisted without native factor completion")
	}
	p.AuthenticationMethod = "email-otp"
	if got, err := NewMFAPasswordTOTPCompletionEffect(c, p); err == nil || got != nil {
		t.Fatal("foreign primary profile accepted")
	}
	if _, err := json.Marshal(effect); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration exported", err)
	}
}

func TestMFAPasswordOTPCompletionEffectRequiresNativeSameWorkCompletion(t *testing.T) {
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	p := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "identity", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewMFAPasswordOTPCompletionEffect(c, p)
	if err != nil || effect == nil {
		t.Fatal("native password/OTP completion effect unavailable", err)
	}
	if _, err := effect.Apply(t.Context(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedOTPCompletion{}); err == nil {
		t.Fatal("OTP session persisted without actual checked/recorded completion")
	}
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if _, err := effect.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedOTPCompletion{}); !errors.Is(err, context.Canceled) {
		t.Fatal("OTP effect lost cancellation", err)
	}
	p.AuthenticationMethod = "email-otp"
	if e, err := NewMFAPasswordOTPCompletionEffect(c, p); err == nil || e != nil {
		t.Fatal("single-factor OTP substituted for original password authority")
	}
}

func TestMFATOTPCompletionEffectRequiresActualProtectedFactor(t *testing.T) {
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "identity"}
	effect, err := NewMFATOTPCompletionEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*MFATOTPCompletionEffect{nil, {}, effect} {
		if _, err := e.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedTOTPCompletion{}); err == nil {
			t.Fatal("projected session substituted real protected factor")
		}
		if _, err := e.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery accepted")
		}
	}
	if e, err := NewMFATOTPCompletionEffect(config, MagicLinkAdmissionConfig{}); err == nil || e != nil {
		t.Fatal("unconfigured directory authority accepted")
	}
	if fmt.Sprintf("%#v", effect) != "postgres.MFATOTPCompletionEffect(redacted)" {
		t.Fatal("MFA configuration disclosed")
	}
	if _, err := json.Marshal(effect); err == nil {
		t.Fatal("MFA configuration serialized")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := effect.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedTOTPCompletion{}); !errors.Is(err, context.Canceled) {
		t.Fatal("MFA effect lost cancellation", err)
	}
	if _, err := effect.Recover(ctx, kernel.RecoveryWork{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("MFA recovery lost cancellation", err)
	}
}

func TestMFARecoveryCompletionEffectRequiresRecordedNativeBurn(t *testing.T) {
	c := Config{Schema: "session_store", MaximumDuration: time.Second}
	magic, err := NewMFARecoveryCompletionEffect(c, MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "identity"})
	if err != nil {
		t.Fatal(err)
	}
	password, err := NewMFAPasswordRecoveryCompletionEffect(c, IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "identity", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"})
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range []*MFARecoveryCompletionEffect{nil, {}, magic, password} {
		if _, err := effect.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedRecoveryCompletion{}); err == nil {
			t.Fatal("session issued without recorded recovery burn")
		}
		if _, err := effect.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery evidence accepted")
		}
	}
	if fmt.Sprintf("%#v", password) != "postgres.MFARecoveryCompletionEffect(redacted)" {
		t.Fatal("recovery profile disclosed")
	}
	if _, err := json.Marshal(password); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("recovery profile serialized", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := password.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, mfapg.LockedRecoveryCompletion{}); !errors.Is(err, context.Canceled) {
		t.Fatal("recovery effect lost cancellation", err)
	}
	if mfaRecoveryIssuanceDigest([32]byte{1}, "user", "session", "family", []byte{1}) == mfaTOTPIssuanceDigest([32]byte{1}, "user", "session", "family", []byte{1}) {
		t.Fatal("recovery reused TOTP issuance evidence")
	}
}

func TestMFAFactorAuthorityKeyIsOwnerAndTenantBound(t *testing.T) {
	a, err := mfapg.FactorAuthorityKey("a", "b:c")
	if err != nil {
		t.Fatal(err)
	}
	// Independently computed using SHA-256 over the documented Ruby pack("n")
	// framing. Pin the public scope profile, not merely self-consistency.
	if a != "factor:v1:dgl0SfNtrthYvyOl2kNaGt4jlcOp2s9Ipy0m3XZ-Aas" {
		t.Fatal("factor authority profile changed")
	}
	b, err := mfapg.FactorAuthorityKey("a:b", "c")
	if err != nil || a == b {
		t.Fatal("factor scope framing aliases owner/tenant", err)
	}
	again, err := mfapg.FactorAuthorityKey("a", "b:c")
	if err != nil || a != again {
		t.Fatal("factor scope changed without an identity change", err)
	}
	if _, err := mfapg.FactorAuthorityKey("", "c"); err == nil {
		t.Fatal("empty factor owner accepted")
	}
}
