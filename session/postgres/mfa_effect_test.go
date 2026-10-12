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
)

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
