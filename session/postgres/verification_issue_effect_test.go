package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestVerificationSigninEffectRejectsUnownedOrUncommittedSource(t *testing.T) {
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	for _, c := range []Config{{}, {Schema: "identity", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: 2 * time.Minute}} {
		if e, err := NewEmailVerificationSigninEffect(c, profile); err == nil || e != nil {
			t.Fatal("invalid native owner admitted")
		}
	}
	effect, err := NewEmailVerificationSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*EmailVerificationSigninEffect{nil, {}, effect} {
		if _, err := e.Apply(t.Context(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, identity.CommandResult{}); err == nil {
			t.Fatal("metadata without committed verification/owned Work issued a session")
		}
		if err := e.CheckCurrent(t.Context(), kernel.Work{}, nil, identity.Command{}, kernel.RecipientRecord{}, identity.CommandResult{}); err == nil {
			t.Fatal("unowned final admission accepted")
		}
		if _, err := e.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery manufactured issuance")
		}
	}
}
