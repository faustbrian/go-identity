package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestRetainedOTPSigninIdentityRejectsUnownedReads(t *testing.T) {
	b := revokeBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.otp.signin", "identity-otp-signin", ""
	for _, r := range []*Repository{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if got, err := r.ReadOTPSigninIdentity(ctx, b); err == nil || got != (OTPSigninIdentity{}) {
				t.Fatal("unowned identity read accepted")
			}
		}
		if got, err := r.ReadOTPSigninIdentity(context.Background(), identity.CommandBinding{}); err == nil || got != (OTPSigninIdentity{}) {
			t.Fatal("zero historical scope accepted")
		}
	}
}

func TestRetainedOTPSigninIdentityNoImplicitDisclosure(t *testing.T) {
	got := OTPSigninIdentity{UserID: "private-user", SessionID: "private-session", FamilyID: "private-family"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(verb, got) != "postgres.OTPSigninIdentity(redacted)" {
			t.Fatal("implicit identity formatting exposed metadata")
		}
	}
	if _, err := json.Marshal(got); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit identity JSON admitted")
	}
	if _, err := got.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit identity text admitted")
	}
}
