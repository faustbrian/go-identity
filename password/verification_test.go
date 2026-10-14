package password_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	primitive "github.com/faustbrian/go-password"
)

// Plan: portable verification preserves borrowed raw password/bearer and
// explicit target, admits no retry-key field or caller-selected proof/lifetime,
// and checks intrinsic bounds without issuing a proof or accessing owners.
// Real signed issuance, primary authority, risk and recovery remain native.
func TestVerificationRequestBoundsAndBorrowedCustody(t *testing.T) {
	secret, err := primitive.NewSecret([]byte(" raw-synthetic-verification "))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	r := password.VerificationRequest{TenantID: "tenant", Session: auth.NewBearerCredential("synthetic-original-bearer"), Password: secret, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.password.change", Audience: "backend"}, Network: "192.0.2.1", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Tenant: "tenant", Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}}
	if err := r.Validate(); err != nil {
		t.Fatal("valid bounded input denied", err)
	}
	for _, change := range []func(*password.VerificationRequest){
		func(r *password.VerificationRequest) { r.TenantID = "" },
		func(r *password.VerificationRequest) { r.TenantID = identity.TenantID(strings.Repeat("x", 129)) },
		func(r *password.VerificationRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *password.VerificationRequest) {
			r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
		},
		func(r *password.VerificationRequest) { r.Caller.Request.Subject.ID = "" },
		func(r *password.VerificationRequest) { r.Caller.PolicyRevision = 0 },
		func(r *password.VerificationRequest) { r.Session = auth.BearerCredential{} },
		func(r *password.VerificationRequest) { r.Session = auth.NewBearerCredential(strings.Repeat("x", 129)) },
		func(r *password.VerificationRequest) { r.Network = "" },
		func(r *password.VerificationRequest) { r.Network = "untrusted\nnetwork" },
		func(r *password.VerificationRequest) { r.Device = "untrusted\ndevice" },
		func(r *password.VerificationRequest) { r.Device = strings.Repeat("x", 129) },
		func(r *password.VerificationRequest) { r.Password = primitive.Secret{} },
		func(r *password.VerificationRequest) { r.Target.Purpose = "" },
		func(r *password.VerificationRequest) { r.Target.Action = " " },
		func(r *password.VerificationRequest) { r.Target.Audience = strings.Repeat("x", 257) },
	} {
		bad := r
		change(&bad)
		if !errors.Is(bad.Validate(), password.ErrPasswordWork) {
			t.Fatal("invalid scope or custody admitted")
		}
	}
	for _, field := range []string{"IdempotencyKey", "Proof", "TTL", "Assurance", "Now"} {
		if _, found := reflect.TypeOf(r).FieldByName(field); found {
			t.Fatal("non-keyed verification exposes override")
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%d"} {
		out := fmt.Sprintf(verb, r)
		if strings.Contains(out, "synthetic") || strings.Contains(out, "192.0.2.1") {
			t.Fatal("verification diagnostics leaked custody")
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("verification request serialized")
	}
	if raw, err := r.MarshalText(); len(raw) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("verification text export admitted")
	}
	if strings.Contains(r.LogValue().String(), "synthetic") {
		t.Fatal("verification slog leaked")
	}
	if err := secret.Use(func(raw []byte) error {
		if string(raw) != " raw-synthetic-verification " {
			t.Error("verification normalized password")
		}
		return nil
	}); err != nil {
		t.Fatal("intrinsic validation consumed caller secret", err)
	}
	secret.Destroy()
	if !errors.Is(r.Validate(), password.ErrPasswordWork) {
		t.Fatal("destroyed secret admitted")
	}
}

func TestVerificationTargetExactIntrinsicBounds(t *testing.T) {
	valid := password.VerificationTarget{Purpose: auth.Purpose(strings.Repeat("p", 128)), Action: strings.Repeat("a", 128), Audience: strings.Repeat("b", 256)}
	if err := valid.Validate(); err != nil {
		t.Fatal("inclusive bounds denied", err)
	}
	for _, change := range []func(*password.VerificationTarget){
		func(r *password.VerificationTarget) { r.Purpose += "p" },
		func(r *password.VerificationTarget) { r.Action += "a" },
		func(r *password.VerificationTarget) { r.Audience += "b" },
		func(r *password.VerificationTarget) { r.Purpose = "non-ascii-ä" },
		func(r *password.VerificationTarget) { r.Action = "contains space" },
		func(r *password.VerificationTarget) { r.Audience = "contains\x7f" },
	} {
		bad := valid
		change(&bad)
		if !errors.Is(bad.Validate(), password.ErrPasswordWork) {
			t.Fatal("invalid target admitted")
		}
	}
}
