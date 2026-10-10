package password_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

func signupInput(t testing.TB) password.SignupRequest {
	t.Helper()
	r := signinInput(t)
	key, err := identity.NewIdempotencyKey([]byte("synthetic-signup-retry"))
	if err != nil {
		t.Fatal(err)
	}
	r.Caller.Request.Action = "identity.password.signup"
	r.Caller.Request.Resource.ID = "identity.password.signup"
	return password.SignupRequest{TenantID: r.TenantID, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Email: " generic-owned-address ", Password: r.Password, RememberPolicy: r.Remember, Origin: r.Origin, CallbackURL: r.CallbackURL, Caller: r.Caller, Network: r.Network, Device: r.Device, IdempotencyKey: key}
}

func TestSignupRequestPreservesOriginalGenericCustody(t *testing.T) {
	r := signupInput(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid generic signup denied", err)
	}
	original := []byte(" raw\x00synthetic-ä-password ")
	if err := r.Password.Use(func(got []byte) error {
		if !bytes.Equal(got, original) {
			t.Error("signup normalized raw password")
		}
		return nil
	}); err != nil {
		t.Fatal("signup consumed custody", err)
	}
	if r.Email != " generic-owned-address " {
		t.Fatal("signup interpreted or normalized generic address")
	}
	for _, size := range []int{1, 4096, 4097} {
		changed := r
		changed.Email = password.SignupAddressInput(strings.Repeat("a", size))
		if (changed.Validate() == nil) != (size <= 4096) {
			t.Fatal("address transport byte bounds")
		}
	}
}

func TestSignupRequestRequiresOriginalKeyFlowAndBoundedFields(t *testing.T) {
	r := signupInput(t)
	for _, mutate := range []func(*password.SignupRequest){
		func(r *password.SignupRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *password.SignupRequest) { r.PreAuthID = "" },
		func(r *password.SignupRequest) { r.Email = "\xff" },
		func(r *password.SignupRequest) { r.Origin = "" },
		func(r *password.SignupRequest) { r.Caller.Request.Action = "identity.password.signin" },
		func(r *password.SignupRequest) { r.AllowedFields = make([]identity.AttributeUpdate, 65) },
		func(r *password.SignupRequest) {
			r.AllowedFields = []identity.AttributeUpdate{{Name: "nickname", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: strings.Repeat("x", 4097)}}}}
		},
	} {
		changed := r
		changed.Caller = r.Caller.Clone()
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid signup input admitted")
		}
	}
	for _, output := range []string{fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", &r), r.LogValue().String()} {
		for _, sentinel := range []string{"generic-owned-address", "synthetic-signup-retry", r.Cookie.Token(), "synthetic-ä-password"} {
			if strings.Contains(output, sentinel) {
				t.Fatal("signup diagnostics disclosed original input")
			}
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("signup input serialized")
	}
	if _, err := r.MarshalText(); err == nil {
		t.Fatal("signup input serialized as text")
	}
}

func TestSignupRequestAttributeShapesAndBudget(t *testing.T) {
	r := signupInput(t)
	text := func(value string) identity.AttributeValue {
		return identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: value}}
	}
	list := make([]identity.AttributeScalar, 64)
	for i := range list {
		list[i] = text(strings.Repeat("x", 4096)).Scalar
	}
	for _, value := range []identity.AttributeValue{
		text(""), text(" unnormalized-ä-value "),
		{Kind: identity.AttributeBool, Scalar: identity.AttributeScalar{Kind: identity.AttributeBool}},
		{Kind: identity.AttributeInt64, Scalar: identity.AttributeScalar{Kind: identity.AttributeInt64}},
		{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime, Time: time.Unix(1, 0)}},
		{Kind: identity.AttributeStringList, List: []identity.AttributeScalar{}},
		{Kind: identity.AttributeStringList, List: list},
	} {
		r.AllowedFields = []identity.AttributeUpdate{{Name: "requested_field", Value: value}}
		if err := r.Validate(); err != nil {
			t.Fatal("valid requested attribute rejected", err)
		}
	}
	r.AllowedFields = append(r.AllowedFields, identity.AttributeUpdate{Name: "extra", Value: text("x")})
	if r.Validate() == nil {
		t.Fatal("aggregate input budget exceeded")
	}
	for _, name := range []string{"", "id", "tenant_id", "status", "version", "Uppercase", "1prefix", "field-name", "\xff", strings.Repeat("n", 129)} {
		r.AllowedFields = []identity.AttributeUpdate{{Name: name, Value: text("value")}}
		if r.Validate() == nil {
			t.Fatal("invalid/reserved field name admitted")
		}
	}
	r.AllowedFields = []identity.AttributeUpdate{{Name: "duplicate", Value: text("a")}, {Name: "duplicate", Value: text("b")}}
	if r.Validate() == nil {
		t.Fatal("duplicate field admitted")
	}
	for _, value := range []identity.AttributeValue{
		{}, text("\xff"),
		{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, Bool: true}},
		{Kind: identity.AttributeBool, Scalar: identity.AttributeScalar{Kind: identity.AttributeBool, String: "hidden"}},
		{Kind: identity.AttributeInt64, Scalar: identity.AttributeScalar{Kind: identity.AttributeInt64, Bool: true}},
		{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime}},
		{Kind: identity.AttributeStringList},
		{Kind: identity.AttributeStringList, Scalar: text("mixed").Scalar, List: list},
		{Kind: identity.AttributeStringList, List: append(append([]identity.AttributeScalar(nil), list...), text("extra").Scalar)},
		{Kind: identity.AttributeStringList, List: []identity.AttributeScalar{{Kind: identity.AttributeBool}}},
		{Kind: identity.AttributeString, Scalar: text("value").Scalar, List: []identity.AttributeScalar{}},
	} {
		r.AllowedFields = []identity.AttributeUpdate{{Name: "requested_field", Value: value}}
		if r.Validate() == nil {
			t.Fatal("malformed tagged value admitted")
		}
	}
}

func FuzzSignupRequestGenericAddress(f *testing.F) {
	f.Add(" unnormalized generic input ")
	f.Add("\xff")
	f.Add("")
	f.Fuzz(func(t *testing.T, address string) {
		if len(address) > 4097 {
			return
		}
		r := signupInput(t)
		r.Email = password.SignupAddressInput(address)
		if (r.Validate() == nil) != (len(address) > 0 && len(address) <= 4096 && utf8.ValidString(address)) || string(r.Email) != address {
			t.Fatal("generic address changed or structural bound mismatch")
		}
	})
}
