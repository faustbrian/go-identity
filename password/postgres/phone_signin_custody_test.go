package passwordpostgres

import (
	"bytes"
	"context"
	"testing"

	phone "github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

func TestPhoneSigninRejectsRetargetedOriginalIdentifier(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	service := &SigninService{c: SigninConfig{Phone: policy, IdentifierKey: bytes.Repeat([]byte{9}, 32)}}
	request, original, key, _ := nativeSigninFlow(t)
	request.Identifier = "+12025550123"
	request.Caller.Request.Action = "identity.phone.password-signin"
	spec, _ := original.Bindings()
	spec.Binding.Intent.Action = "identity.phone.password-signin"
	number, err := policy.Canonicalize(context.Background(), string(request.Identifier))
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.Intent.IdentifierBinding, err = phone.PasswordSigninIdentifierBinding(number, request.TenantID, service.c.IdentifierKey)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(request.Cookie.Token())
	spec.Cookie, err = token.PreAuthDigest(key, spec.Binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.requirePhoneSigninTarget(context.Background(), request, flow); err != nil {
		t.Fatal("original canonical phone target denied", err)
	}
	request.Identifier = "+12025550124"
	if err := service.requirePhoneSigninTarget(context.Background(), request, flow); err == nil {
		t.Fatal("original flow was retargeted to another phone")
	}
	request.Identifier = "+12025550123"
	spec.Binding.Intent.IdentifierBinding = [32]byte{}
	unbound, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.requirePhoneSigninTarget(context.Background(), request, unbound); err == nil {
		t.Fatal("unbound legacy flow admitted phone password comparison")
	}
}
