package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestPreAuthMappingRetainsRealCookieWithoutPersistence(t *testing.T) {
	c, _ := NewAttemptCodec(codecConfig())
	legacy, spec := mappedAttempt(t, otp.PurposeSignin, true)
	b, _ := legacy.Bindings()
	continuation, _ := b.Continuation.Bindings()
	flow, _ := continuation.Authorization.Bindings()
	spec.Binding.AnonymousFlowID = string(flow.PreAuthTransactionID)
	continuation.Scope.AuthorizationBinding = [32]byte{}
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	token, _ := session.ParseToken(wire)
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	binding := session.PreAuthBinding{ID: flow.PreAuthTransactionID, Intent: session.PreAuthIntent{TenantID: "tenant", Action: spec.Binding.OperationID, Origin: "https://identity.test", Nonce: [32]byte{1}, Remember: continuation.RememberPolicy, PolicyID: spec.Binding.PolicyID, PolicyVersion: spec.Binding.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, err := token.PreAuthDigest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := otp.NewBoundPreAuthAuthorization(record)
	cont, err := otp.NewContinuation(continuation.Scope, bound, continuation.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := legacy.Code()
	a, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, cont, b.Mode, b.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	command, plan, err := c.MapPreAuth(context.Background(), a, 3, spec, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	cookie, ok := command.PreAuthCookie()
	if !ok || cookie.Token() != wire {
		t.Fatal("original cookie not retained")
	}
	metadata, _ := command.Feature()
	for _, field := range metadata.Fields {
		if field.Value.Text == wire || bytes.Contains(field.Value.Bytes, []byte(wire)) {
			t.Fatal("bearer entered persistence projection")
		}
	}
	plain, _ := identity.NewFeatureCommand(metadata)
	if _, ok := plain.PreAuthCookie(); ok {
		t.Fatal("persisted fields reconstructed cookie")
	}
	restarted, _ := NewAttemptCodec(codecConfig())
	if _, err := restarted.restoreAttempt(command, plan); err != nil {
		t.Fatal(err)
	}
	borrowed, _ := session.ParseToken(cookie.Token())
	actual, _ := borrowed.PreAuthDigest(key, binding)
	if actual != digest {
		t.Fatal("cookie bytes changed across command mapping")
	}
	if _, _, err := c.MapPreAuth(context.Background(), legacy, 3, spec, auth.NewBearerCredential(wire)); err == nil {
		t.Fatal("legacy ID-only custody mapped as complete")
	}
	if _, _, err := c.MapPreAuth(context.Background(), a, 3, spec, auth.NewBearerCredential("")); err == nil {
		t.Fatal("absent cookie mapped")
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		command, plan, err := c.MapPreAuth(ctx, a, 3, spec, auth.NewBearerCredential(wire))
		if err == nil || plan != (identitypostgres.OTPAttemptPlan{}) {
			t.Fatal("invalid context returned mapped custody")
		}
		if _, ok := command.PreAuthCookie(); ok {
			t.Fatal("failed mapping retained cookie")
		}
	}
	var absent *AttemptCodec
	if _, _, err := absent.MapPreAuth(context.Background(), a, 3, spec, auth.NewBearerCredential(wire)); err == nil {
		t.Fatal("nil codec mapped")
	}
}
