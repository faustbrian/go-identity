package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestNativeSessionSubmittedTokenCustody(t *testing.T) {
	a, spec, original := sessionCustodyFixture(t)
	b, _ := a.Bindings()
	continuation, _ := b.Continuation.Bindings()
	continuation.Scope.AuthorizationBinding = [32]byte{}
	s, _ := original.Bindings()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	token, _ := session.ParseToken(wire)
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	s.Lookup, _ = token.Digest(key, string(s.TenantID))
	original, _ = session.NewSession(s)
	flow, _ := otp.NewBoundSessionAuthorization(original)
	cont, err := otp.NewContinuation(continuation.Scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := a.Code()
	a, err = issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, cont, b.Mode, b.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := NewAttemptCodec(codecConfig())
	command, plan, err := codec.MapSession(context.Background(), a, 3, spec, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[uint32]session.DigestKey{3: key}
	got, err := codec.authenticateSession(context.Background(), keys, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := got.Bindings()
	if g.Lookup != s.Lookup || !g.Authentication.Proof.IssuedAt.Equal(s.Authentication.Proof.IssuedAt) {
		t.Fatal("original token/timeline replaced")
	}
	if submitted, ok := command.SessionToken(); !ok || submitted.Token() != wire {
		t.Fatal("submitted token custody lost")
	}
	if _, ok := command.PreAuthCookie(); ok {
		t.Fatal("session became pre-auth")
	}
	metadata, _ := command.Feature()
	wrongWire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32))
	wrong, _ := identity.NewFeatureOneTimeCodeSessionCommand(metadata, code, auth.NewBearerCredential(wrongWire))
	preauth, _ := identity.NewFeatureOneTimeCodePreAuthCommand(metadata, code, auth.NewBearerCredential(wire))
	absent, _ := identity.NewFeatureOneTimeCodeCommand(metadata, code)
	for _, candidate := range []identity.Command{wrong, preauth, absent, {}} {
		if _, err := codec.authenticateSession(context.Background(), keys, candidate, plan); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("wrong/absent session token admitted")
		}
	}
	otherKey, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x57}, 32))
	for _, retained := range []map[uint32]session.DigestKey{nil, {4: key}, {3: otherKey}} {
		if _, err := codec.authenticateSession(context.Background(), retained, command, plan); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("key fallback/replacement admitted")
		}
	}
	changed := plan
	changed.ScopeDigest[0] ^= 1
	if _, err := codec.authenticateSession(context.Background(), keys, command, changed); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("changed plan admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := codec.authenticateSession(ctx, keys, command, plan); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, _, err := codec.MapSession(context.Background(), a, 3, spec, auth.NewBearerCredential("invalid")); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("malformed token mapped")
	}
	legacy, legacySpec := mappedAttempt(t, otp.PurposeEmailVerification, false)
	if _, _, err := codec.MapSession(context.Background(), legacy, 3, legacySpec, auth.NewBearerCredential(wire)); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("legacy flow acquired session custody")
	}
	if _, err := codec.authenticateSession(nil, keys, command, kernel.OTPAttemptPlan{}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil context admitted")
	}
}
