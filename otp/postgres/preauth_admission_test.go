package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func admissionFixture(t *testing.T, now time.Time) (*AttemptCodec, identity.Command, kernel.OTPAttemptPlan, session.PreAuthTransaction, string) {
	t.Helper()
	c, err := NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	legacy, spec := mappedAttempt(t, otp.PurposeSignin, true)
	b, _ := legacy.Bindings()
	continuation, _ := b.Continuation.Bindings()
	flow, _ := continuation.Authorization.Bindings()
	spec.Binding.AnonymousFlowID = string(flow.PreAuthTransactionID)
	continuation.Scope.AuthorizationBinding = [32]byte{}
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	token, _ := session.ParseToken(wire)
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	binding := session.PreAuthBinding{ID: flow.PreAuthTransactionID, Intent: session.PreAuthIntent{TenantID: "tenant", Action: spec.Binding.OperationID, Origin: "https://identity.test", Nonce: [32]byte{1}, Remember: continuation.RememberPolicy, PolicyID: spec.Binding.PolicyID, PolicyVersion: spec.Binding.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, _ := token.PreAuthDigest(key, binding)
	record, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	authorization, _ := otp.NewBoundPreAuthAuthorization(record)
	cont, err := otp.NewContinuation(continuation.Scope, authorization, continuation.RememberPolicy)
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
	return c, command, plan, record, wire
}

func TestNativePreAuthSubmittedCookieAdmission(t *testing.T) {
	c, command, plan, original, wire := admissionFixture(t, time.Now().UTC())
	config := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	keys := map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32), 4: bytes.Repeat([]byte{0x57}, 32)}
	p, err := newPreAuthProfile(config, keys)
	if err != nil {
		t.Fatal(err)
	}
	// Caller buffers cannot mutate retained configuration.
	keys[3][0]++
	delete(keys, 3)
	r, err := c.authenticatePreAuth(context.Background(), p, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.Bindings()
	got, _ := r.Bindings()
	if got != want {
		t.Fatal("original flow changed")
	}
	metadata, _ := command.Feature()
	code, _ := command.OneTimeCode()
	wrong, _ := identity.NewFeatureOneTimeCodePreAuthCommand(metadata, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32))))
	noCookie, _ := identity.NewFeatureOneTimeCodeCommand(metadata, code)
	plain, _ := identity.NewFeatureCommand(metadata)
	for _, candidate := range []identity.Command{wrong, noCookie, plain, {}} {
		if r, err := c.authenticatePreAuth(context.Background(), p, candidate, plan); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("absent or wrong submitted bearer admitted", err)
		} else if _, err := r.Bindings(); err == nil {
			t.Fatal("failed admission retained flow")
		}
	}
	for _, keys := range []map[uint32][]byte{{4: bytes.Repeat([]byte{0x57}, 32)}, {3: bytes.Repeat([]byte{0x57}, 32)}} {
		other, _ := newPreAuthProfile(config, keys)
		if _, err := c.authenticatePreAuth(context.Background(), other, command, plan); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("key fallback or changed material admitted", err)
		}
	}
	changed := plan
	changed.DigestKeyVersion++
	if _, err := c.authenticatePreAuth(context.Background(), p, command, changed); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("changed plan admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.authenticatePreAuth(ctx, p, command, plan); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := c.authenticatePreAuth(nil, p, command, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil context admitted")
	}
	if _, err := c.authenticatePreAuth(context.Background(), nil, command, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil profile admitted")
	}
	var absent *AttemptCodec
	if _, err := absent.authenticatePreAuth(context.Background(), p, command, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil codec admitted")
	}
	if cookie, _ := command.PreAuthCookie(); cookie.Token() != wire {
		t.Fatal("admission mutated cookie custody")
	}
}

func TestNativePreAuthProfileConfiguration(t *testing.T) {
	valid := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	for _, keys := range []map[uint32][]byte{nil, {}, {0: bytes.Repeat([]byte{1}, 32)}, {3: nil}, {3: make([]byte, 32)}, {3: bytes.Repeat([]byte{1}, 65)}} {
		if _, err := newPreAuthProfile(valid, keys); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid keys accepted")
		}
	}
	for _, config := range []sessionpg.Config{{}, {Schema: "public", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: time.Minute + 1}} {
		if _, err := newPreAuthProfile(config, map[uint32][]byte{3: bytes.Repeat([]byte{1}, 32)}); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid primary configuration accepted")
		}
	}
}
