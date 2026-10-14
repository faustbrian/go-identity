package otp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/otp"
)

func attemptContinuation(t *testing.T) otp.Continuation {
	t.Helper()
	s := digestScopeSpec(t)
	s.AuthorizationBinding = [32]byte{}
	a, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuthID()})
	c, e := otp.NewContinuation(s, a, rememberPolicy(t))
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestServerIssuedAttemptsBindSubmissionAndRecovery(t *testing.T) {
	c := attemptContinuation(t)
	code, _ := auth.NewOneTimeCode("123456")
	i, e := otp.NewAttemptIssuer(7, [32]byte{9})
	if e != nil {
		t.Fatal(e)
	}
	a, e := i.Prepare(context.Background(), c, otp.AttemptModeConsume, 11, code)
	if e != nil {
		t.Fatal(e)
	}
	b, e := a.Bindings()
	if e != nil || b.Mode != otp.AttemptModeConsume || b.ExpectedVersion != 11 || b.FingerprintKeyVersion != 7 {
		t.Fatal("attempt metadata changed")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(string(b.AttemptID))
	if e != nil || len(raw) != 16 {
		t.Fatal("attempt ID not canonical random128")
	}
	recovery, e := a.Recovery()
	if e != nil || recovery.AttemptID != b.AttemptID || recovery.Fingerprint != b.Fingerprint || recovery.FingerprintKeyVersion != 7 || string(recovery.TenantID) != "tenant" {
		t.Fatal("recovery identity changed")
	}
	borrowed, e := a.Code()
	if e != nil {
		t.Fatal(e)
	}
	// Fingerprint independently encodes complete scope, mode, expected version
	// and fingerprint key version, then the authentication HMAC framing/code.
	cb, _ := c.Bindings()
	scope := []byte("identity-otp-code-scope-v1\x00")
	for _, value := range []string{"tenant", "signin", "subject", "email", "user@example.test", "challenge", "target"} {
		scope = binary.BigEndian.AppendUint16(scope, uint16(len(value)))
		scope = append(scope, value...)
	}
	scope = binary.BigEndian.AppendUint64(scope, 3)
	scope = binary.BigEndian.AppendUint64(scope, 4)
	scope = append(scope, cb.Scope.AuthorizationBinding[:]...)
	bind := []byte("identity-otp-attempt-fingerprint-v1\x00")
	bind = binary.BigEndian.AppendUint32(bind, uint32(len(scope)))
	bind = append(bind, scope...)
	bind = append(bind, 2)
	bind = binary.BigEndian.AppendUint64(bind, 11)
	bind = binary.BigEndian.AppendUint32(bind, 7)
	msg := []byte("authentication-one-time-code-digest-v1\x00")
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(bind)))
	msg = append(msg, bind...)
	msg = append(msg, 0, 6)
	msg = append(msg, []byte("123456")...)
	key := [32]byte{9}
	h := hmac.New(sha256.New, key[:])
	h.Write(msg)
	if string(b.Fingerprint) != base64.RawURLEncoding.EncodeToString(h.Sum(nil)) {
		t.Fatal("exact fingerprint changed")
	}
	// Borrowing stays opaque and preserves exact submitted bytes without an accessor.
	x, _ := borrowed.KeyedDigest(key, []byte("test"))
	y, _ := code.KeyedDigest(key, []byte("test"))
	if x != y {
		t.Fatal("submission code changed")
	}
	second, e := i.Prepare(context.Background(), c, otp.AttemptModeConsume, 11, code)
	if e != nil {
		t.Fatal(e)
	}
	b2, _ := second.Bindings()
	if b2.AttemptID == b.AttemptID || b2.Fingerprint != b.Fingerprint {
		t.Fatal("new submission identity or stable exact-input fingerprint changed")
	}
	wrong, _ := auth.NewOneTimeCode("123457")
	for _, other := range []struct {
		mode    otp.AttemptMode
		version uint64
		code    auth.OneTimeCode
	}{{otp.AttemptModeCheck, 11, code}, {otp.AttemptModeConsume, 12, code}, {otp.AttemptModeConsume, 11, wrong}} {
		a, e := i.Prepare(context.Background(), c, other.mode, other.version, other.code)
		if e != nil {
			t.Fatal(e)
		}
		got, _ := a.Bindings()
		if got.Fingerprint == b.Fingerprint {
			t.Fatal("different submission collapsed")
		}
	}
	for _, cfg := range []struct {
		version uint32
		key     [32]byte
	}{{8, key}, {7, [32]byte{10}}} {
		issuer, _ := otp.NewAttemptIssuer(cfg.version, cfg.key)
		a, e := issuer.Prepare(context.Background(), c, otp.AttemptModeConsume, 11, code)
		if e != nil {
			t.Fatal(e)
		}
		got, _ := a.Bindings()
		if got.Fingerprint == b.Fingerprint {
			t.Fatal("different fingerprint custody collapsed")
		}
	}
	for _, value := range []any{i, a, b, recovery, b.AttemptID, b.Fingerprint} {
		for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			if !strings.Contains(fmt.Sprintf(format, value), "redacted") {
				t.Fatal("attempt formatting disclosed")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("attempt JSON allowed")
		}
		if _, e := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(e, otp.ErrSensitiveSerialization) {
			t.Fatal("attempt text allowed")
		}
	}
	var wg sync.WaitGroup
	ids := make(chan otp.AttemptID, 20)
	for range 20 {
		wg.Go(func() {
			cmd, e := i.Prepare(context.Background(), c, otp.AttemptModeConsume, 11, code)
			if e != nil {
				t.Error(e)
				return
			}
			got, e := cmd.Bindings()
			if e != nil || got.Fingerprint != b.Fingerprint {
				t.Error("concurrent binding changed")
				return
			}
			ids <- got.AttemptID
		})
	}
	wg.Wait()
	close(ids)
	seen := map[otp.AttemptID]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatal("attempt ID repeated")
		}
		seen[id] = true
	}
	if len(seen) != 20 {
		t.Fatal("missing concurrent command")
	}
}

func TestAttemptPreparationRejectsZeroAndCancelledInput(t *testing.T) {
	if _, e := otp.NewAttemptIssuer(0, [32]byte{1}); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero key version accepted")
	}
	if _, e := otp.NewAttemptIssuer(1, [32]byte{}); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero key accepted")
	}
	c := attemptContinuation(t)
	code, _ := auth.NewOneTimeCode("123456")
	i, _ := otp.NewAttemptIssuer(1, [32]byte{1})
	for _, call := range []func() (otp.AttemptCommand, error){
		func() (otp.AttemptCommand, error) { return i.Prepare(nil, c, otp.AttemptModeConsume, 1, code) },
		func() (otp.AttemptCommand, error) {
			return (otp.AttemptIssuer{}).Prepare(context.Background(), c, otp.AttemptModeConsume, 1, code)
		},
		func() (otp.AttemptCommand, error) {
			return i.Prepare(context.Background(), otp.Continuation{}, otp.AttemptModeConsume, 1, code)
		},
		func() (otp.AttemptCommand, error) { return i.Prepare(context.Background(), c, 0, 1, code) },
		func() (otp.AttemptCommand, error) { return i.Prepare(context.Background(), c, 99, 1, code) },
		func() (otp.AttemptCommand, error) {
			return i.Prepare(context.Background(), c, otp.AttemptModeConsume, 0, code)
		},
		func() (otp.AttemptCommand, error) {
			return i.Prepare(context.Background(), c, otp.AttemptModeConsume, 1, auth.OneTimeCode{})
		},
	} {
		if _, e := call(); !errors.Is(e, otp.ErrInvalidAttempt) {
			t.Fatal("invalid attempt accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := i.Prepare(ctx, c, otp.AttemptModeConsume, 1, code); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if _, e := (otp.AttemptCommand{}).Bindings(); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero command projection")
	}
	if _, e := (otp.AttemptCommand{}).Recovery(); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero recovery")
	}
	if _, e := (otp.AttemptCommand{}).Code(); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero code borrow")
	}
}
