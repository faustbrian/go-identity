package otp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type entropyFunc func([]byte) (int, error)

func (f entropyFunc) Read(b []byte) (int, error) { return f(b) }

func TestAttemptEntropyFailureAndCancellationClearTemporaryID(t *testing.T) {
	d, _ := NewDestinationInput("user@example.test")
	a, _ := NewFlowAuthorization(FlowAuthorizationSpec{Kind: FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: identity.PreAuthTransactionID("AQEBAQEBAQEBAQEBAQEBAQ")})
	p, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 30 * time.Minute, FreshFor: 15 * time.Minute})
	c, e := NewContinuation(DigestScopeSpec{TenantID: "tenant", Purpose: PurposeSignin, SubjectID: "subject", Channel: ChannelEmail, Destination: d, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 1, Generation: 1}, a, p)
	if e != nil {
		t.Fatal(e)
	}
	code, _ := auth.NewOneTimeCode("123456")
	issuer, _ := NewAttemptIssuer(1, [32]byte{1})
	for _, reader := range []io.Reader{bytes.NewReader(nil), bytes.NewReader(make([]byte, 15)), bytes.NewReader(make([]byte, 16)), entropyFunc(func([]byte) (int, error) { return 0, errors.New("synthetic sensitive failure") })} {
		cmd, e := issuer.prepare(context.Background(), reader, c, AttemptModeConsume, 1, code)
		if !errors.Is(e, ErrAttemptUnavailable) || cmd.state != nil {
			t.Fatal("entropy failure produced command")
		}
	}
	if _, e := issuer.prepare(context.Background(), nil, c, AttemptModeConsume, 1, code); !errors.Is(e, ErrInvalidAttempt) {
		t.Fatal("nil entropy accepted")
	}
	for _, cancelDuringRead := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		var borrowed []byte
		reader := entropyFunc(func(b []byte) (int, error) {
			borrowed = b
			for i := range b {
				b[i] = 1
			}
			if cancelDuringRead {
				cancel()
			}
			return len(b), nil
		})
		cmd, e := issuer.prepare(ctx, reader, c, AttemptModeConsume, 1, code)
		cancel()
		if cancelDuringRead {
			if !errors.Is(e, context.Canceled) || cmd.state != nil {
				t.Fatal("cancelled entropy yielded command")
			}
		} else {
			if e != nil || cmd.state == nil {
				t.Fatal("valid entropy rejected")
			}
		}
		for _, v := range borrowed {
			if v != 0 {
				t.Fatal("temporary entropy retained")
			}
		}
	}
}
