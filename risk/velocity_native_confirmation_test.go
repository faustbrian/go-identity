package risk_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestVelocityNativeConfirmationHistoricalIdentity(t *testing.T) {
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	live := true
	checks := 0
	check := func(context.Context) error {
		checks++
		if !live {
			return errors.New("private primary failure")
		}
		return nil
	}
	l, _ := j.Lease(lb, check)
	c, _ := j.Closure(l, b, check)
	p, _ := native.AcknowledgePublication(context.Background(), l, c)
	k, _ := j.AcknowledgeConfirmation(context.Background(), l, c, p, check)
	ack, err := native.AcknowledgeNativeConfirmation(context.Background(), l, c, p, k)
	if err != nil {
		t.Fatal(err)
	}
	live = false
	before := checks
	got, err := verifier.NativeConfirmation(l, c, p, k, ack)
	if err != nil || got != b || checks != before {
		t.Fatal("historical identity acquired current authority", err)
	}
	if _, err := native.AcknowledgeNativeConfirmation(context.Background(), l, c, p, k); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) {
		t.Fatal("invalidated primary issued new native acknowledgement", err)
	}
	c2, _ := j.Closure(l, b, check)
	live = true
	p2, _ := native.AcknowledgePublication(context.Background(), l, c)
	_, _, _, foreign := risk.NewVelocityRecoveryAuthorities()
	for _, invoke := range []func() error{
		func() error { _, e := verifier.NativeConfirmation(l, c2, p, k, ack); return e },
		func() error { _, e := verifier.NativeConfirmation(l, c, p2, k, ack); return e },
		func() error { _, e := foreign.NativeConfirmation(l, c, p, k, ack); return e },
		func() error {
			_, e := verifier.NativeConfirmation(l, c, p, k, risk.VelocityNativeConfirmation{})
			return e
		},
	} {
		if !errors.Is(invoke(), risk.ErrInvalidVelocityRecovery) {
			t.Fatal("substituted identity admitted")
		}
	}
	for _, value := range []any{ack, []risk.VelocityNativeConfirmation{ack}, map[risk.VelocityNativeConfirmation]int{ack: 1}} {
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("native acknowledgement serialized", err)
		}
		if reflect.TypeOf(value).ConvertibleTo(reflect.TypeOf(native)) {
			t.Fatal("acknowledgement promoted to issuer")
		}
	}
	if got := fmt.Sprintf("%#v", ack); got != "risk.velocityRecovery(redacted)" {
		t.Fatal("native acknowledgement leaked custody", got)
	}
	for range 12 {
		t.Run("copied-historical-identity", func(t *testing.T) {
			t.Parallel()
			got, err := verifier.NativeConfirmation(l, c, p, k, ack)
			if err != nil || got != b {
				t.Fatal("concurrent copy changed original facts", err)
			}
			got.Position++
			if original, err := verifier.NativeConfirmation(l, c, p, k, ack); err != nil || original != b {
				t.Fatal("returned projection changed owned custody", err)
			}
		})
	}
}

func TestVelocityNativeConfirmationContextAndOwnership(t *testing.T) {
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	calls := 0
	check := func(context.Context) error { calls++; return nil }
	l, _ := j.Lease(lb, check)
	c, _ := j.Closure(l, b, check)
	p, _ := native.AcknowledgePublication(context.Background(), l, c)
	k, _ := j.AcknowledgeConfirmation(context.Background(), l, c, p, check)
	before := calls
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, candidate := range []context.Context{nil, ctx} {
		if got, err := native.AcknowledgeNativeConfirmation(candidate, l, c, p, k); err == nil || got != (risk.VelocityNativeConfirmation{}) || calls != before {
			t.Fatal("invalid context reached primary authority", err)
		}
	}
	_, _, foreign, _ := risk.NewVelocityRecoveryAuthorities()
	for _, owner := range []risk.VelocityNativeIssuer{{}, foreign} {
		if got, err := owner.AcknowledgeNativeConfirmation(context.Background(), l, c, p, k); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityNativeConfirmation{}) || calls != before {
			t.Fatal("foreign owner acknowledged confirmation", err)
		}
	}
	// Cancellation inside the final original-confirmation check cannot expose
	// an acknowledgement even when that callback returns nominal success.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	armed := false
	k, _ = j.AcknowledgeConfirmation(context.Background(), l, c, p, func(context.Context) error {
		if armed {
			cancel()
		}
		return nil
	})
	armed = true
	if got, err := native.AcknowledgeNativeConfirmation(ctx, l, c, p, k); !errors.Is(err, context.Canceled) || got != (risk.VelocityNativeConfirmation{}) {
		t.Fatal("late cancellation issued custody", err)
	}
	if got, err := verifier.NativeConfirmation(risk.VelocityLease{}, c, p, k, risk.VelocityNativeConfirmation{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("zero chain disclosed historical facts", err)
	}
}
