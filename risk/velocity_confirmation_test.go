package risk_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestVelocityConfirmationExactPrimaryCustody(t *testing.T) {
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, binding := publicationFacts()
	var leaseLive, cutLive, confirmed atomic.Bool
	leaseLive.Store(true)
	cutLive.Store(true)
	check := func(live *atomic.Bool) func(context.Context) error {
		return func(context.Context) error {
			if !live.Load() {
				return errors.New("private confirmation diagnostic")
			}
			return nil
		}
	}
	l, err := j.Lease(lb, check(&leaseLive))
	if err != nil {
		t.Fatal(err)
	}
	c, err := j.Closure(l, binding, check(&cutLive))
	if err != nil {
		t.Fatal(err)
	}
	p, err := native.AcknowledgePublication(context.Background(), l, c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := j.AcknowledgeConfirmation(context.Background(), l, c, p, check(&confirmed)); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityConfirmation{}) {
		t.Fatal("publication alone manufactured primary confirmation", err)
	}
	confirmed.Store(true)
	k, err := j.AcknowledgeConfirmation(context.Background(), l, c, p, check(&confirmed))
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.Confirmation(context.Background(), l, c, p, k)
	if err != nil || got != binding {
		t.Fatal("original confirmed cut lost", err)
	}
	got.Position++
	for index := range 16 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			t.Parallel()
			got, err := verifier.Confirmation(context.Background(), l, c, p, k)
			if err != nil || got != binding {
				t.Fatal("copied custody changed", err)
			}
		})
	}
	for _, live := range []*atomic.Bool{&leaseLive, &cutLive, &confirmed} {
		live.Store(false)
		if got, err := verifier.Confirmation(context.Background(), l, c, p, k); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityClosureBinding{}) {
			t.Fatal("invalidated primary authority admitted", err)
		}
		live.Store(true)
	}
	l2, _ := j.Lease(lb, check(&leaseLive))
	c2, _ := j.Closure(l, binding, check(&cutLive))
	p2, _ := native.AcknowledgePublication(context.Background(), l, c)
	_, _, _, foreign := risk.NewVelocityRecoveryAuthorities()
	for _, invoke := range []func() error{
		func() error { _, e := verifier.Confirmation(context.Background(), l2, c, p, k); return e },
		func() error { _, e := verifier.Confirmation(context.Background(), l, c2, p, k); return e },
		func() error { _, e := verifier.Confirmation(context.Background(), l, c, p2, k); return e },
		func() error { _, e := foreign.Confirmation(context.Background(), l, c, p, k); return e },
		func() error {
			_, e := verifier.Confirmation(context.Background(), l, c, p, risk.VelocityConfirmation{})
			return e
		},
	} {
		if err := invoke(); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
			t.Fatal("replacement custody admitted", err)
		}
	}
	for _, value := range []any{k, []risk.VelocityConfirmation{k}, map[risk.VelocityConfirmation]string{k: "value"}} {
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("confirmation serialized", err)
		}
		if text := fmt.Sprintf("%+v", value); strings.Contains(text, "private confirmation") {
			t.Fatal("diagnostic escaped")
		}
	}
	if text := fmt.Sprintf("%#v", k); text != "risk.velocityRecovery(redacted)" {
		t.Fatal("confirmation not redacted", text)
	}
	for _, value := range []any{k, p, c, verifier} {
		if reflect.TypeOf(value).ConvertibleTo(reflect.TypeOf(j)) {
			t.Fatal("public custody promoted to primary issuer")
		}
	}
}

func TestVelocityConfirmationContextAndInvalidIssuance(t *testing.T) {
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, binding := publicationFacts()
	l, _ := j.Lease(lb, func(context.Context) error { return nil })
	c, _ := j.Closure(l, binding, func(context.Context) error { return nil })
	p, _ := native.AcknowledgePublication(context.Background(), l, c)
	called := false
	check := func(context.Context) error { called = true; return nil }
	foreign, _, _, _ := risk.NewVelocityRecoveryAuthorities()
	for _, issuer := range []risk.VelocityJournalIssuer{{}, foreign} {
		if k, err := issuer.AcknowledgeConfirmation(context.Background(), l, c, p, check); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || k != (risk.VelocityConfirmation{}) || called {
			t.Fatal("foreign issuance reached authority", err)
		}
	}
	if k, err := j.AcknowledgeConfirmation(context.Background(), l, c, p, nil); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || k != (risk.VelocityConfirmation{}) {
		t.Fatal("missing checker accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		k, err := j.AcknowledgeConfirmation(ctx, l, c, p, check)
		if err == nil || k != (risk.VelocityConfirmation{}) || called {
			t.Fatal("invalid context issued confirmation", err)
		}
	}
	for _, expected := range []error{context.Canceled, context.DeadlineExceeded, risk.ErrVelocityRecoveryUnavailable} {
		callback := func(context.Context) error {
			if expected == risk.ErrVelocityRecoveryUnavailable {
				return errors.New("secret primary diagnostic")
			}
			return expected
		}
		k, err := j.AcknowledgeConfirmation(context.Background(), l, c, p, callback)
		if !errors.Is(err, expected) || k != (risk.VelocityConfirmation{}) {
			t.Fatal("authority failure classification changed", err)
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	if k, err := j.AcknowledgeConfirmation(ctx, l, c, p, func(context.Context) error { cancel(); return nil }); !errors.Is(err, context.Canceled) || k != (risk.VelocityConfirmation{}) {
		t.Fatal("late success issued custody", err)
	}
	k, err := j.AcknowledgeConfirmation(context.Background(), l, c, p, check)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := verifier.Confirmation(ctx, l, c, p, k); !errors.Is(err, context.Canceled) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("canceled check disclosed cut", err)
	}
}
