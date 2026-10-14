package risk_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestVelocityEligibilityUsesCurrentPrimaryNotReplay(t *testing.T) {
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	replaying := true
	replayChecks := 0
	replay := func(context.Context) error {
		replayChecks++
		if !replaying {
			return errors.New("private replay failure")
		}
		return nil
	}
	l, _ := j.Lease(lb, replay)
	c, _ := j.Closure(l, b, replay)
	p, _ := native.AcknowledgePublication(context.Background(), l, c)
	k, _ := j.AcknowledgeConfirmation(context.Background(), l, c, p, replay)
	a, _ := native.AcknowledgeNativeConfirmation(context.Background(), l, c, p, k)
	// An actual primary healthy transition invalidates all replay-only checks.
	replaying = false
	before := replayChecks
	healthy := true
	currentChecks := 0
	current := func(context.Context) error {
		currentChecks++
		if !healthy {
			return errors.New("private primary health failure")
		}
		return nil
	}
	h, err := j.AcknowledgeEligibility(context.Background(), l, c, p, k, a, current)
	if err != nil {
		t.Fatal("healthy primary custody could not cross replay boundary", err)
	}
	got, err := verifier.Eligibility(context.Background(), l, c, p, k, a, h)
	if err != nil || got != b || replayChecks != before || currentChecks != 2 {
		t.Fatal("eligibility widened replay authority or missed current primary", err)
	}
	healthy = false
	if got, err := verifier.Eligibility(context.Background(), l, c, p, k, a, h); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("copied eligibility cached a primary allowance", err)
	}
	if replayChecks != before {
		t.Fatal("healthy validation reused replay callbacks")
	}
}

type eligibilityChain struct {
	j risk.VelocityJournalIssuer
	n risk.VelocityNativeIssuer
	v risk.VelocityNativeVerifier
	l risk.VelocityLease
	c risk.VelocityClosure
	p risk.VelocityPublication
	k risk.VelocityConfirmation
	a risk.VelocityNativeConfirmation
}

func newEligibilityChain(t *testing.T) eligibilityChain {
	t.Helper()
	f := eligibilityChain{}
	f.j, _, f.n, f.v = risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	check := func(context.Context) error { return nil }
	var err error
	f.l, err = f.j.Lease(lb, check)
	if err != nil {
		t.Fatal(err)
	}
	f.c, err = f.j.Closure(f.l, b, check)
	if err != nil {
		t.Fatal(err)
	}
	f.p, err = f.n.AcknowledgePublication(context.Background(), f.l, f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.k, err = f.j.AcknowledgeConfirmation(context.Background(), f.l, f.c, f.p, check)
	if err != nil {
		t.Fatal(err)
	}
	f.a, err = f.n.AcknowledgeNativeConfirmation(context.Background(), f.l, f.c, f.p, f.k)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f eligibilityChain) issue(ctx context.Context, check func(context.Context) error) (risk.VelocityEligibility, error) {
	return f.j.AcknowledgeEligibility(ctx, f.l, f.c, f.p, f.k, f.a, check)
}
func (f eligibilityChain) read(ctx context.Context, h risk.VelocityEligibility) (risk.VelocityClosureBinding, error) {
	return f.v.Eligibility(ctx, f.l, f.c, f.p, f.k, f.a, h)
}

func TestVelocityEligibilityRejectsSubstitutedChain(t *testing.T) {
	f := newEligibilityChain(t)
	calls := 0
	check := func(context.Context) error { calls++; return nil }
	h, err := f.issue(context.Background(), check)
	if err != nil {
		t.Fatal(err)
	}
	before := calls
	lb, b := publicationFacts()
	other := newEligibilityChain(t)
	l2, _ := f.j.Lease(lb, check)
	c2, _ := f.j.Closure(f.l, b, check)
	p2, _ := f.n.AcknowledgePublication(context.Background(), f.l, f.c)
	k2, _ := f.j.AcknowledgeConfirmation(context.Background(), f.l, f.c, f.p, check)
	a2, _ := f.n.AcknowledgeNativeConfirmation(context.Background(), f.l, f.c, f.p, f.k)
	before = calls
	for _, change := range []func(*eligibilityChain){
		func(c *eligibilityChain) { c.v = risk.VelocityNativeVerifier{} },
		func(c *eligibilityChain) { c.v = other.v },
		func(c *eligibilityChain) { c.l = risk.VelocityLease{} },
		func(c *eligibilityChain) { c.l = l2 },
		func(c *eligibilityChain) { c.c = risk.VelocityClosure{} },
		func(c *eligibilityChain) { c.c = c2 },
		func(c *eligibilityChain) { c.p = risk.VelocityPublication{} },
		func(c *eligibilityChain) { c.p = p2 },
		func(c *eligibilityChain) { c.k = risk.VelocityConfirmation{} },
		func(c *eligibilityChain) { c.k = k2 },
		func(c *eligibilityChain) { c.a = risk.VelocityNativeConfirmation{} },
		func(c *eligibilityChain) { c.a = a2 },
	} {
		candidate := f
		change(&candidate)
		if got, err := candidate.read(context.Background(), h); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityClosureBinding{}) {
			t.Fatal("zero/foreign/equal replacement acquired eligibility", err)
		}
	}
	for _, owner := range []risk.VelocityJournalIssuer{{}, other.j} {
		candidate := f
		candidate.j = owner
		if got, err := candidate.issue(context.Background(), check); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityEligibility{}) {
			t.Fatal("foreign primary issued eligibility", err)
		}
	}
	if got, err := f.issue(context.Background(), nil); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityEligibility{}) {
		t.Fatal("missing primary checker issued eligibility", err)
	}
	if got, err := f.read(context.Background(), risk.VelocityEligibility{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("zero eligibility returned facts", err)
	}
	if calls != before {
		t.Fatal("invalid custody reached primary callback")
	}
}

func TestVelocityEligibilityContextsAndFailurePrivacy(t *testing.T) {
	f := newEligibilityChain(t)
	calls := 0
	check := func(context.Context) error { calls++; return nil }
	h, err := f.issue(context.Background(), check)
	if err != nil {
		t.Fatal(err)
	}
	before := calls
	canceled, stop := context.WithCancel(context.Background())
	stop()
	expired, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	for _, test := range []struct {
		ctx context.Context
		err error
	}{
		{nil, risk.ErrInvalidVelocityRecovery},
		{canceled, context.Canceled},
		{expired, context.DeadlineExceeded},
	} {
		if got, err := f.issue(test.ctx, check); !errors.Is(err, test.err) || got != (risk.VelocityEligibility{}) {
			t.Fatal("invalid context issued eligibility", err)
		}
		if got, err := f.read(test.ctx, h); !errors.Is(err, test.err) || got != (risk.VelocityClosureBinding{}) {
			t.Fatal("invalid context returned facts", err)
		}
	}
	if calls != before {
		t.Fatal("invalid context reached primary callback")
	}
	for _, failure := range []error{fmt.Errorf("wrapped: %w", context.Canceled), fmt.Errorf("wrapped: %w", context.DeadlineExceeded), errors.New("private primary diagnostic")} {
		errWanted := risk.ErrVelocityRecoveryUnavailable
		if errors.Is(failure, context.Canceled) {
			errWanted = context.Canceled
		}
		if errors.Is(failure, context.DeadlineExceeded) {
			errWanted = context.DeadlineExceeded
		}
		if got, err := f.issue(context.Background(), func(context.Context) error { return failure }); !errors.Is(err, errWanted) || got != (risk.VelocityEligibility{}) || err.Error() != errWanted.Error() {
			t.Fatal("primary failure leaked/issued eligibility", err)
		}
		armed := false
		h, err := f.issue(context.Background(), func(context.Context) error {
			if armed {
				return failure
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		armed = true
		if got, err := f.read(context.Background(), h); !errors.Is(err, errWanted) || got != (risk.VelocityClosureBinding{}) || err.Error() != errWanted.Error() {
			t.Fatal("primary failure leaked/returned facts", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if got, err := f.issue(ctx, func(context.Context) error { cancel(); return nil }); !errors.Is(err, context.Canceled) || got != (risk.VelocityEligibility{}) {
		t.Fatal("late cancellation issued eligibility", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	armed := false
	h, err = f.issue(context.Background(), func(context.Context) error {
		if armed {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	armed = true
	if got, err := f.read(ctx, h); !errors.Is(err, context.Canceled) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("late cancellation returned eligibility", err)
	}
}

func TestVelocityEligibilityCopiesAreCurrentAndRedacted(t *testing.T) {
	f := newEligibilityChain(t)
	var healthy atomic.Bool
	healthy.Store(true)
	h, err := f.issue(context.Background(), func(context.Context) error {
		if !healthy.Load() {
			return risk.ErrVelocityRecoveryUnavailable
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, original := publicationFacts()
	var wg sync.WaitGroup
	for range 12 {
		copy := h
		wg.Go(func() {
			got, err := f.read(context.Background(), copy)
			if err != nil || got != original {
				t.Error("concurrent copy lost original cut", err)
				return
			}
			got.ReplayThrough = got.ReplayThrough.Add(time.Hour)
			if again, err := f.read(context.Background(), copy); err != nil || again != original {
				t.Error("returned facts mutated owned eligibility", err)
			}
		})
	}
	wg.Wait()
	// Expiry/revocation is the primary checker's authority; core has no clock.
	healthy.Store(false)
	for _, copy := range []risk.VelocityEligibility{h, h} {
		if got, err := f.read(context.Background(), copy); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityClosureBinding{}) {
			t.Fatal("copy renewed original validity", err)
		}
	}
	for _, value := range []any{h, []risk.VelocityEligibility{h}, map[risk.VelocityEligibility]int{h: 1}} {
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("eligibility serialized", err)
		}
	}
	if got := fmt.Sprintf("%#v", h); got != "risk.velocityRecovery(redacted)" {
		t.Fatal("eligibility leaked custody", got)
	}
	for _, role := range []any{f.j, f.n, f.v} {
		if reflect.TypeOf(h).ConvertibleTo(reflect.TypeOf(role)) {
			t.Fatal("eligibility promoted to another role")
		}
	}
}
