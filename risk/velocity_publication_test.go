package risk_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func publicationFacts() (risk.VelocityLeaseBinding, risk.VelocityClosureBinding) {
	lease, _ := recoveryFacts()
	through := lease.ExpiresAt.Add(-time.Second)
	return lease, risk.VelocityClosureBinding{ID: [32]byte{5}, Position: 0, ReplayFrom: through.Add(-2 * time.Hour), ReplayThrough: through, JournalStartedAt: through.Add(-time.Hour), MaximumWindow: time.Hour}
}

func TestVelocityPublicationPublicExactCustody(t *testing.T) {
	j, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	var live atomic.Bool
	live.Store(true)
	check := func(context.Context) error {
		if !live.Load() {
			return errors.New("private primary closure diagnostic")
		}
		return nil
	}
	lease, err := j.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	closure, err := j.Closure(lease, b, check)
	if err != nil {
		t.Fatal("covered closure not issued", err)
	}
	got, err := reader.Closure(context.Background(), lease, closure)
	if err != nil || got != b {
		t.Fatal("original closure changed", err)
	}
	publication, err := native.AcknowledgePublication(context.Background(), lease, closure)
	if err != nil {
		t.Fatal("exact publication not acknowledged", err)
	}
	got, err = verifier.Publication(context.Background(), lease, closure, publication)
	if err != nil || got != b {
		t.Fatal("publication lost original coverage", err)
	}
	b.Position = 99
	got.Position = 98
	got, err = verifier.Publication(context.Background(), lease, closure, publication)
	if err != nil || got.Position != 0 {
		t.Fatal("public mutation changed original cut", err)
	}
	replacement, err := j.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Closure(context.Background(), replacement, closure); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("equal-fields replacement rebound closure", err)
	}
	_, same := publicationFacts()
	other, err := j.Closure(lease, same, check)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Publication(context.Background(), lease, other, publication); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("publication substituted equal-fields closure", err)
	}
	fj, fr, fn, fv := risk.NewVelocityRecoveryAuthorities()
	fl, err := fj.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	fc, err := fj.Closure(fl, same, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	fp, err := fn.AcknowledgePublication(context.Background(), fl, fc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fn.AcknowledgePublication(context.Background(), lease, closure); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign native manufactured publication", err)
	}
	if _, err := verifier.Publication(context.Background(), lease, closure, fp); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign publication admitted", err)
	}
	if _, err := fr.Closure(context.Background(), lease, closure); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign reader disclosed closure", err)
	}
	if _, err := fv.Publication(context.Background(), lease, closure, publication); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign verifier disclosed publication", err)
	}
	live.Store(false)
	if p, err := native.AcknowledgePublication(context.Background(), lease, closure); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || p != (risk.VelocityPublication{}) {
		t.Fatal("stale closure issued publication", err)
	}
	if got, err := verifier.Publication(context.Background(), lease, closure, publication); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("stale publication returned facts", err)
	}
	for _, value := range []any{j, reader, verifier, closure, same, publication} {
		if reflect.TypeOf(value).ConvertibleTo(reflect.TypeOf(native)) {
			t.Fatal("public role promoted to native issuer")
		}
	}
}

func TestVelocityPublicationPublicBounds(t *testing.T) {
	j, _, _, _ := risk.NewVelocityRecoveryAuthorities()
	lb, original := publicationFacts()
	lease, err := j.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*risk.VelocityClosureBinding){
		func(b *risk.VelocityClosureBinding) { b.ID = [32]byte{} },
		func(b *risk.VelocityClosureBinding) { b.Position = -1 },
		func(b *risk.VelocityClosureBinding) { b.MaximumWindow = 0 },
		func(b *risk.VelocityClosureBinding) { b.MaximumWindow = time.Hour - time.Microsecond },
		func(b *risk.VelocityClosureBinding) { b.MaximumWindow = time.Hour + time.Microsecond },
		func(b *risk.VelocityClosureBinding) { b.ReplayFrom = b.ReplayThrough },
		func(b *risk.VelocityClosureBinding) {
			b.ReplayFrom = b.ReplayThrough.Add(-time.Hour + time.Microsecond)
		},
		func(b *risk.VelocityClosureBinding) {
			b.JournalStartedAt = b.ReplayThrough.Add(-time.Hour + time.Microsecond)
		},
		func(b *risk.VelocityClosureBinding) { b.ReplayThrough = lb.ExpiresAt },
		func(b *risk.VelocityClosureBinding) { b.ReplayThrough = lb.ExpiresAt.Add(time.Microsecond) },
		func(b *risk.VelocityClosureBinding) { b.ReplayFrom = time.Time{} },
		func(b *risk.VelocityClosureBinding) { b.JournalStartedAt = time.Time{} },
		func(b *risk.VelocityClosureBinding) { b.ReplayThrough = time.Time{} },
		func(b *risk.VelocityClosureBinding) { b.ReplayFrom = b.ReplayFrom.Add(time.Nanosecond) },
		func(b *risk.VelocityClosureBinding) { b.ReplayThrough = b.ReplayThrough.Add(time.Nanosecond) },
		func(b *risk.VelocityClosureBinding) { b.JournalStartedAt = b.JournalStartedAt.Add(time.Nanosecond) },
	} {
		b := original
		change(&b)
		if got, err := j.Closure(lease, b, func(context.Context) error { return nil }); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || got != (risk.VelocityClosure{}) {
			t.Fatal("malformed coverage issued", err)
		}
	}
	for _, position := range []int64{0, 1, math.MaxInt64} {
		b := original
		b.Position = position
		if _, err := j.Closure(lease, b, func(context.Context) error { return nil }); err != nil {
			t.Fatal("bounded progress rejected", err)
		}
	}
	// A traversal origin older than journal provenance is valid: the final full
	// window is covered without falsely claiming the earlier interval.
	for _, extra := range []time.Duration{0, time.Microsecond, time.Hour} {
		b := original
		b.JournalStartedAt = b.ReplayThrough.Add(-time.Hour - extra)
		if _, err := j.Closure(lease, b, func(context.Context) error { return nil }); err != nil {
			t.Fatal("full coverage rejected", err)
		}
	}
	if _, err := j.Closure(lease, original, nil); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("missing checker accepted", err)
	}
	if _, err := (risk.VelocityJournalIssuer{}).Closure(lease, original, func(context.Context) error { return nil }); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero issuer accepted", err)
	}
	if _, err := j.Closure(risk.VelocityLease{}, original, func(context.Context) error { return nil }); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero lease accepted", err)
	}
}

func TestVelocityPublicationPublicOriginalLeaseInvalidation(t *testing.T) {
	j, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	var live atomic.Bool
	live.Store(true)
	lease, err := j.Lease(lb, func(context.Context) error {
		if !live.Load() {
			return errors.New("private original lease diagnostic")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The closure checker deliberately remains successful. Its check must not
	// substitute for independent current ownership of the original lease.
	closure, err := j.Closure(lease, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	publication, err := native.AcknowledgePublication(context.Background(), lease, closure)
	if err != nil {
		t.Fatal(err)
	}
	live.Store(false)
	if got, err := reader.Closure(context.Background(), lease, closure); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("lost original ownership disclosed covered cut", err)
	}
	if got, err := native.AcknowledgePublication(context.Background(), lease, closure); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityPublication{}) {
		t.Fatal("lost original ownership issued publication", err)
	}
	if got, err := verifier.Publication(context.Background(), lease, closure, publication); !errors.Is(err, risk.ErrVelocityRecoveryUnavailable) || got != (risk.VelocityClosureBinding{}) {
		t.Fatal("lost original ownership verified publication", err)
	}
}

func TestVelocityPublicationPublicConcurrentCopies(t *testing.T) {
	j, _, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	lease, err := j.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	closure, err := j.Closure(lease, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for index := range 16 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			t.Parallel()
			p, err := native.AcknowledgePublication(context.Background(), lease, closure)
			if err != nil {
				t.Fatal(err)
			}
			got, err := verifier.Publication(context.Background(), lease, closure, p)
			if err != nil || got != b {
				t.Fatal("concurrent original cut changed", err)
			}
			got.Position++
			fresh, err := verifier.Publication(context.Background(), lease, closure, p)
			if err != nil || fresh != b {
				t.Fatal("parallel copy changed custody", err)
			}
		})
	}
}

func TestVelocityPublicationPublicCancellationAndRedaction(t *testing.T) {
	j, reader, native, verifier := risk.NewVelocityRecoveryAuthorities()
	lb, b := publicationFacts()
	var checks atomic.Int64
	lease, err := j.Lease(lb, func(context.Context) error { checks.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	closure, err := j.Closure(lease, b, func(context.Context) error { checks.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	publication, err := native.AcknowledgePublication(context.Background(), lease, closure)
	if err != nil {
		t.Fatal(err)
	}
	checks.Store(0)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, done := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer done()
	for _, ctx := range []context.Context{nil, canceled, expired} {
		want := risk.ErrInvalidVelocityRecovery
		if ctx != nil {
			want = ctx.Err()
		}
		if got, err := reader.Closure(ctx, lease, closure); !errors.Is(err, want) || got != (risk.VelocityClosureBinding{}) {
			t.Fatal("invalid context disclosed cut", err)
		}
		if got, err := native.AcknowledgePublication(ctx, lease, closure); !errors.Is(err, want) || got != (risk.VelocityPublication{}) {
			t.Fatal("invalid context issued publication", err)
		}
		if got, err := verifier.Publication(ctx, lease, closure, publication); !errors.Is(err, want) || got != (risk.VelocityClosureBinding{}) {
			t.Fatal("invalid context disclosed publication", err)
		}
	}
	if checks.Load() != 0 {
		t.Fatal("invalid context reached primary")
	}
	for _, failure := range []error{fmt.Errorf("wrapped: %w", context.Canceled), fmt.Errorf("wrapped: %w", context.DeadlineExceeded), errors.New("private closure diagnostic")} {
		failed, err := j.Closure(lease, b, func(context.Context) error { return failure })
		if err != nil {
			t.Fatal(err)
		}
		want := risk.ErrVelocityRecoveryUnavailable
		if errors.Is(failure, context.Canceled) {
			want = context.Canceled
		}
		if errors.Is(failure, context.DeadlineExceeded) {
			want = context.DeadlineExceeded
		}
		if got, err := native.AcknowledgePublication(context.Background(), lease, failed); !errors.Is(err, want) || got != (risk.VelocityPublication{}) {
			t.Fatal("failed primary check granted publication", err)
		}
	}
	during, stop := context.WithCancel(context.Background())
	late, err := j.Closure(lease, b, func(context.Context) error { stop(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got, err := native.AcknowledgePublication(during, lease, late); !errors.Is(err, context.Canceled) || got != (risk.VelocityPublication{}) {
		t.Fatal("cancellation during closure check ignored", err)
	}
	for _, value := range []any{b, closure, publication, risk.VelocityClosureBinding{}, risk.VelocityClosure{}, risk.VelocityPublication{}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if out := fmt.Sprintf(format, value); !strings.Contains(out, "redacted") || strings.Contains(out, "2026") || strings.Contains(out, "tenant") {
				t.Fatal("publication custody disclosed facts")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("publication custody JSON serialized", err)
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("publication custody text serialized", err)
		}
	}
	if _, err := (risk.VelocityNativeIssuer{}).AcknowledgePublication(context.Background(), lease, closure); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero native issuer accepted", err)
	}
	if _, err := native.AcknowledgePublication(context.Background(), lease, risk.VelocityClosure{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero closure accepted", err)
	}
	if _, err := verifier.Publication(context.Background(), lease, closure, risk.VelocityPublication{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero publication accepted", err)
	}
}
