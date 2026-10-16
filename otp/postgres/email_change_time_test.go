package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-identity/email"
)

func TestEmailChangeConservesInitiatingSessionExpiry(t *testing.T) {
	_, _, _, original := nativeSessionFixture(t)
	b, _ := original.Bindings()
	o := email.ChangeOrigin{Session: original}
	o.Spec.IssuedAt = b.IssuedAt.Add(time.Minute)
	lifetime, err := original.Lifetime(o.Spec.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	// Existing capability timestamps are whole seconds, unlike the retained
	// session record. Derivation must not misclassify that rounded not-before
	// as evidence that the authentic session was issued in the future.
	o.Spec.IssuedAt = b.IssuedAt.Truncate(time.Second)
	for _, deadline := range []time.Time{lifetime.ExpiresAt.Add(-time.Minute), lifetime.ExpiresAt.Add(time.Minute)} {
		o.Spec.ExpiresAt = deadline
		expiry, err := originalChangeExpiry(o)
		want := deadline
		if lifetime.ExpiresAt.Before(want) {
			want = lifetime.ExpiresAt
		}
		if err != nil || !expiry.Equal(want) {
			t.Fatal("original session validity was extended", err)
		}
		p := emailChangeSendProfile{origin: o, expiresAt: expiry}
		for _, now := range []time.Time{want.Add(-time.Nanosecond), want, want.Add(time.Nanosecond)} {
			if p.validAt(now) != now.Before(want) {
				t.Fatal("original validity lost exclusive expiry")
			}
		}
		if p.validAt(o.Spec.IssuedAt.Add(-time.Nanosecond)) {
			t.Fatal("future original change became valid")
		}
	}
}
