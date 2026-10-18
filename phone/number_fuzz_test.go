package phone_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/phone"
)

func FuzzNumberPolicy(f *testing.F) {
	for _, seed := range []string{"+12025550123", "2025550123", "+442079460123", "011442079460123", "+4402079460123", "tel:+12025550123", "+12025550123;ext=1", "２０２５５５０１２３", "\xff", ""} {
		f.Add(seed)
	}
	p, err := phone.NewNumberPolicy(phone.NumberPolicySpec{
		Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64,
		AllowNational: true, DefaultRegion: "US", PreserveDisplay: true,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		n, err := p.Canonicalize(context.Background(), raw)
		if err != nil {
			if _, err := n.Record(); err == nil {
				t.Fatal("partial number escaped denial")
			}
			return
		}
		r, err := n.Record()
		if err != nil || len(r.E164) > 16 || len(r.Display) > 64 || r.Profile != phone.CurrentNumberProfile() {
			t.Fatal("unbounded or unbound result")
		}
		canonical, err := p.Canonicalize(context.Background(), r.E164)
		if err != nil || !canonical.Equal(n) {
			t.Fatal("not a canonical fixed point")
		}
		restored, err := p.Restore(context.Background(), r)
		if err != nil || !restored.Equal(n) || restored.Display() != raw {
			t.Fatal("record did not round trip")
		}
	})
}
