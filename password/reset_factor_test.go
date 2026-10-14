package password_test

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/password"
)

func TestResetProfileBindsOriginalFactorGeneration(t *testing.T) {
	c, original := resetProfileFixture(t)
	p, err := password.NewResetProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	now := original.IssuedAt.Add(time.Second)
	for _, version := range []uint64{1, math.MaxUint64} {
		original.FactorVersion = version
		wire, err := p.Payload(original)
		if err != nil || wire.Caveats["password.factor-version"] != strconv.FormatUint(version, 10) {
			t.Fatal("factor generation absent from signed scope", err)
		}
		grant := signResetGrant(t, wire, now)
		got, err := p.ResolveOriginal(grant, now)
		if err != nil || got != original {
			t.Fatal("factor generation changed during original reconstruction", err)
		}
		foreign := original
		foreign.FactorVersion = 0
		if p.Authorize(grant, foreign, now) == nil {
			t.Fatal("factor-bound grant downgraded to legacy scope")
		}
		for _, bad := range []string{"0", "01", "-1", "18446744073709551616"} {
			wire.Caveats["password.factor-version"] = bad
			malformed := signResetGrant(t, wire, now)
			got, err := p.ResolveOriginal(malformed, now)
			if err == nil || got != (password.ResetGrantSpec{}) {
				t.Fatal("noncanonical factor generation returned original intent")
			}
		}
	}
	original.FactorVersion = 0
	legacy, err := p.Payload(original)
	if err != nil || len(legacy.Caveats) != 8 {
		t.Fatal("legacy signed scope changed", err)
	}
	got, err := p.ResolveOriginal(signResetGrant(t, legacy, now), now)
	if err != nil || got != original || got.FactorVersion != 0 {
		t.Fatal("legacy scope fabricated a factor generation", err)
	}
}
