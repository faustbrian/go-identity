package passwordpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identifier/v2"
	"github.com/faustbrian/go-identity/email"
)

func TestNativeResetRequestRateSource(t *testing.T) {
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "reset-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: profile})
	if err != nil {
		t.Fatal(err)
	}
	// No pool, repository or issuer is installed: source normalization must not
	// query an account or require a delivery provider, even for a missing user.
	s := &ResetService{config: func() ResetConfig { return ResetConfig{Repository: Config{MaximumDuration: time.Second}} }, request: &resetRequestRuntime{config: ResetRequestConfig{Address: parser}}}
	for _, raw := range []identifier.Input{"Person@EXAMPLE.test", "e\u0301@example.test", "missing@example.test"} {
		address, err := parser.Parse(email.AddressInput(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.ResetRequestRateSource(context.Background(), raw)
		if err != nil || got != address.Canonical().Record().Value {
			t.Fatal("reset rate source differs from frozen recipient parser", err)
		}
	}
	for _, raw := range []identifier.Input{"", "not-an-address", "person\n@example.test"} {
		if got, err := s.ResetRequestRateSource(context.Background(), raw); err == nil || got != "" {
			t.Fatal("invalid reset source admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.ResetRequestRateSource(ctx, "person@example.test"); !errors.Is(err, context.Canceled) || got != "" {
		t.Fatal("canceled reset source admitted", err)
	}
	if got, err := (&ResetService{}).ResetRequestRateSource(context.Background(), "person@example.test"); err == nil || got != "" {
		t.Fatal("unselected reset request produced rate source")
	}
}
