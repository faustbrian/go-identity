package passwordpostgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identifier"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
)

func TestNativeSignupRateSource(t *testing.T) {
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "signup-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: profile, PreserveDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &SignupService{config: func() SignupConfig {
		return SignupConfig{Repository: Config{MaximumDuration: time.Second}, Address: parser}
	}}
	for _, raw := range []password.SignupAddressInput{"Person@EXAMPLE.test", "e\u0301@example.test"} {
		want, err := parser.Parse(email.AddressInput(raw))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := s.SignupRateSource(context.Background(), raw)
				if err != nil || got != want.Canonical().Record().Value {
					t.Error("rate source differs from creation parser")
				}
			}()
		}
		wg.Wait()
	}
	for _, raw := range []password.SignupAddressInput{"", "not-an-address", "person\n@example.test", password.SignupAddressInput(strings.Repeat("x", 4097)), password.SignupAddressInput(string([]byte{0xff}))} {
		if got, err := s.SignupRateSource(context.Background(), raw); err == nil || got != "" {
			t.Fatal("invalid input disclosed rate source")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.SignupRateSource(canceled, "person@example.test"); !errors.Is(err, context.Canceled) || got != "" {
		t.Fatal("canceled source returned metadata")
	}
	for _, service := range []*SignupService{nil, {}, {config: func() SignupConfig { panic("synthetic configuration failure") }}, {config: func() SignupConfig { return SignupConfig{} }}} {
		if got, err := service.SignupRateSource(context.Background(), "person@example.test"); err == nil || got != "" {
			t.Fatal("unconfigured source returned metadata")
		}
	}
	if got, err := s.SignupRateSource(nil, "person@example.test"); err == nil || got != "" {
		t.Fatal("nil context returned metadata")
	}
}
