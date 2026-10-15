package magiclinkpostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
)

func TestRequestRateSourceUsesFrozenAddressPolicyWithoutAuthority(t *testing.T) {
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
		ID: "magic-mail-v1", Version: 1, Unicode: identifier.UnicodeNormalizationNFC,
		CaseFold: true, MaximumBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: profile})
	if err != nil {
		t.Fatal(err)
	}
	// No pool, directory, issuer, risk or sender is supplied: normalization
	// precedes those owners and cannot expose account existence.
	s := &RequestService{config: func() RequestConfig { return RequestConfig{Address: parser} }}
	for _, raw := range []email.AddressInput{"Person@EXAMPLE.TEST", "person@example.test"} {
		got, err := s.RequestRateSource(context.Background(), raw)
		if err != nil || got != "person@example.test" {
			t.Fatal("canonical rate source differs from request policy", err)
		}
	}
	for _, raw := range []email.AddressInput{"", "Person <person@example.test>", "person@example.test\n", "a@b@c"} {
		if got, err := s.RequestRateSource(context.Background(), raw); err == nil || got != "" {
			t.Fatal("invalid source admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.RequestRateSource(ctx, "person@example.test"); got != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled normalization exposed source", err)
	}
	if got, err := s.RequestRateSource(nil, "person@example.test"); got != "" || err == nil {
		t.Fatal("nil context admitted")
	}
	var absent *RequestService
	if got, err := absent.RequestRateSource(context.Background(), "person@example.test"); got != "" || err == nil {
		t.Fatal("absent configuration admitted")
	}
	for _, unavailable := range []*RequestService{
		{},
		{config: func() RequestConfig { return RequestConfig{} }},
		{config: func() RequestConfig { panic("private configuration") }},
	} {
		if got, err := unavailable.RequestRateSource(context.Background(), "person@example.test"); got != "" || err == nil {
			t.Fatal("unavailable parser exposed source")
		}
	}
}

func TestPublicRequestRequiresNativeComposition(t *testing.T) {
	if s, err := NewRequestService(nil, RequestConfig{}, nil); err == nil || s != nil {
		t.Fatal("zero composition constructed")
	}
	var s *RequestService
	if out, err := s.Request(context.Background(), magiclink.RequestRequest{}); err == nil || out != (magiclink.RequestResult{}) {
		t.Fatal("zero service acknowledged work")
	}
}

func TestRequestReceiptPreservesKnownCommitWithError(t *testing.T) {
	id, _ := identity.NewCommandID()
	cause := context.Canceled
	out, err := requestReceipt(id, identity.CommandResult{Outcome: identity.CommitOutcomeCommitted, Feature: &identity.FeatureReceipt{Operation: requestOperation()}}, cause)
	if !errors.Is(err, cause) || out.Validate() != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID != id || !out.Accepted {
		t.Fatal("known committed request discarded after response failure", err)
	}
}
