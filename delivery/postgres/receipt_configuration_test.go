package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

type receiptClockFunc func() time.Time

func (f receiptClockFunc) Now() time.Time { return f() }

func TestReceiptConfigurationIsOptInAndRetained(t *testing.T) {
	if auth, source, err := receiptConfiguration(EnqueueConfig{}); auth != nil || source != nil || err != nil {
		t.Fatal("disabled callbacks changed composition")
	}
	_, input, now := receiptAuthFixture(t)
	profile := ReceiptKeyProfile{TenantID: "tenant", Provider: "test-provider", ProviderConfigVersion: 1, ActorID: "provider-actor", KeyID: "callback-key", Key: [32]byte{9}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	config := EnqueueConfig{StateTracking: true, Custody: ContributorConfig{Deployment: "test", ProviderProfiles: map[uint64]ProviderProfile{1: {Provider: "test-provider"}}}, Receipts: &ReceiptAuthenticationConfig{Profiles: []ReceiptKeyProfile{profile}}}
	auth, source, err := receiptConfiguration(config)
	if err != nil || source == nil || auth.maxBytes != 16384 {
		t.Fatal("default owned callback profile", err)
	}
	config.Receipts.Profiles[0].Key = [32]byte{}
	if _, _, err := auth.verify(context.Background(), input, now); err != nil {
		t.Fatal("public credential input retained mutable alias", err)
	}
	config.Receipts.Profiles[0] = profile
	for _, change := range []func(*EnqueueConfig){
		func(c *EnqueueConfig) { c.StateTracking = false },
		func(c *EnqueueConfig) { c.Receipts.Profiles = nil },
		func(c *EnqueueConfig) { c.Receipts.MaxBodyBytes = 255 },
		func(c *EnqueueConfig) { c.Receipts.MaxBodyBytes = 65537 },
		func(c *EnqueueConfig) { c.Receipts.Profiles[0].ProviderConfigVersion = 2 },
		func(c *EnqueueConfig) { c.Receipts.Profiles[0].Provider = "foreign" },
	} {
		candidate := config
		copied := *config.Receipts
		candidate.Receipts = &copied
		candidate.Receipts.Profiles = append([]ReceiptKeyProfile(nil), config.Receipts.Profiles...)
		change(&candidate)
		if a, source, err := receiptConfiguration(candidate); a != nil || source != nil || !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("unsafe callback profile admitted", err)
		}
	}
}

func TestReceiptClockFailureNeverAuthenticatesEvidence(t *testing.T) {
	auth, input, now := receiptAuthFixture(t)
	callback := SignedReceiptCallback{TenantID: "tenant", Provider: input.Provider, ProviderConfigVersion: input.Version, KeyID: input.KeyID, SignedAt: input.SignedAt, Body: input.Body, Signature: input.Signature}
	for _, source := range []receiptClockFunc{func() time.Time { panic("synthetic-clock-failure") }, func() time.Time { return time.Time{} }} {
		e := &receiptExecutor{auth: auth, clock: source}
		got, actor, err := e.authenticate(context.Background(), callback)
		if !errors.Is(err, delivery.ErrUnavailable) || got != (delivery.ReceiptRecordRequest{}) || actor != "" {
			t.Fatal("broken clock supplied evidence")
		}
	}
	e := &receiptExecutor{auth: auth, clock: receiptClockFunc(func() time.Time { return now })}
	if _, actor, err := e.authenticate(context.Background(), callback); err != nil || actor != "provider-actor" {
		t.Fatal("trusted clock denied callback", err)
	}
}
