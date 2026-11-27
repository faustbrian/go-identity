package postgres

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestProxyPreviewExpectedBindingRetainsOriginalAndAcceptsRetainedKeys(t *testing.T) {
	service, production, original := proxyBindingFixture(t)
	issued := production.IssuedAt.Truncate(time.Second)
	original.Evidence.IssuedAt, original.Evidence.ExpiresAt = issued, issued.Add(5*time.Minute)
	locator := proxyPreviewBindingLocator{Tenant: production.Tenant, Flow: production.Transaction, OriginCommand: production.OriginCommand,
		CallbackCommand: production.CallbackCommand, IssuedAt: issued, ExpiresAt: issued.Add(3 * time.Minute)}
	input := proxyPreviewBinding{Evidence: original.Evidence, PreAuthDigest: sha256.Sum256([]byte("exact preview browser flow")), GlobalVersion: 23, TenantVersion: 29}
	x, first, err := sealProxyPreviewBinding(t.Context(), service, "binding-v1", locator, input)
	if err != nil || len(x) == 0 || bytes.Contains(x, []byte(original.Evidence.ClientID)) {
		t.Fatal("expected preview metadata was not sealed", err)
	}
	y, second, err := sealProxyPreviewBinding(t.Context(), service, "binding-v2", locator, input)
	if err != nil || len(y) == 0 || bytes.Equal(x, y) || first == ([32]byte{}) || first != second {
		t.Fatal("independently sealed binding did not use rotated wrapping key", err)
	}
	for _, wire := range [][]byte{x, y} {
		got, digest, err := openProxyPreviewBinding(t.Context(), service, locator, wire)
		if err != nil || !reflect.DeepEqual(got, input) || digest != first {
			t.Fatal("sealed original changed browser, deadline, authority versions or claims", err)
		}
	}
	shorter := locator
	shorter.ExpiresAt = locator.ExpiresAt.Add(-time.Second)
	wire, clipped, err := sealProxyPreviewBinding(t.Context(), service, "binding-v1", shorter, input)
	if err != nil {
		t.Fatal("original browser is permitted to shorten the preview deadline", err)
	}
	if _, digest, err := openProxyPreviewBinding(t.Context(), service, shorter, wire); err != nil || digest != clipped || digest == first {
		t.Fatal("the native grant commitment did not bind the shortened preview cutoff", err)
	}
	if got, err := openProxyOriginalBinding(t.Context(), service, production, x); !errors.Is(err, errProxyBinding) || got.Evidence.CommandID != "" {
		t.Fatal("production recovered metadata from the preview custody domain", err)
	}
	for name, change := range map[string]func(*proxyPreviewBindingLocator){
		"tenant":    func(l *proxyPreviewBindingLocator) { l.Tenant = "tenant-b" },
		"flow":      func(l *proxyPreviewBindingLocator) { l.Flow = "BAQEBAQEBAQEBAQEBAQEBA" },
		"origin":    func(l *proxyPreviewBindingLocator) { l.OriginCommand = "BAQEBAQEBAQEBAQEBAQEBA" },
		"callback":  func(l *proxyPreviewBindingLocator) { l.CallbackCommand = "BAQEBAQEBAQEBAQEBAQEBA" },
		"admission": func(l *proxyPreviewBindingLocator) { l.IssuedAt = l.IssuedAt.Add(time.Second) },
		"cutoff":    func(l *proxyPreviewBindingLocator) { l.ExpiresAt = l.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			l := locator
			change(&l)
			got, digest, err := openProxyPreviewBinding(t.Context(), service, l, x)
			if !errors.Is(err, errProxyBinding) || got.Evidence.CommandID != "" || digest != ([32]byte{}) {
				t.Fatal("another row recovered expected preview metadata", err)
			}
		})
	}
	x[len(x)-1] ^= 1
	if got, digest, err := openProxyPreviewBinding(t.Context(), service, locator, x); !errors.Is(err, errProxyBinding) || got.Evidence.CommandID != "" || digest != ([32]byte{}) {
		t.Fatal("altered custody disclosed original metadata", err)
	}
}

func TestProxyPreviewExpectedBindingRejectsMissingAuthorityAndExtendedLifetime(t *testing.T) {
	service, production, original := proxyBindingFixture(t)
	issued := production.IssuedAt.Truncate(time.Second)
	original.Evidence.IssuedAt, original.Evidence.ExpiresAt = issued, issued.Add(2*time.Minute)
	locator := proxyPreviewBindingLocator{Tenant: production.Tenant, Flow: production.Transaction, OriginCommand: production.OriginCommand,
		CallbackCommand: production.CallbackCommand, IssuedAt: issued, ExpiresAt: issued.Add(time.Minute)}
	input := proxyPreviewBinding{Evidence: original.Evidence, PreAuthDigest: sha256.Sum256([]byte("exact preview browser flow")), GlobalVersion: 1, TenantVersion: 2}
	for name, change := range map[string]func(*proxyPreviewBindingLocator, *proxyPreviewBinding){
		"browser commitment": func(_ *proxyPreviewBindingLocator, b *proxyPreviewBinding) { b.PreAuthDigest = [32]byte{} },
		"global authority":   func(_ *proxyPreviewBindingLocator, b *proxyPreviewBinding) { b.GlobalVersion = 0 },
		"tenant authority":   func(_ *proxyPreviewBindingLocator, b *proxyPreviewBinding) { b.TenantVersion = 0 },
		"recipient":          func(_ *proxyPreviewBindingLocator, b *proxyPreviewBinding) { b.Evidence.Recipient = "" },
		"state":              func(_ *proxyPreviewBindingLocator, b *proxyPreviewBinding) { b.Evidence.StateDigest = [32]byte{} },
		"extended cutoff": func(l *proxyPreviewBindingLocator, _ *proxyPreviewBinding) {
			l.ExpiresAt = l.IssuedAt.Add(3 * time.Minute)
		},
		"same commands": func(l *proxyPreviewBindingLocator, _ *proxyPreviewBinding) { l.CallbackCommand = l.OriginCommand },
	} {
		t.Run(name, func(t *testing.T) {
			l, b := locator, input
			change(&l, &b)
			if wire, digest, err := sealProxyPreviewBinding(t.Context(), service, "binding-v1", l, b); !errors.Is(err, errProxyBinding) || len(wire) != 0 || digest != ([32]byte{}) {
				t.Fatal("sealed a binding without original preview authority", err)
			}
		})
	}
}
