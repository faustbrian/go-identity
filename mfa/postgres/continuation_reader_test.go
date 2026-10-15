package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func TestContinuationReaderRejectsUnownedResourcesAndZeroGrant(t *testing.T) {
	for _, duration := range []time.Duration{0, time.Second, 6 * time.Second} {
		if _, err := NewContinuationReader(nil, duration); err == nil {
			t.Fatal("reader accepted absent primary resource")
		}
	}
	var reader *ContinuationReader
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := reader.Read(ctx, capability.Grant{}, "https://identity.test"); err == nil {
			t.Fatal("unverified scope acquired continuation")
		}
	}
}
