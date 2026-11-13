package sessionvalkey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	cache "github.com/faustbrian/go-identity/session/valkey"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func TestUnsupportedProfilesRejectBeforeNetwork(t *testing.T) {
	for _, profile := range []string{"authoritative", "secondary-source", "offline-fallback", "cache-only", ""} {
		_, err := cache.New(context.Background(), cache.Config{Profile: profile, Topology: "standalone"}, nil, &clock{time.Now()})
		if !errors.Is(err, cache.ErrInvalidInput) {
			t.Fatal("unsupported authority profile accepted", profile, err)
		}
	}
	for _, topology := range []string{"cluster", "replica", "sentinel", ""} {
		_, err := cache.New(context.Background(), cache.Config{Profile: "positive-cache", Topology: topology}, nil, &clock{time.Now()})
		if !errors.Is(err, cache.ErrInvalidInput) {
			t.Fatal("unsupported topology accepted", topology, err)
		}
	}
}

func TestZeroCheckpointCannotFill(t *testing.T) {
	var c *cache.Cache
	if filled, err := c.Fill(context.Background(), cache.Checkpoint{}, session.GetResult{}); filled || !errors.Is(err, cache.ErrInvalidInput) {
		t.Fatal("zero cache/checkpoint produced a fill", err)
	}
}

func TestZeroCacheRejectsWorkAndClosesSafely(t *testing.T) {
	var nilCache *cache.Cache
	nilCache.Close()
	c := new(cache.Cache)
	c.Close()
	c.Close()
	if _, err := c.Get(context.Background(), session.GetRequest{}); !errors.Is(err, cache.ErrInvalidInput) {
		t.Fatal("zero cache admitted Get", err)
	}
	if _, err := c.Checkpoint(context.Background(), session.GetRequest{}); !errors.Is(err, cache.ErrInvalidInput) {
		t.Fatal("zero cache captured generation", err)
	}
	if err := c.Invalidate(context.Background(), "tenant", "session"); !errors.Is(err, cache.ErrInvalidInput) {
		t.Fatal("zero cache invalidated", err)
	}
	if err := c.InvalidateFamily(nil, "tenant", "family"); !errors.Is(err, cache.ErrInvalidInput) {
		t.Fatal("nil context accepted", err)
	}
}
