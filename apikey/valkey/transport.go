package apikeyvalkey

import (
	"context"
	"strconv"
	"strings"

	"github.com/faustbrian/go-identity/apikey"
	valkey "github.com/valkey-io/valkey-go"
)

func (c *Cache) withClient(ctx context.Context, call func(context.Context, valkey.Client) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, c.state.config.CacheTimeout)
	defer cancel()
	client, err := c.client(bounded)
	if err != nil {
		return ErrUnavailable
	}
	defer client.Close()
	if err := call(bounded, client); err != nil {
		return ErrUnavailable
	}
	return nil
}

// Topology observations are transport selection, never owner/quota authority.
// Repeat them on each fresh operation client; promotion/redirects are not used.
func primaryClient(ctx context.Context, client valkey.Client) error {
	cluster, err := client.Do(ctx, client.B().Arbitrary("INFO").Args("cluster").Build()).ToString()
	if err != nil || len(cluster) > 8192 || !strings.Contains(cluster, "cluster_enabled:0\r\n") {
		return ErrUnavailable
	}
	replication, err := client.Do(ctx, client.B().Arbitrary("INFO").Args("replication").Build()).ToString()
	if err != nil || len(replication) > 32768 || !strings.Contains(replication, "role:master\r\n") {
		return ErrUnavailable
	}
	return nil
}

func (c *Cache) probe(ctx context.Context) error {
	return c.withClient(ctx, func(ctx context.Context, client valkey.Client) error {
		if err := primaryClient(ctx, client); err != nil {
			return err
		}
		value, err := client.Do(ctx, client.B().Ping().Build()).ToString()
		if err != nil || value != "PONG" {
			return ErrUnavailable
		}
		return nil
	})
}

func (c *Cache) read(ctx context.Context, key string) (blob []byte, err error) {
	err = c.withClient(ctx, func(ctx context.Context, client valkey.Client) error {
		if err := primaryClient(ctx, client); err != nil {
			return err
		}
		// GETRANGE bounds a real server's payload before allocation/copy into the
		// codec. The inclusive end deliberately requests one excess byte so an
		// oversized stored value is a miss, not a truncated envelope candidate.
		value, err := client.Do(ctx, client.B().Arbitrary("GETRANGE").Args(key, "0", strconv.Itoa(c.state.config.MaximumPayloadBytes)).Build()).ToString()
		if err != nil || len(value) > c.state.config.MaximumPayloadBytes {
			return ErrUnavailable
		}
		blob = []byte(value)
		return nil
	})
	if err != nil {
		clear(blob)
		return nil, err
	}
	return blob, nil
}

func (c *Cache) publish(ctx context.Context, key string, p apikey.PositiveProjectionPublication) error {
	if len(p.Ciphertext) == 0 || len(p.Ciphertext) > c.state.config.MaximumPayloadBytes {
		return ErrInvalidInput
	}
	return c.withClient(ctx, func(ctx context.Context, client valkey.Client) error {
		if err := primaryClient(ctx, client); err != nil {
			return err
		}
		now := c.now()
		if now.IsZero() || now.Before(p.ReadStartedAt) || !now.Before(p.ValidUntil) {
			return ErrUnavailable
		}
		deadline := p.ValidUntil.UnixMilli() // floor the original absolute deadline
		if deadline <= now.UnixMilli() {
			return ErrUnavailable
		}
		// PXAT cannot acquire a fresh relative TTL while a queued write waits.
		// Server expiry is cleanup only: the codec independently enforces the
		// original authority window, even if cache clocks/contents are stale.
		return client.Do(ctx, client.B().Arbitrary("SET").Args(key, string(p.Ciphertext), "PXAT", strconv.FormatInt(deadline, 10)).Build()).Error()
	})
}
