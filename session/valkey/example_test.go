package sessionvalkey_test

import (
	"context"

	"github.com/faustbrian/go-identity/session"
	cache "github.com/faustbrian/go-identity/session/valkey"
)

func ExampleCache_Get() {
	// The application supplies the existing native service's codec and trusted
	// clock. This adapter never implements SessionReader or accepts public claims.
	use := func(ctx context.Context, config cache.Config, codec *session.EncryptedCacheCodec, clock session.IssuerClock, request session.GetRequest) error {
		projection, err := cache.New(ctx, config, codec, clock)
		if err != nil {
			return err
		}
		defer projection.Close()
		result, err := projection.Get(ctx, request)
		if err != nil {
			return err
		}
		if !result.Authenticated {
			return session.ErrUnauthenticated
		}
		return result.ValidateAt(clock.Now())
	}
	_ = use
}
