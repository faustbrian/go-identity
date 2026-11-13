package reference

import (
	"context"
	"fmt"
	"io"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	sessionvalkey "github.com/faustbrian/go-identity/session/valkey"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// SessionCacheConfiguration explicitly selects an encrypted standalone-TLS
// positive projection for ordinary session reads. Nil selection preserves native
// reads. Codec and Valkey must share deployment epoch and compatible payload
// bounds. Valkey.LookupKeys must be empty: composition derives the exact native
// readable keys. EnvelopeKeys and the native clock remain borrowed. The cache
// owns only its transport, constructed during Initialize and drained on Close.
// Protected metadata, signout and mutation consumers always retain the primary.
type SessionCacheConfiguration struct {
	Codec  session.EncryptedCacheConfig
	Valkey sessionvalkey.Config
}

// All fields are immutable except native, published under storeState.mu before
// readiness. Close prevents publication before draining any retained native.
type sessionCacheState struct {
	config sessionvalkey.Config
	codec  *session.EncryptedCacheCodec
	clock  session.IssuerClock
	native *sessionvalkey.Cache
}

func composeSessionCache(selected *SessionCacheConfiguration, native sessionpg.SignOutServiceConfig, primary *session.SessionService, keys envelope.KeyProvider) (*sessionCacheState, error) {
	if selected == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_session_cache"}
	if primary == nil || keys == nil || native.Execution.Clock == nil || len(selected.Valkey.LookupKeys) != 0 {
		return nil, invalid
	}
	c := selected.Valkey
	c.LookupKeys = slices.Clone(native.Validation.LookupKeys)
	c.TrustPEM = slices.Clone(c.TrustPEM)
	if c.Validate() != nil || c.DeploymentEpoch != selected.Codec.DeploymentEpoch || c.MaximumPayloadBytes < selected.Codec.MaximumBytes || c.MaximumDuration > native.MaximumDuration {
		return nil, invalid
	}
	// Get performs a bounded cache read, optional primary fallback, then a
	// best-effort fill. Reserve both cache operations inside the graph budget;
	// cache latency must not consume the primary's configured fallback time.
	primaryBudget := native.Validation.MaximumDuration
	if primaryBudget <= 0 || primaryBudget >= c.MaximumDuration || c.CacheTimeout > (c.MaximumDuration-primaryBudget)/2 {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	codec, err := session.NewEncryptedCacheCodec(primary, crypto, selected.Codec)
	if err != nil {
		return nil, invalid
	}
	return &sessionCacheState{config: c, codec: codec, clock: native.Execution.Clock}, nil
}

// initializeSessionCache acquires transport only after other native startup has
// succeeded. Publication belongs to Initialize's final lifetime/readiness lock.
func (s *sessionCacheState) initialize(ctx context.Context) (*sessionvalkey.Cache, error) {
	if s == nil {
		return nil, nil
	}
	cache, err := sessionvalkey.New(ctx, s.config, s.codec, s.clock)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return cache, nil
}

func (s *sessionCacheState) close() {
	if s != nil && s.native != nil {
		s.native.Close()
	}
}

// Format redacts deployment credentials and transport configuration.
func (SessionCacheConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.SessionCacheConfiguration(redacted)")
}

// MarshalJSON prevents implicit deployment-credential export.
func (SessionCacheConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prevents implicit deployment-credential export.
func (SessionCacheConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
