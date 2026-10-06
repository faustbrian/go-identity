package session

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"
)

// CachedAdmission owns immutable same-process positive Get custody. Zero is a
// miss. Copies preserve the original exclusive deadline and complete Session;
// there is no second authority vector or caller-constructible positive state.
// It stores no raw bearer and owns no cache, goroutine, pool or invalidation
// journal. It is not a serializable cookie/Valkey snapshot or a stateless token.
// Those profiles require their separate authenticated persistence composition.
type CachedAdmission struct{ state *cachedAdmissionState }
type cachedAdmissionState struct{ result GetResult }

// CacheAdmission prepares optional same-service reuse of an authentic Get
// result. maximumAge is 1ms..5m, clipped to the original conservative validity
// and lifetime. The configured trusted clock owns the observation; callers
// cannot select time. Fabricated, modified, foreign-service or expired results
// deny. Promotion/copying never renews freshness or a prior shortened deadline.
func (s *SessionService) CacheAdmission(result GetResult, maximumAge time.Duration) (out CachedAdmission, err error) {
	defer func() {
		if recover() != nil {
			out, err = CachedAdmission{}, ErrUnavailable
		}
	}()
	if s == nil || issuerNil(s.config.Clock) || maximumAge < time.Millisecond || maximumAge > 5*time.Minute {
		return out, ErrInvalidInput
	}
	if result.validity == nil || result.validity.owner != s {
		return out, ErrUnauthenticated
	}
	now := s.config.Clock.Now()
	if result.ValidateAt(now) != nil {
		return out, ErrUnauthenticated
	}
	p := *result.validity
	if cap := now.Add(maximumAge); cap.Before(p.until) {
		p.until = cap
	}
	result.validity = &p
	return CachedAdmission{&cachedAdmissionState{result}}, nil
}

// GetCached reuses only an exact same-service tenant, credential digest and
// transport until its original exclusive deadline. It never manufactures a
// new lease. Zero, stale, foreign or substituted cache entries invoke bounded
// authoritative Get with the original request; a failed refresh never falls
// back to stale positive evidence. Lost invalidation events cannot extend the
// source read's at-most-20s evidence window. Explicit current invalidation may
// discard the handle sooner. Caller cancellation and backward clocks deny.
// This is opt-in same-process admission reuse, not serialized cookie caching.
func (s *SessionService) GetCached(ctx context.Context, request GetRequest, cached CachedAdmission) (out GetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = GetResult{}, ErrUnavailable
		}
	}()
	if s == nil || s.reader == nil || issuerNil(s.config.Clock) || ctx == nil || !authorityKey(string(request.TenantID), 128) || request.Credential.token.state == nil || (request.Credential.kind != CredentialCookie && request.Credential.kind != CredentialBearer) {
		return out, ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	now := s.config.Clock.Now()
	if !validTime(now) {
		return out, ErrUnavailable
	}
	if cached.state != nil {
		entry := cached.state.result
		p := entry.validity
		if p != nil && p.owner == s && now.Before(p.acceptedAt) {
			return out, ErrUnavailable
		}
		if p != nil && p.owner == s && p.transport == request.Credential.kind && entry.ValidateAt(now) == nil {
			spec, e := entry.Session.Bindings()
			if e == nil && spec.TenantID == request.TenantID && spec.Audience == s.config.Audience {
				matched := 0
				for _, key := range s.config.LookupKeys {
					if key.state != nil && key.state.version == spec.Lookup.KeyVersion {
						digest, e := request.Credential.token.Digest(key, string(request.TenantID))
						if e == nil {
							matched |= subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:])
						}
					}
				}
				if matched == 1 {
					final := s.config.Clock.Now()
					if bounded.Err() != nil {
						return out, sessionReadFailure(bounded)
					}
					if !validTime(final) || final.Before(now) {
						return out, ErrUnavailable
					}
					if entry.ValidateAt(final) == nil {
						return entry, nil
					}
				}
			}
		}
	}
	return s.Get(bounded, request)
}

// Format redacts correlation and original authentication custody.
func (CachedAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.CachedAdmission(redacted)"))
}

// MarshalJSON denies turning process custody into an unauthenticated cache blob.
func (CachedAdmission) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit cache/map-key export.
func (CachedAdmission) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
