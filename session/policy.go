// Package session owns shared session lifetime and transport policy. Durable
// session issuance and authentication are separate from these policy values.
package session

import (
	"errors"
	"time"
)

var (
	// ErrInvalidPolicy means configuration, choice or an uninitialized policy
	// cannot safely determine session behavior. It contains no request data.
	ErrInvalidPolicy = errors.New("session: invalid policy")
	// ErrInvalidTime means the supplied authoritative timeline is inconsistent.
	ErrInvalidTime = errors.New("session: invalid timeline")
	// ErrExpired means a session or transport lifetime has ended.
	ErrExpired = errors.New("session: expired")
)

// RememberChoice distinguishes omitted input from both explicit choices.
// Continuations carry RememberPolicy, never this unresolved input.
type RememberChoice uint8

const (
	// RememberDefault resolves through LifetimeConfig.Default exactly once.
	RememberDefault RememberChoice = iota
	// BrowserSession omits cookie persistence and caps authority at 24 hours.
	// Browser restoration can retain session cookies; server expiry still applies.
	BrowserSession
	// PersistentSession permits a persistent cookie bounded by session expiry.
	PersistentSession
)

// LifetimeConfig is explicit deployment policy, not a package default. All
// fields are required. AbsoluteTTL is 15 minutes..30 days, IdleTTL is 5
// minutes..AbsoluteTTL, RefreshAfter is 1 minute..IdleTTL and FreshFor is 15
// minutes..24 hours. Sensitive-operation freshness is a separate stricter gate.
type LifetimeConfig struct {
	Default      RememberChoice
	AbsoluteTTL  time.Duration
	IdleTTL      time.Duration
	RefreshAfter time.Duration
	FreshFor     time.Duration
}

// RememberPolicy is an immutable resolved choice and lifetime policy, safe to
// copy across authentication continuations and concurrent callers. Zero is
// invalid. It is configuration, not authenticated proof or session authority.
type RememberPolicy struct {
	choice                         RememberChoice
	absolute, idle, refresh, fresh time.Duration
}

// ResolveRememberPolicy resolves omitted input once. A browser choice cannot
// be upgraded by a later continuation: retain the returned value unchanged.
// Invalid configuration fails even for explicit choices. No callbacks or IO run.
func ResolveRememberPolicy(choice RememberChoice, c LifetimeConfig) (RememberPolicy, error) {
	if !explicit(c.Default) || c.AbsoluteTTL < 15*time.Minute || c.AbsoluteTTL > 30*24*time.Hour || c.IdleTTL < 5*time.Minute || c.IdleTTL > c.AbsoluteTTL || c.RefreshAfter < time.Minute || c.RefreshAfter > c.IdleTTL || c.FreshFor < 15*time.Minute || c.FreshFor > 24*time.Hour {
		return RememberPolicy{}, ErrInvalidPolicy
	}
	if choice == RememberDefault {
		choice = c.Default
	}
	if !explicit(choice) {
		return RememberPolicy{}, ErrInvalidPolicy
	}
	abs := c.AbsoluteTTL
	if choice == BrowserSession {
		abs = min(abs, 24*time.Hour)
	}
	idle := min(c.IdleTTL, abs)
	return RememberPolicy{choice: choice, absolute: abs, idle: idle, refresh: min(c.RefreshAfter, idle), fresh: min(c.FreshFor, abs)}, nil
}

func explicit(c RememberChoice) bool { return c == BrowserSession || c == PersistentSession }

// Choice returns the resolved explicit choice; zero returns RememberDefault.
func (p RememberPolicy) Choice() RememberChoice { return p.choice }

// AbsoluteTTL returns the immutable lifetime cap; zero returns zero.
func (p RememberPolicy) AbsoluteTTL() time.Duration { return p.absolute }

// Lifetime is a read-only calculation, not authoritative validity evidence.
// Revocation and all authority versions must still be checked by the session
// owner. RefreshDue is advisory: it does not authorize refresh or token rotation.
type Lifetime struct {
	AbsoluteExpiresAt time.Time
	ExpiresAt         time.Time
	RefreshDue        bool
	Fresh             bool
}

// Evaluate computes expiry at authoritative now. issuedAt is original family
// issuance, lastActivity is an authoritative accepted-use timestamp and
// authenticatedAt is the last completed authentication/reauthentication within
// that family. Activity/rotation never resets issuedAt or authenticatedAt.
// Future, pre-issuance, zero and out-of-range times fail closed; equality with
// expiry is expired and equality with freshness end is not fresh. No skew is
// silently granted. Evaluate neither reads nor mutates a store.
func (p RememberPolicy) Evaluate(now, issuedAt, lastActivity, authenticatedAt time.Time) (Lifetime, error) {
	if !explicit(p.choice) {
		return Lifetime{}, ErrInvalidPolicy
	}
	if !validTime(now) || !validTime(issuedAt) || !validTime(lastActivity) || !validTime(authenticatedAt) || issuedAt.After(now) || lastActivity.Before(issuedAt) || lastActivity.After(now) || authenticatedAt.Before(issuedAt) || authenticatedAt.After(now) {
		return Lifetime{}, ErrInvalidTime
	}
	abs := issuedAt.Add(p.absolute)
	idle := lastActivity.Add(p.idle)
	if !validTime(abs) || !validTime(idle) {
		return Lifetime{}, ErrInvalidTime
	}
	expires := abs
	if idle.Before(expires) {
		expires = idle
	}
	if !now.Before(expires) {
		return Lifetime{}, ErrExpired
	}
	return Lifetime{AbsoluteExpiresAt: abs, ExpiresAt: expires, RefreshDue: !now.Before(lastActivity.Add(p.refresh)), Fresh: now.Before(authenticatedAt.Add(p.fresh))}, nil
}

func validTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }
