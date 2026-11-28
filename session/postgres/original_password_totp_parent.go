package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// OriginalPasswordTOTPParentReference identifies an ordinary parent in trusted
// derived-session storage. It is not a transport credential. Callers must not
// build it from request fields or expose it to clients; authenticate the
// derived credential and use its immutable persisted parent link instead.
type OriginalPasswordTOTPParentReference struct {
	TenantID       identity.TenantID
	ActorID        identity.UserID
	SessionID      string
	SessionVersion uint64
	Lookup         session.TokenDigest
}

// Format redacts correlated identifiers and the lookup digest.
func (OriginalPasswordTOTPParentReference) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.OriginalPasswordTOTPParentReference(redacted)")
}

// MarshalJSON prevents using this trusted storage selector in wire contracts.
func (OriginalPasswordTOTPParentReference) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// OriginalPasswordTOTPParentObservation is a point-in-time liveness check,
// not authentication, a session, or permission to perform any operation.
// ValidUntil is exclusive and cannot exceed the original read budget or the
// effective idle/absolute expiry. Call Observe again for each derived use;
// this value must not be cached or renewed by a downstream consumer.
type OriginalPasswordTOTPParentObservation struct {
	ReadStartedAt time.Time
	ValidUntil    time.Time
	ExpiresAt     time.Time
}

// OriginalPasswordTOTPParentObserver reads only the borrowed primary through
// the normal password+MFA authority graph. It owns no pool, key, clock,
// transaction, cache or worker. It never accepts or returns a bearer.
type OriginalPasswordTOTPParentObserver struct {
	reader      *primarySessionReader
	uncertainty time.Duration
}

// Format hides the native runtime graph in diagnostics.
func (OriginalPasswordTOTPParentObserver) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.OriginalPasswordTOTPParentObserver(redacted)")
}

// MarshalJSON denies implicit serialization of the native runtime graph.
func (OriginalPasswordTOTPParentObserver) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewOriginalPasswordTOTPParentObserver selects the primary stateful profile.
// Lookup keys are not required here because only already-custodied, exact
// lookup digests are read, never credential bytes. No I/O occurs here.
func NewOriginalPasswordTOTPParentObserver(pool *database.Pool, c SessionServiceConfig) (*OriginalPasswordTOTPParentObserver, error) {
	validation := c.Validation
	if validation.Profile != session.StorageStatefulOpaque || nilIssueDependency(validation.Clock) ||
		validation.MaximumDuration < time.Millisecond || validation.MaximumDuration > 5*time.Second ||
		validation.ClockUncertainty < time.Millisecond || validation.ClockUncertainty > 5*time.Second {
		return nil, session.ErrInvalidInput
	}
	reader, _, err := newPasswordSessionReader(pool, c, true)
	if err != nil {
		return nil, err
	}
	return &OriginalPasswordTOTPParentObserver{reader: reader, uncertainty: validation.ClockUncertainty}, nil
}

// Observe freshly rechecks the exact linked ordinary password+TOTP session
// and all its native authority. It never falls back to another parent, factor,
// tenant or digest. Missing, expired, inactive or changed authority denies;
// store or clock failure returns no positive observation.
func (o *OriginalPasswordTOTPParentObserver) Observe(ctx context.Context, ref OriginalPasswordTOTPParentReference) (OriginalPasswordTOTPParentObservation, error) {
	if o == nil || o.reader == nil || ctx == nil || !scopeID(string(ref.TenantID)) || !scopeID(string(ref.ActorID)) ||
		!scopeID(ref.SessionID) || ref.SessionVersion == 0 || ref.Lookup.KeyVersion == 0 || ref.Lookup.Sum == ([32]byte{}) {
		return OriginalPasswordTOTPParentObservation{}, session.ErrInvalidInput
	}
	r := o.reader
	bounded, stop := context.WithTimeout(ctx, r.native.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return OriginalPasswordTOTPParentObservation{}, err
	}
	before := r.clock.Now()
	if !sessionReadTime(before) {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnavailable
	}
	observation, err := r.ObserveSession(bounded, session.SessionLookup{TenantID: ref.TenantID, Digests: []session.TokenDigest{ref.Lookup}})
	if cancelErr := bounded.Err(); cancelErr != nil {
		return OriginalPasswordTOTPParentObservation{}, cancelErr
	}
	if errors.Is(err, session.ErrUnauthenticated) {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnauthenticated
	}
	if err != nil {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnavailable
	}
	return o.checkObservation(ref, observation, before, r.clock.Now())
}

func (o *OriginalPasswordTOTPParentObserver) checkObservation(ref OriginalPasswordTOTPParentReference, observed session.SessionObservation, before, now time.Time) (OriginalPasswordTOTPParentObservation, error) {
	if !sessionReadTime(now) || now.Before(before) {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnavailable
	}
	if !observed.Active {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnauthenticated
	}
	spec, err := observed.Session.Bindings()
	if err != nil {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnavailable
	}
	factor, err := observed.Session.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" || spec.Authentication.Kind != session.AuthenticationVerified ||
		spec.Authentication.Proof.Method != "password" || spec.Authentication.Proof.Purpose != session.PasswordMFAPrimaryPurpose ||
		spec.TenantID != ref.TenantID || spec.UserID != ref.ActorID || spec.SessionID != ref.SessionID ||
		spec.Version != ref.SessionVersion || spec.Audience != o.reader.profile.Audience ||
		spec.Lookup.KeyVersion != ref.Lookup.KeyVersion || subtle.ConstantTimeCompare(spec.Lookup.Sum[:], ref.Lookup.Sum[:]) != 1 {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnauthenticated
	}
	if _, err := observed.Current.Bindings(); err != nil {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnavailable
	}
	if spec.Authority.CompareCurrent(observed.Current) != nil {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnauthenticated
	}
	const maximumEvidenceAge = 20 * time.Second
	start, until := observed.ReadStartedAt, observed.ValidUntil
	if !sessionReadTime(start) || !sessionReadTime(until) || !until.After(start) ||
		until.After(start.Add(maximumEvidenceAge)) || start.After(now.Add(o.uncertainty)) {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnavailable
	}
	lifetime, err := observed.Session.Lifetime(now)
	if err != nil {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnauthenticated
	}
	// Exclude read delay and clock uncertainty; neither callback completion
	// nor another wrapper can renew the original primary observation.
	until = minTime(until, before.Add(maximumEvidenceAge)).Add(-o.uncertainty)
	until = minTime(until, lifetime.ExpiresAt)
	if !sessionReadTime(until) || !now.Before(until) {
		return OriginalPasswordTOTPParentObservation{}, session.ErrUnauthenticated
	}
	return OriginalPasswordTOTPParentObservation{ReadStartedAt: start.UTC(), ValidUntil: until.UTC(), ExpiresAt: lifetime.ExpiresAt.UTC()}, nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
