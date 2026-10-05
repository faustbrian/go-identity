package i18n

import (
	"context"
	"fmt"
	identity "github.com/faustbrian/go-identity"
	"math"
	"reflect"
	"slices"
	"time"
	"unicode/utf8"
)

// PreferenceKey binds exact personal-data tenant and subject identities. IDs
// retain their original bytes; structural validity never grants access.
type PreferenceKey struct {
	TenantID  identity.TenantID
	SubjectID identity.UserID
}

// Preference is an immutable versioned durable projection, not a fallback.
// Versions are positive. Locale is canonical and explicitly supported.
type Preference struct {
	TenantID             identity.TenantID
	SubjectID            identity.UserID
	Locale               string
	Version              uint64
	ConsentNoticeVersion uint64
}

// PreferenceCommand binds one idempotent optimistic mutation. ExpectedVersion
// zero means create only; preserve CommandID and all fields across retries.
// The store must reject altered same-ID commands and lifecycle resurrection.
// Positive ConsentNoticeVersion records accepted notice, not proof of consent.
type PreferenceCommand struct {
	Key                  PreferenceKey
	ExpectedVersion      uint64
	Locale               string
	ConsentNoticeVersion uint64
	CommandID            identity.CommandID
}

func (PreferenceKey) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.PreferenceKey(redacted)"))
}
func (Preference) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("i18n.Preference(redacted)")) }
func (PreferenceCommand) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.PreferenceCommand(redacted)"))
}

// PreferenceStore is the consumer-owned durable authority. Operations must be
// bounded by context and concurrent-safe. Get never persists fallback; absence
// is PreferenceNotFoundError. Set atomically checks expected version, canonical
// ID/notice policy, supported locale and lifecycle fences, and persists command
// identity with its exact result. Same-ID replays return the original projection
// even after later writes; altered same-ID commands conflict. Unknown commits
// must be reconciled by that same command, never a new write identity. This
// interface does not authorize callers or acknowledge lifecycle closure.
type PreferenceStore interface {
	GetPreference(context.Context, PreferenceKey) (Preference, error)
	SetPreference(context.Context, PreferenceCommand) (Preference, error)
}

// PreferenceInputError classifies malformed/bounded policy input before IO.
type PreferenceInputError struct{}

func (PreferenceInputError) Error() string { return "identity.i18n: invalid preference input" }

// PreferenceNotFoundError is explicit durable absence, never an inferred locale.
type PreferenceNotFoundError struct{}

func (PreferenceNotFoundError) Error() string { return "identity.i18n: preference absent" }

// PreferenceConflictError promises no new write committed for this attempt.
// Existing same-command results must be returned instead of this classification.
type PreferenceConflictError struct{}

func (PreferenceConflictError) Error() string { return "identity.i18n: preference conflict" }

// PreferenceDeniedError is an authoritative no-write policy/lifecycle denial.
type PreferenceDeniedError struct{}

func (PreferenceDeniedError) Error() string { return "identity.i18n: preference denied" }

// PreferenceUnavailableError redacts read-provider or invalid-projection failure.
type PreferenceUnavailableError struct{}

func (PreferenceUnavailableError) Error() string { return "identity.i18n: preference unavailable" }

// PreferenceOutcomeUnknownError means a store mutation was invoked without a
// valid committed or explicit no-write result. Reconcile the same CommandID;
// cancellation, panic and malformed output cannot prove rollback. Cause is only
// context cancellation/deadline, never raw provider diagnostics.
type PreferenceOutcomeUnknownError struct {
	CommandID identity.CommandID
	Cause     error
}

func (PreferenceOutcomeUnknownError) Error() string {
	return "identity.i18n: preference outcome unknown"
}
func (e PreferenceOutcomeUnknownError) Unwrap() error { return e.Cause }
func (PreferenceOutcomeUnknownError) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.PreferenceOutcomeUnknownError(redacted)"))
}

// PreferencePolicyConfig supplies the immutable accepted-locale policy and
// bounded store. Timeout must be positive and at most 30 seconds. Supported has
// 1..256 unique canonical locales. Catalog/config migrations must separately
// reconcile durable preferences; this fixed policy never silently changes.
type PreferencePolicyConfig struct {
	Store     PreferenceStore
	Supported []Locale
	Timeout   time.Duration
}

// PreferencePolicy enforces structural mutation/read policy, not authorization.
// The caller must already own an authenticated authorized tenant/subject scope;
// canonical-ID, actual consent/notice authority and lifecycle fences belong to
// the durable operation owner. Reference composition must bind these real
// authorities before exposing methods over HTTP. No callbacks run under locks;
// no retry, inference, fallback persistence or goroutine is hidden here.
type PreferencePolicy struct {
	store     PreferenceStore
	supported []Locale
	timeout   time.Duration
}

var _ PreferenceStore = (*PreferencePolicy)(nil)

// NewPreferencePolicy validates configuration and copies supported locales. A
// store callback must honor its context; no detached timeout wrapper is used.
func NewPreferencePolicy(config PreferencePolicyConfig) (*PreferencePolicy, error) {
	if nilPreferenceStore(config.Store) || config.Timeout <= 0 || config.Timeout > 30*time.Second || len(config.Supported) == 0 || len(config.Supported) > 256 {
		return nil, PreferenceInputError{}
	}
	supported := slices.Clone(config.Supported)
	for i, locale := range supported {
		canonical, err := CanonicalLocale(string(locale))
		if err != nil || canonical != locale || slices.Contains(supported[:i], locale) {
			return nil, PreferenceInputError{}
		}
	}
	return &PreferencePolicy{store: config.Store, supported: supported, timeout: config.Timeout}, nil
}

func nilPreferenceStore(store PreferenceStore) bool {
	if store == nil {
		return true
	}
	// This is only typed-nil detection, not reflection-driven invocation/wiring.
	v := reflect.ValueOf(store)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func validPreferenceKey(key PreferenceKey) bool {
	for _, value := range []string{string(key.TenantID), string(key.SubjectID)} {
		if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
			return false
		}
		for _, r := range value {
			if r <= ' ' || r == 0x7f {
				return false
			}
		}
	}
	return true
}

func (p *PreferencePolicy) validProjection(value Preference, key PreferenceKey) bool {
	locale, err := CanonicalLocale(value.Locale)
	return err == nil && string(locale) == value.Locale && slices.Contains(p.supported, locale) && value.TenantID == key.TenantID && value.SubjectID == key.SubjectID && value.Version > 0 && value.ConsentNoticeVersion > 0
}

// GetPreference never turns absence into a locale or writes. Malformed/cross-
// tenant provider output and panics return zero/unavailable without diagnostics.
func (p *PreferencePolicy) GetPreference(ctx context.Context, key PreferenceKey) (result Preference, err error) {
	defer func() {
		if recover() != nil {
			result, err = Preference{}, PreferenceUnavailableError{}
		}
	}()
	if ctx == nil || p == nil || p.store == nil || !validPreferenceKey(key) {
		return Preference{}, PreferenceInputError{}
	}
	if err := ctx.Err(); err != nil {
		return Preference{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	result, err = p.store.GetPreference(bounded, key)
	if canceled := bounded.Err(); canceled != nil {
		return Preference{}, canceled
	}
	if err != nil {
		switch err.(type) {
		case PreferenceNotFoundError, *PreferenceNotFoundError, PreferenceDeniedError, *PreferenceDeniedError:
			return Preference{}, err
		}
		return Preference{}, PreferenceUnavailableError{}
	}
	if !p.validProjection(result, key) {
		return Preference{}, PreferenceUnavailableError{}
	}
	return result, nil
}

// SetPreference invokes at most one bounded mutation after validating every
// field. A valid result must match command scope/locale/notice and expected+1.
// Unknown failures return zero plus reconciliation identity, never rollback.
func (p *PreferencePolicy) SetPreference(ctx context.Context, cmd PreferenceCommand) (result Preference, err error) {
	invoked := false
	defer func() {
		if recover() != nil {
			result = Preference{}
			if invoked {
				err = PreferenceOutcomeUnknownError{CommandID: cmd.CommandID}
			} else {
				err = PreferenceInputError{}
			}
		}
	}()
	if ctx == nil || p == nil || p.store == nil || !validPreferenceKey(cmd.Key) || cmd.ConsentNoticeVersion == 0 || cmd.ExpectedVersion == math.MaxUint64 {
		return Preference{}, PreferenceInputError{}
	}
	locale, parseErr := CanonicalLocale(cmd.Locale)
	if parseErr != nil || string(locale) != cmd.Locale || !slices.Contains(p.supported, locale) {
		return Preference{}, PreferenceInputError{}
	}
	if _, err := identity.ParseCommandID(string(cmd.CommandID)); err != nil {
		return Preference{}, PreferenceInputError{}
	}
	if err := ctx.Err(); err != nil {
		return Preference{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	invoked = true
	result, err = p.store.SetPreference(bounded, cmd)
	if err != nil {
		switch err.(type) {
		case PreferenceConflictError, *PreferenceConflictError, PreferenceDeniedError, *PreferenceDeniedError, PreferenceInputError, *PreferenceInputError:
			return Preference{}, err
		}
		return Preference{}, PreferenceOutcomeUnknownError{CommandID: cmd.CommandID, Cause: bounded.Err()}
	}
	if !p.validProjection(result, cmd.Key) || result.Locale != cmd.Locale || result.Version != cmd.ExpectedVersion+1 || result.ConsentNoticeVersion != cmd.ConsentNoticeVersion {
		return Preference{}, PreferenceOutcomeUnknownError{CommandID: cmd.CommandID, Cause: bounded.Err()}
	}
	// An exact durable committed result is stronger than a late cancellation.
	return result, nil
}
