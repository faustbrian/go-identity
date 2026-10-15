package password

import (
	"context"
	"errors"
	"time"

	primitive "github.com/faustbrian/go-password/v2"
)

// ErrPasswordWork is a redacted pre-mutation failure. It carries no dependency
// diagnostic, account-existence fact, candidate or encoded hash. Cancellation
// is reported separately through the standard context errors.
var ErrPasswordWork = errors.New("identity.password.work_unavailable")

// passwordWork is the shared pre-transaction execution path, not an authority
// or store. The owning workflow freezes it at construction. Screening is an
// owned service closure which completes the configured HIBP/risk decision; it
// is never selected by a request or invoked inside a database transaction.
// The real primitive owns resource admission and cryptography. Dummy custody
// must use the current policy so unknown identities do not skip expensive work.
type passwordWork struct {
	primitive        *primitive.Service
	minimum, maximum uint32
	timeout          time.Duration
	dummy            primitive.EncodedHash
}

func (w passwordWork) valid() bool {
	if w.primitive == nil || w.minimum == 0 || w.maximum < w.minimum || w.maximum > 1<<20 || w.timeout <= 0 || w.timeout > time.Minute {
		return false
	}
	policy := w.primitive.Policy()
	if policy.Algorithm() == "" || int(w.maximum) > policy.Limits().PasswordBytes {
		return false
	}
	parsed, err := primitive.ParseEncodedHash(w.dummy.String(), policy.Limits())
	if err != nil || parsed.Algorithm() != policy.Algorithm() {
		return false
	}
	// NeedsRehash intentionally permits stronger/non-downgradable legacy hashes;
	// dummy work instead requires equality with the selected current profile.
	switch policy.Algorithm() {
	case primitive.Argon2id:
		return parsed.Argon2idParameters() == policy.Argon2idParameters()
	case primitive.Bcrypt:
		return parsed.BcryptCost() == policy.BcryptCost()
	default:
		return false
	}
}

func (w passwordWork) newHash(ctx context.Context, secret primitive.Secret, screen func(context.Context, primitive.Secret) error) (hash primitive.EncodedHash, err error) {
	defer func() {
		if recover() != nil {
			hash = primitive.EncodedHash{}
			err = ErrPasswordWork
		}
	}()
	if ctx == nil || !w.valid() || screen == nil {
		return primitive.EncodedHash{}, ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return primitive.EncodedHash{}, err
	}
	if err := w.admit(secret); err != nil {
		return primitive.EncodedHash{}, err
	}
	// Provider callbacks borrow independently; do not hold Secret.Use while a
	// checker attempts its own borrow, and never hash on incomplete screening.
	if e := screen(ctx, secret); e != nil {
		if err := ctx.Err(); err != nil {
			return primitive.EncodedHash{}, err
		}
		return primitive.EncodedHash{}, ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return primitive.EncodedHash{}, err
	}
	if err := w.admit(secret); err != nil {
		return primitive.EncodedHash{}, err
	}
	e := secret.Use(func(raw []byte) error {
		if len(raw) < int(w.minimum) || len(raw) > int(w.maximum) {
			return ErrInvalidPassword
		}
		var e error
		hash, e = w.primitive.Hash(ctx, raw)
		return e
	})
	if err := ctx.Err(); err != nil {
		return primitive.EncodedHash{}, err
	}
	if e != nil || hash.String() == "" {
		return primitive.EncodedHash{}, ErrPasswordWork
	}
	if err := w.admit(secret); err != nil {
		return primitive.EncodedHash{}, err
	}
	return hash, nil
}

// verify deliberately returns the same zero result/nil error for an unknown
// identity and a known mismatch. A dummy match is always discarded. This is
// comparable hash work, not a wall-clock constant-time promise across legacy
// algorithms, storage or policy. No upgrade, session or proof is issued here.
func (w passwordWork) verify(ctx context.Context, secret primitive.Secret, stored primitive.EncodedHash, known bool) (result primitive.Result, err error) {
	defer func() {
		if recover() != nil {
			result = primitive.Result{}
			err = ErrPasswordWork
		}
	}()
	if ctx == nil || !w.valid() {
		return primitive.Result{}, ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return primitive.Result{}, err
	}
	// Existing passwords may predate the signup minimum; never prevent their
	// verification by applying the new-password minimum.
	if secret.Len() == 0 || secret.Len() > int(w.maximum) {
		return primitive.Result{}, ErrInvalidPassword
	}
	selected := w.dummy
	if known {
		selected = stored
	}
	e := secret.Use(func(raw []byte) error {
		if len(raw) == 0 || len(raw) > int(w.maximum) {
			return ErrInvalidPassword
		}
		var e error
		result, e = w.primitive.Verify(ctx, raw, selected.String())
		return e
	})
	if err := ctx.Err(); err != nil {
		return primitive.Result{}, err
	}
	if secret.Len() == 0 {
		return primitive.Result{}, ErrInvalidPassword
	}
	if e != nil && !errors.Is(e, primitive.ErrMismatch) {
		return primitive.Result{}, ErrPasswordWork
	}
	if !known || e != nil {
		return primitive.Result{}, nil
	}
	return result, nil
}

func (w passwordWork) admit(secret primitive.Secret) error {
	length := secret.Len()
	if length < int(w.minimum) || length > int(w.maximum) {
		return ErrInvalidPassword
	}
	return nil
}
