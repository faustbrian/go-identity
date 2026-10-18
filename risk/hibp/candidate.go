package hibp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	password "github.com/faustbrian/go-password/v2"
)

var errInvalidCandidate = errors.New("hibp: invalid candidate")

// Neither the candidate suffix nor a complete digest has a public projection.
// The checker clears this transient value once matching is complete.
type candidate struct {
	prefix [5]byte
	suffix [35]byte
}

func (candidate) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "hibp.candidate(redacted)") }
func (candidate) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (candidate) MarshalText() ([]byte, error) { return nil, errSensitive }
func (c *candidate) clear()                    { clear(c.prefix[:]); clear(c.suffix[:]) }

func deriveCandidate(ctx context.Context, secret password.Secret, maxBytes int) (candidate, error) {
	if ctx == nil || maxBytes < 1 || maxBytes > 1<<20 || secret.Len() == 0 || secret.Len() > maxBytes {
		return candidate{}, errInvalidCandidate
	}
	if e := ctx.Err(); e != nil {
		return candidate{}, e
	}
	var result candidate
	err := secret.Use(func(b []byte) error {
		if len(b) < 1 || len(b) > maxBytes {
			return errInvalidCandidate
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		// SHA-1 is mandated solely by the range protocol, not password storage.
		digest := sha1.Sum(b)
		defer clear(digest[:])
		var encoded [40]byte
		defer clear(encoded[:])
		hex.Encode(encoded[:], digest[:])
		for i, b := range encoded {
			if b >= 'a' && b <= 'f' {
				encoded[i] = b - ('a' - 'A')
			}
		}
		copy(result.prefix[:], encoded[:5])
		copy(result.suffix[:], encoded[5:])
		return nil
	})
	if e := ctx.Err(); e != nil {
		result.clear()
		return candidate{}, e
	}
	if err != nil {
		result.clear()
		return candidate{}, errInvalidCandidate
	}
	return result, nil
}
