// Package identity owns identity-domain values and workflows. Persistence and
// authentication ceremonies are composed through separate adapters. Identifiers
// identify records or attempts; possession does not confer authority.
package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// SubjectID is the canonical 22-character unpadded base64url encoding of a
// non-zero 128-bit subject identifier. The zero value is invalid. Values are
// immutable and safe for concurrent reads; reconstruct wire values with
// ParseSubjectID. A SubjectID alone proves neither identity nor tenant authority.
type SubjectID string

// PreAuthTransactionID is a canonical non-zero 128-bit attempt/correlation ID.
// Its empty zero value is invalid. Immutable values are safe for concurrent
// reads. Possession grants no authentication, capability-use or transaction
// authority: consumers must bind the exact tenant, attempt and continuation.
type PreAuthTransactionID string

var (
	// ErrInvalidSubjectID identifies malformed, noncanonical or zero subject IDs.
	// It never contains the rejected input.
	ErrInvalidSubjectID = errors.New("identity: invalid subject ID")
	// ErrSubjectIDEntropy identifies unavailable, incomplete or all-zero entropy.
	// It never includes entropy bytes or provider error details.
	ErrSubjectIDEntropy = errors.New("identity: subject ID entropy unavailable")
	// ErrInvalidPreAuthTransactionID identifies invalid attempt IDs without input.
	ErrInvalidPreAuthTransactionID = errors.New("identity: invalid pre-auth transaction ID")
	// ErrPreAuthTransactionIDEntropy identifies invalid entropy without details.
	ErrPreAuthTransactionIDEntropy = errors.New("identity: pre-auth transaction ID entropy unavailable")
)

// NewSubjectID reads exactly 16 bytes from crypto/rand, rejects all-zero entropy
// and returns its canonical representation. Failure returns an empty ID and
// ErrSubjectIDEntropy. The function retains no caller state or resources.
func NewSubjectID() (SubjectID, error) {
	raw, err := newID(rand.Reader, ErrSubjectIDEntropy)
	return SubjectID(raw), err
}

// ParseSubjectID accepts only a canonical unpadded base64url encoding of 16
// non-zero bytes. It checks the length before decoding; invalid input returns
// an empty ID and ErrInvalidSubjectID without disclosing the input.
func ParseSubjectID(raw string) (SubjectID, error) {
	if _, ok := decodeID(raw); !ok {
		return "", ErrInvalidSubjectID
	}
	return SubjectID(raw), nil
}

// FormatSubjectID returns the canonical representation or an empty string for
// an invalid value, including a forged conversion from a noncanonical string.
func FormatSubjectID(id SubjectID) string {
	if _, ok := decodeID(string(id)); !ok {
		return ""
	}
	return string(id)
}

// CompareSubjectID returns -1, 0 or 1 in decoded bytewise order, not encoded
// ASCII order. Invalid operands return 0 and ErrInvalidSubjectID.
func CompareSubjectID(left, right SubjectID) (int, error) {
	return compareIDs(string(left), string(right), ErrInvalidSubjectID)
}

// NewPreAuthTransactionID reads exactly 16 crypto/rand bytes and rejects all-zero
// entropy. Failure returns an empty ID and ErrPreAuthTransactionIDEntropy.
func NewPreAuthTransactionID() (PreAuthTransactionID, error) {
	raw, err := newID(rand.Reader, ErrPreAuthTransactionIDEntropy)
	return PreAuthTransactionID(raw), err
}

// ParsePreAuthTransactionID accepts only the canonical encoding of a non-zero
// 128-bit value, with bounded decoding and ErrInvalidPreAuthTransactionID on
// failure. Parsing never grants authority or reserves a database transaction.
func ParsePreAuthTransactionID(raw string) (PreAuthTransactionID, error) {
	if _, ok := decodeID(raw); !ok {
		return "", ErrInvalidPreAuthTransactionID
	}
	return PreAuthTransactionID(raw), nil
}

// FormatPreAuthTransactionID returns the canonical encoding or an empty string
// for an invalid value. No normalization of attacker-supplied text is attempted.
func FormatPreAuthTransactionID(id PreAuthTransactionID) string {
	if _, ok := decodeID(string(id)); !ok {
		return ""
	}
	return string(id)
}

// ComparePreAuthTransactionID compares decoded bytes, returning -1, 0 or 1.
// Invalid operands return 0 and ErrInvalidPreAuthTransactionID.
func ComparePreAuthTransactionID(left, right PreAuthTransactionID) (int, error) {
	return compareIDs(string(left), string(right), ErrInvalidPreAuthTransactionID)
}

func newID(reader io.Reader, entropyError error) (string, error) {
	var value [16]byte
	// io.ReadFull propagates short reads as errors without changing the process-
	// wide crypto/rand source or exposing its diagnostics through the public API.
	if _, err := io.ReadFull(reader, value[:]); err != nil || value == [16]byte{} {
		return "", entropyError
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func decodeID(raw string) ([16]byte, bool) {
	var value [16]byte
	if len(raw) != 22 {
		return value, false
	}
	// Strict rejects non-zero trailing padding bits; exact length and an encode
	// comparison reject ignored newlines and other alternate representations.
	n, err := base64.RawURLEncoding.Strict().Decode(value[:], []byte(raw))
	return value, err == nil && n == len(value) && value != [16]byte{} && base64.RawURLEncoding.EncodeToString(value[:]) == raw
}

func compareIDs(left, right string, invalidError error) (int, error) {
	a, valid := decodeID(left)
	if !valid {
		return 0, invalidError
	}
	b, valid := decodeID(right)
	if !valid {
		return 0, invalidError
	}
	return bytes.Compare(a[:], b[:]), nil
}
