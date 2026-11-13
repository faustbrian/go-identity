package postgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
)

// CanonicalRequestKey owns a stable, protocol-selected request selector. It is
// correlation input, never a client retry key, authorization or outcome proof.
// The feature must include every field defining the protocol's original command
// (for SCIM DELETE: connection, route, target and If-Match), excluding credentials
// and optional retry headers. Mutable policy/version input belongs separately
// in RequestIntent. Zero is invalid; copies support concurrent reads.
type CanonicalRequestKey struct{ selector func() string }

// NewCanonicalRequestKey copies 1..65536 exact selector bytes without I/O or
// normalization. The limit bounds trusted protocol preparation, not HTTP body
// acceptance. Selectors may contain private identifiers: never log them. The
// owner must validate its protocol schema before construction.
func NewCanonicalRequestKey(selector []byte) (CanonicalRequestKey, error) {
	if len(selector) == 0 || len(selector) > 65536 {
		return CanonicalRequestKey{}, invalidRequestKey()
	}
	owned := string(selector)
	return CanonicalRequestKey{selector: func() string { return owned }}, nil
}

func (k CanonicalRequestKey) digest(authority [32]byte) ([32]byte, error) {
	if k.selector == nil || authority == ([32]byte{}) {
		return [32]byte{}, invalidRequestKey()
	}
	mac := hmac.New(sha256.New, authority[:])
	_, _ = io.WriteString(mac, "golib.identity.canonical-request.v1\x00")
	selector := k.selector()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(selector)))
	_, _ = mac.Write(length[:])
	_, _ = io.WriteString(mac, selector)
	return [32]byte(mac.Sum(nil)), nil
}

// Format redacts the selector for every diagnostic verb.
func (CanonicalRequestKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CanonicalRequestKey(redacted)")
}

// MarshalJSON rejects implicit persistence of private request selectors.
func (CanonicalRequestKey) MarshalJSON() ([]byte, error) { return nil, invalidRequestKey() }

// MarshalText rejects implicit text disclosure and map-key serialization.
func (CanonicalRequestKey) MarshalText() ([]byte, error) { return nil, invalidRequestKey() }

// LogValue emits no private selector bytes.
func (CanonicalRequestKey) LogValue() slog.Value {
	return slog.StringValue("postgres.CanonicalRequestKey(redacted)")
}
