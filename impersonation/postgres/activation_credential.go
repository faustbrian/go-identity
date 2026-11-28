package impersonationpostgres

import (
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
)

const derivedCredentialPrefix = "imp1."

// DerivedCredential owns a 32-byte impersonation bearer with an imp1. wire
// prefix rejected by the ordinary session parser. Zero is invalid. Copies
// share session.Token's concurrent one-shot Reveal permission; formatting and
// implicit JSON/text serialization never disclose the bearer. It owns no
// external resource and does not prove authorization or durable activation.
// Only the native activation owner can create one; parsing remains internal.
type DerivedCredential struct{ token session.Token }

func newDerivedCredential() (DerivedCredential, error) {
	token, err := session.NewToken(32)
	if err != nil {
		return DerivedCredential{}, impersonation.ErrInvalidInput
	}
	return DerivedCredential{token: token}, nil
}

func parseDerivedCredential(wire string) (DerivedCredential, error) {
	// A 32-byte canonical unpadded base64url token is exactly 43 bytes. Bound
	// before parsing so the wider ordinary 32..64-byte profile cannot enter.
	if len(wire) != len(derivedCredentialPrefix)+43 || !strings.HasPrefix(wire, derivedCredentialPrefix) {
		return DerivedCredential{}, impersonation.ErrInvalidInput
	}
	token, err := session.ParseToken(wire[len(derivedCredentialPrefix):])
	if err != nil {
		return DerivedCredential{}, impersonation.ErrInvalidInput
	}
	return DerivedCredential{token: token}, nil
}

// Reveal returns the prefixed credential exactly once across all value copies.
// It returns ErrInvalidInput for zero and session.ErrTokenAlreadyRevealed after
// any copy reveals. Only the explicitly authorized activation response may
// receive it, after durable commit; an unknown outcome must disclose nothing.
// This is delivery custody, not erasure, a replay store or activation authority.
func (c DerivedCredential) Reveal() (string, error) {
	wire, err := c.token.Reveal()
	if err != nil {
		if err == session.ErrInvalidToken {
			return "", impersonation.ErrInvalidInput
		}
		return "", err
	}
	return derivedCredentialPrefix + wire, nil
}

func (c DerivedCredential) lookup(key session.DigestKey, tenant identity.TenantID) (session.TokenDigest, error) {
	// The native owner selects dedicated impersonation lookup key material.
	// Reuse the existing tenant/version digest framing, never a second scheme.
	digest, err := c.token.Digest(key, string(tenant))
	if err != nil {
		return session.TokenDigest{}, impersonation.ErrInvalidInput
	}
	return digest, nil
}

// Format redacts every formatting verb, including quoted and Go-syntax output.
func (DerivedCredential) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "[REDACTED]") }

// MarshalJSON denies implicit credential disclosure; only Reveal may deliver it.
func (DerivedCredential) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit text and map-key credential disclosure.
func (DerivedCredential) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
