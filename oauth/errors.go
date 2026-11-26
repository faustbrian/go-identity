// Package oauth owns bounded relying-party OAuth protocol, not identity, state
// reservation, linking or session authority. Its selected OIDC client supports
// HTTPS authorization-code/query/S256 PKCE and explicit Google ID-token input.
package oauth

import (
	"context"
	"errors"
)

// ErrorKind is a closed exchange disposition. No disposition permits an
// automatic authorization-code retry; durable reconciliation belongs to the
// native callback owner.
type ErrorKind string

const (
	// InvalidInput means local configuration/custody/preflight failed before send.
	InvalidInput ErrorKind = "invalid_input"
	// Refused means a coherent definitive OAuth refusal was received.
	Refused ErrorKind = "refused"
	// InvalidProof means a completed response did not prove the configured identity.
	InvalidProof ErrorKind = "invalid_proof"
	// Unavailable means local cancellation prevented an exchange attempt.
	Unavailable ErrorKind = "unavailable"
	// Unknown means an attempted exchange has no trustworthy terminal result.
	Unknown ErrorKind = "unknown"
)

// Error contains only a stable classification and optional context error.
// Provider descriptions, URLs, response bodies and transport errors are never
// retained. Context cancellation remains discoverable with errors.Is.
type Error struct {
	kind         ErrorKind
	contextError error
}

func (e *Error) Error() string { return "oauth: " + string(e.kind) }

// Kind returns the stable disposition; a nil Error is invalid input.
func (e *Error) Kind() ErrorKind {
	if e == nil {
		return InvalidInput
	}
	return e.kind
}

// Is preserves only cancellation/deadline classification, not secret diagnostics.
func (e *Error) Is(target error) bool {
	return e != nil && e.contextError != nil && errors.Is(e.contextError, target)
}

func failure(kind ErrorKind, ctx context.Context) error {
	e := &Error{kind: kind}
	if ctx != nil {
		e.contextError = ctx.Err()
	}
	return e
}
