package session

import (
	"errors"
	"fmt"
	"io"
	"time"

	authentication "github.com/faustbrian/go-authentication"
)

// ErrInvalidIssueRequest rejects a zero, anonymous or proof-mismatched request
// without exposing account, credential or proof identifiers.
var ErrInvalidIssueRequest = errors.New("session: invalid issue request")

// IssueRequest retains the closed native command and opaque final authentication
// proof together. Zero is invalid; copies are immutable and concurrency safe.
// Construction binds metadata, not the expected authority. The configured issuer
// and adapter must call Validate with their expected authority and trusted now,
// then recheck current lifecycle and atomically finalize proof/session effects.
// This value cannot reserve, consume, commit or reveal a credential.
type IssueRequest struct{ state *issueRequestState }
type issueRequestState struct {
	command SessionCommand
	proof   authentication.AuthenticatedProof
}

// NewAuthenticatedIssueRequest preserves a command's complete authority vector,
// resolved remember policy and original proof/credential versions while binding
// its metadata exactly to the opaque authenticated proof. Anonymous and partial
// authentication cannot use this constructor. No caller-created projection can
// replace the proof. A proof from another valid composition may be structurally
// bound, but Validate rejects it against the issuer's expected authority.
// No IO, token generation or consumption occurs. Invalid input returns zero.
func NewAuthenticatedIssueRequest(command SessionCommand, proof authentication.AuthenticatedProof) (IssueRequest, error) {
	issue, ok := command.Issue()
	if !ok {
		return IssueRequest{}, ErrInvalidIssueRequest
	}
	spec, _ := issue.Session.Bindings()
	metadata := spec.Authentication
	bindings := proof.Bindings()
	if metadata.Kind != AuthenticationVerified || bindings.ProofVersion == 0 || metadata.ProofVersion != bindings.ProofVersion || metadata.CredentialID != bindings.CredentialID || metadata.CredentialVersion != bindings.CredentialVersion || !sameAuthenticationProof(metadata.Proof, bindings.Proof) {
		return IssueRequest{}, ErrInvalidIssueRequest
	}
	return IssueRequest{state: &issueRequestState{command: command, proof: proof}}, nil
}

func sameAuthenticationProof(a, b authentication.Proof) bool {
	return a.ID == b.ID && a.Tenant == b.Tenant && a.Subject == b.Subject && a.Method == b.Method && a.Assurance == b.Assurance && a.Purpose == b.Purpose && a.Audience == b.Audience && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// Validate checks private proof provenance against the expected configured
// authority, exact scope and exclusive expiry, then original session freshness
// and lifetime at trusted now. It performs no IO or authority refresh. The
// authority must come from trusted composition, not a request-selected instance.
// Success is final-authentication admission only, not current account/credential
// validity, one-time use or session authentication. Those checks and required
// audit/outbox effects belong to the protected authoritative transaction.
func (r IssueRequest) Validate(authority *authentication.AuthorityAuthenticator, now time.Time) error {
	if r.state == nil {
		return ErrInvalidIssueRequest
	}
	issue, _ := r.state.command.Issue()
	spec, _ := issue.Session.Bindings()
	if err := authority.ValidateAuthenticatedProof(r.state.proof, authentication.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: now}); err != nil {
		return err
	}
	return r.state.command.ValidateIssueAt(now)
}

// Command returns the immutable structural projection and false for zero.
// This projection intentionally loses proof admission; it cannot replace the
// original request or grant execution authority to an adapter.
func (r IssueRequest) Command() (SessionCommand, bool) {
	if r.state == nil {
		return SessionCommand{}, false
	}
	return r.state.command, true
}

// Format redacts command scope and authentication linkage for every fmt verb.
func (IssueRequest) Format(s fmt.State, _ rune) { io.WriteString(s, "session.IssueRequest(redacted)") }

// MarshalJSON prevents accidental request/proof serialization.
func (IssueRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText prevents text and map-key disclosure.
func (IssueRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
