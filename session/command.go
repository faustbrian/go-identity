package session

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidSessionCommand rejects zero, unsupported or misbound commands.
var ErrInvalidSessionCommand = errors.New("session: invalid command")

// IssueCommandSpec is the native storage-neutral projection of new issuance.
// Binding targets exactly Session and declares policy/schema/actor separately
// from the effective user. It is not authority, proof consumption or a commit.
// Adapters must validate the complete native schema and every effect before
// mapping to identity's command fingerprint protocol. No transaction is exposed.
type IssueCommandSpec struct {
	Binding identity.CommandBinding
	Session Session
}

// SessionCommand is a closed immutable native transition. Currently only issue
// is implemented; other transitions cannot be smuggled through operation IDs.
// Zero is invalid, copies are concurrency safe, and formatting/serialization
// cannot expose scope. Construction grants no issuance or execution authority.
type SessionCommand struct{ issue *IssueCommandSpec }

// IssueOperation returns the exact v1 native issue mapping. This declaration
// conveys no registered contributor or runtime readiness; core never imports
// PostgreSQL, opens a transaction, accepts a callback or creates a journal.
func IssueOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// NewIssueCommand binds one new version1 record to its exact command scope and
// resolved policy. Existing family version is retained, never reset. The final
// proof metadata must have exact session-issue purpose and be unexpired at
// original issuance; anonymous records remain an explicit unprivileged variant.
// This is structural/temporal preparation only. SessionIssuer must independently
// validate the expected authority-issued authentication/anonymous proof, current
// activity/vector and operation policy before any durable reservation or effect.
// The adapter owns atomic consumption, safe recovery and reveal-once delivery.
func NewIssueCommand(b identity.CommandBinding, s Session) (SessionCommand, error) {
	spec, err := s.Bindings()
	if err != nil || b.ValidateFor(IssueOperation()) != nil || b.TenantID != spec.TenantID || b.UserID != spec.UserID || b.RecordID != spec.SessionID || spec.Version != 1 {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	c := SessionCommand{issue: &IssueCommandSpec{Binding: b, Session: s}}
	if c.ValidateIssueAt(spec.IssuedAt) != nil {
		return SessionCommand{}, ErrInvalidSessionCommand
	}
	// All binding strings are bounded by upstream validation before copying.
	b.CommandID = identity.CommandID(strings.Clone(string(b.CommandID)))
	b.TenantID = identity.TenantID(strings.Clone(string(b.TenantID)))
	b.UserID = identity.UserID(strings.Clone(string(b.UserID)))
	b.ActorID = identity.ActorID(strings.Clone(string(b.ActorID)))
	b.OperationID = strings.Clone(b.OperationID)
	b.RecordID = strings.Clone(b.RecordID)
	b.PolicyID = strings.Clone(b.PolicyID)
	b.SchemaID = strings.Clone(b.SchemaID)
	b.CorrelationID = strings.Clone(b.CorrelationID)
	c.issue.Binding = b
	return c, nil
}

// Issue returns a caller-owned scalar projection, not an admitted transaction.
// False means zero/unsupported; no partially prepared command escapes.
func (c SessionCommand) Issue() (IssueCommandSpec, bool) {
	if c.issue == nil {
		return IssueCommandSpec{}, false
	}
	return *c.issue, true
}

// ValidateIssueAt rechecks only immutable temporal metadata at authoritative
// now, including exact proof purpose/audience, exclusive proof/session expiry
// and original authentication freshness. It authenticates NOTHING: private
// proof ownership, activity, policy and every applicable current authority must
// be established separately at reservation/apply under the sole coordinator.
// Anonymous metadata is never upgraded to verified assurance. No IO runs.
func (c SessionCommand) ValidateIssueAt(now time.Time) error {
	if c.issue == nil {
		return ErrInvalidSessionCommand
	}
	s := c.issue.Session.state.spec
	lifetime, err := c.issue.Session.Lifetime(now)
	if err != nil {
		return err
	}
	if !lifetime.Fresh {
		return ErrInvalidSessionCommand
	}
	if s.Authentication.Kind == AuthenticationVerified {
		return s.Authentication.Proof.Validate(authentication.ProofUse{Tenant: string(s.TenantID), Subject: string(s.UserID), Purpose: "session-issue", Audience: s.Audience, Now: now})
	}
	return nil
}

// Format redacts all command scope and metadata.
func (c SessionCommand) Format(f fmt.State, _ rune) {
	io.WriteString(f, "session.SessionCommand(redacted)")
}

// MarshalJSON denies implicit command serialization.
func (c SessionCommand) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit command serialization and map-key disclosure.
func (c SessionCommand) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
