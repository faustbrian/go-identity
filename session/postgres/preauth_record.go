package postgres

import (
	"bytes"
	"encoding/json"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const maximumPreAuthRecordBytes = 8192

// Private canonical bytea, not client JSON. The flattened projection bypasses
// forbidden automatic export of the core private binding; no bearer is stored.
type storedPreAuth struct {
	Schema                      uint32
	ID                          identity.PreAuthTransactionID
	TenantID                    identity.TenantID
	Action, Origin, CallbackURL string
	Nonce                       [32]byte
	Remember                    session.RememberPolicySpec `json:",omitzero"`
	PolicyID                    string
	PolicyVersion               uint64
	IssuedAt, ExpiresAt         time.Time
	Cookie                      session.TokenDigest
	Version                     uint64
	IdentifierBinding           *[32]byte              `json:",omitempty"`
	Purpose                     session.PreAuthPurpose `json:",omitempty"`
}

func encodePreAuth(record session.PreAuthTransaction) ([]byte, error) {
	s, err := record.Bindings()
	if err != nil {
		return nil, ErrInvalidRecord
	}
	b := s.Binding
	r, err := b.Intent.Remember.Bindings()
	if err != nil && b.Intent.Purpose != session.PreAuthPhonePasswordRecovery {
		return nil, ErrInvalidRecord
	}
	i := b.Intent
	// Omit absent binding entirely to preserve installed legacy bytea records.
	// Older binaries reject bound records through their canonical-byte check,
	// rather than silently loading them without the identifier commitment.
	var identifierBinding *[32]byte
	if i.IdentifierBinding != ([32]byte{}) {
		original := i.IdentifierBinding
		identifierBinding = &original
	}
	payload, err := json.Marshal(storedPreAuth{1, b.ID, i.TenantID, i.Action, i.Origin, i.CallbackURL, i.Nonce, r, i.PolicyID, i.PolicyVersion, b.IssuedAt, b.ExpiresAt, s.Cookie, s.Version, identifierBinding, i.Purpose})
	if err != nil || len(payload) > maximumPreAuthRecordBytes {
		return nil, ErrInvalidRecord
	}
	return payload, nil
}

func decodePreAuth(payload []byte) (session.PreAuthTransaction, error) {
	bad := func() (session.PreAuthTransaction, error) { return session.PreAuthTransaction{}, ErrInvalidRecord }
	if len(payload) == 0 || len(payload) > maximumPreAuthRecordBytes {
		return bad()
	}
	var stored storedPreAuth
	if json.Unmarshal(payload, &stored) != nil || stored.Schema != 1 {
		return bad()
	}
	var remember session.RememberPolicy
	if stored.Purpose == session.PreAuthPhonePasswordRecovery {
		if stored.Remember != (session.RememberPolicySpec{}) {
			return bad()
		}
	} else {
		var err error
		remember, err = session.NewRememberPolicy(stored.Remember)
		if err != nil {
			return bad()
		}
	}
	var identifierBinding [32]byte
	if stored.IdentifierBinding != nil {
		identifierBinding = *stored.IdentifierBinding
	}
	result, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: stored.ID, Intent: session.PreAuthIntent{TenantID: stored.TenantID, Action: stored.Action, Origin: stored.Origin, CallbackURL: stored.CallbackURL, Nonce: stored.Nonce, Remember: remember, PolicyID: stored.PolicyID, PolicyVersion: stored.PolicyVersion, IdentifierBinding: identifierBinding, Purpose: stored.Purpose}, IssuedAt: stored.IssuedAt, ExpiresAt: stored.ExpiresAt}, Cookie: stored.Cookie, Version: stored.Version})
	if err != nil {
		return bad()
	}
	canonical, err := encodePreAuth(result)
	// bytea preserves the exact owned encoding. Reject duplicates, unknown,
	// missing/null fields, short/long arrays, trailing data and noncanonical time
	// without accepting JSON decoder zero-filling as complete durable evidence.
	if err != nil || !bytes.Equal(payload, canonical) {
		return bad()
	}
	return result, nil
}
