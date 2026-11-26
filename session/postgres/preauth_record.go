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
	Provider                    *storedPreAuthProvider `json:",omitempty"`
}

// Only the canonical native bytea record may serialize this private profile.
// The public provider binding deliberately refuses automatic serialization.
type storedPreAuthProvider struct {
	ID, ClientID string
	Version      uint64
	Mode         session.PreAuthProviderMode
}

func preAuthRecordProjection(record session.PreAuthTransaction) (session.PreAuthTransactionSpec, session.PreAuthProviderBinding, error) {
	if base, err := record.Bindings(); err == nil {
		return base, session.PreAuthProviderBinding{}, nil
	}
	bound, err := record.ProviderBindings()
	return bound.Transaction, bound.Provider, err
}

func selectedPreAuthProjection(record session.PreAuthTransaction, provider session.PreAuthProviderBinding) (session.PreAuthTransactionSpec, error) {
	if provider == (session.PreAuthProviderBinding{}) {
		return record.Bindings()
	}
	bound, err := record.ProviderBindings()
	if err != nil || bound.Provider != provider {
		return session.PreAuthTransactionSpec{}, session.ErrInvalidPreAuthTransaction
	}
	return bound.Transaction, nil
}

func buildPreAuthRecord(spec session.PreAuthTransactionSpec, provider session.PreAuthProviderBinding) (session.PreAuthTransaction, error) {
	if provider == (session.PreAuthProviderBinding{}) {
		return session.NewPreAuthTransaction(spec)
	}
	return session.NewProviderPreAuthTransaction(session.ProviderPreAuthTransactionSpec{Transaction: spec, Provider: provider})
}

func encodePreAuth(record session.PreAuthTransaction) ([]byte, error) {
	s, selected, err := preAuthRecordProjection(record)
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
	var provider *storedPreAuthProvider
	schema := uint32(1)
	if selected.Mode != 0 {
		schema = 2
		provider = &storedPreAuthProvider{ID: selected.ProviderID, ClientID: selected.ClientID, Version: selected.ProviderVersion, Mode: selected.Mode}
	}
	payload, err := json.Marshal(storedPreAuth{Schema: schema, ID: b.ID, TenantID: i.TenantID, Action: i.Action, Origin: i.Origin, CallbackURL: i.CallbackURL,
		Nonce: i.Nonce, Remember: r, PolicyID: i.PolicyID, PolicyVersion: i.PolicyVersion, IssuedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt,
		Cookie: s.Cookie, Version: s.Version, IdentifierBinding: identifierBinding, Purpose: i.Purpose, Provider: provider})
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
	if json.Unmarshal(payload, &stored) != nil {
		return bad()
	}
	var selected session.PreAuthProviderBinding
	switch {
	case stored.Schema == 1 && stored.Provider == nil:
	case stored.Schema == 2 && stored.Provider != nil && stored.Provider.Mode == session.PreAuthProviderCallback:
		selected = session.PreAuthProviderBinding{ProviderID: stored.Provider.ID, ClientID: stored.Provider.ClientID,
			ProviderVersion: stored.Provider.Version, Mode: stored.Provider.Mode}
	default:
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
	result, err := buildPreAuthRecord(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: stored.ID, Intent: session.PreAuthIntent{TenantID: stored.TenantID, Action: stored.Action, Origin: stored.Origin, CallbackURL: stored.CallbackURL, Nonce: stored.Nonce, Remember: remember, PolicyID: stored.PolicyID, PolicyVersion: stored.PolicyVersion, IdentifierBinding: identifierBinding, Purpose: stored.Purpose}, IssuedAt: stored.IssuedAt, ExpiresAt: stored.ExpiresAt}, Cookie: stored.Cookie, Version: stored.Version}, selected)
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
