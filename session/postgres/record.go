package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ErrInvalidRecord rejects incomplete, oversized or unknown stored projections.
// It contains no stored identifier, digest, authentication or driver diagnostic.
var ErrInvalidRecord = errors.New("session/postgres: invalid stored record")

const maximumRecordBytes = 32768
const storedTimeLayout = "2006-01-02T15:04:05.000000000Z"

// This closed projection deliberately contains no opaque authenticated proof,
// bearer or validity lease. Reconstruction cannot manufacture those authorities.
type storedRecord struct {
	Schema                   uint32
	SessionID, FamilyID      string
	TenantID                 identity.TenantID
	UserID                   identity.UserID
	Audience                 string
	Version, FamilyVersion   uint64
	Remember                 session.RememberPolicySpec
	Authority                session.AuthoritySnapshotSpec
	Lookup                   session.TokenDigest
	Authentication           session.AuthenticationMetadata
	IssuedAt, LastActivityAt time.Time
}

func encodeRecord(s session.Session) ([]byte, string, error) {
	spec, err := s.Bindings()
	if err != nil {
		return nil, "", ErrInvalidRecord
	}
	remember, err := spec.Remember.Bindings()
	if err != nil {
		return nil, "", ErrInvalidRecord
	}
	authority, err := spec.Authority.Bindings()
	if err != nil {
		return nil, "", ErrInvalidRecord
	}
	lifetime, err := s.Lifetime(spec.LastActivityAt)
	if err != nil {
		return nil, "", ErrInvalidRecord
	}
	spec.Authentication.Proof.IssuedAt = spec.Authentication.Proof.IssuedAt.UTC()
	spec.Authentication.Proof.ExpiresAt = spec.Authentication.Proof.ExpiresAt.UTC()
	spec.Authentication.AnonymousAt = spec.Authentication.AnonymousAt.UTC()
	b, err := json.Marshal(storedRecord{1, spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID, spec.Audience, spec.Version, spec.FamilyVersion, remember, authority, spec.Lookup, spec.Authentication, spec.IssuedAt.UTC(), spec.LastActivityAt.UTC()})
	if err != nil || len(b) > maximumRecordBytes {
		return nil, "", ErrInvalidRecord
	}
	return b, lifetime.ExpiresAt.UTC().Format(storedTimeLayout), nil
}

func decodeRecord(b []byte) (session.Session, error) {
	invalid := func() (session.Session, error) { return session.Session{}, ErrInvalidRecord }
	if len(b) == 0 || len(b) > maximumRecordBytes {
		return invalid()
	}
	top, ok := exactObject(b, "Schema", "SessionID", "FamilyID", "TenantID", "UserID", "Audience", "Version", "FamilyVersion", "Remember", "Authority", "Lookup", "Authentication", "IssuedAt", "LastActivityAt")
	if !ok {
		return invalid()
	}
	if _, ok = exactObject(top["Remember"], "Choice", "AbsoluteTTL", "IdleTTL", "RefreshAfter", "FreshFor"); !ok {
		return invalid()
	}
	lookup, ok := exactObject(top["Lookup"], "KeyVersion", "Sum")
	if !ok {
		return invalid()
	}
	// A fixed-array JSON decoder otherwise zero-fills short arrays, discards
	// excess elements and treats null scalar bytes as zero. None is a complete
	// stored digest representation, even when the resulting bytes match an index.
	var sum []*uint8
	if json.Unmarshal(lookup["Sum"], &sum) != nil || len(sum) != 32 {
		return invalid()
	}
	for _, b := range sum {
		if b == nil {
			return invalid()
		}
	}
	authority, ok := exactObject(top["Authority"], "Global", "Tenant", "User", "Identifier", "Credential", "SessionFamily", "Session", "Authorization", "ActiveOrganizationID", "Organization", "Factor", "Passkey")
	if !ok {
		return invalid()
	}
	for _, name := range []string{"Global", "Tenant", "User", "Identifier", "Credential", "SessionFamily", "Session", "Authorization"} {
		if _, ok = exactObject(authority[name], "ScopeKey", "Version"); !ok {
			return invalid()
		}
	}
	for _, name := range []string{"Organization", "Factor", "Passkey"} {
		optional, valid := exactObject(authority[name], "Present", "Binding")
		if !valid {
			return invalid()
		}
		if _, ok = exactObject(optional["Binding"], "ScopeKey", "Version"); !ok {
			return invalid()
		}
	}
	metadata, ok := exactObject(top["Authentication"], "Kind", "Proof", "ProofVersion", "CredentialID", "CredentialVersion", "AnonymousAt")
	if !ok {
		return invalid()
	}
	if _, ok = exactObject(metadata["Proof"], "ID", "Tenant", "Subject", "Method", "Assurance", "Purpose", "Audience", "IssuedAt", "ExpiresAt"); !ok {
		return invalid()
	}
	var record storedRecord
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || record.Schema != 1 {
		return invalid()
	}
	if decoder.Decode(new(any)) != io.EOF {
		return invalid()
	}
	remember, err := session.NewRememberPolicy(record.Remember)
	if err != nil {
		return invalid()
	}
	vector, err := session.NewAuthoritySnapshot(record.Authority)
	if err != nil {
		return invalid()
	}
	result, err := session.NewSession(session.SessionSpec{SessionID: record.SessionID, FamilyID: record.FamilyID, TenantID: record.TenantID, UserID: record.UserID, Audience: record.Audience, Version: record.Version, FamilyVersion: record.FamilyVersion, Remember: remember, Authority: vector, Lookup: record.Lookup, Authentication: record.Authentication, IssuedAt: record.IssuedAt, LastActivityAt: record.LastActivityAt})
	if err != nil {
		return invalid()
	}
	return result, nil
}

// PostgreSQL jsonb canonicalizes object keys before the read. Every stored
// field, including explicit optional absence, must still be present/non-null.
// No map values are converted through float64, preserving all uint64 versions.
func exactObject(b []byte, keys ...string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		value, exists := object[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	return object, true
}
