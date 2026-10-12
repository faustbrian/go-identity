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
	CSRF                     *session.CSRFStateSpec               `json:",omitempty"`
	OTP                      *session.OTPAuthenticationSpec       `json:",omitempty"`
	MagicLink                *session.MagicLinkAuthenticationSpec `json:",omitempty"`
	MFA                      *session.MFAAuthenticationSpec       `json:",omitempty"`
	Continuation             *session.CredentialContinuationSpec  `json:",omitempty"`
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
	record := storedRecord{Schema: 1, SessionID: spec.SessionID, FamilyID: spec.FamilyID, TenantID: spec.TenantID, UserID: spec.UserID, Audience: spec.Audience, Version: spec.Version, FamilyVersion: spec.FamilyVersion, Remember: remember, Authority: authority, Lookup: spec.Lookup, Authentication: spec.Authentication, IssuedAt: spec.IssuedAt.UTC(), LastActivityAt: spec.LastActivityAt.UTC()}
	if state, e := s.CSRFState().Bindings(); e == nil {
		record.Schema, record.CSRF = 2, &state
	}
	if metadata, e := s.OTPAuthentication().Bindings(); e == nil {
		record.Schema += 2
		record.OTP = &metadata
	}
	if metadata, e := s.MagicLinkAuthentication().Bindings(); e == nil {
		record.Schema += 6
		record.MagicLink = &metadata
	}
	if metadata, e := s.MFAAuthentication().Bindings(); e == nil {
		record.Schema += 2
		record.MFA = &metadata
	}
	if continuation, ok := s.CredentialContinuation(); ok {
		record.Schema += 4
		record.Continuation = &continuation
	}
	b, err := json.Marshal(record)
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
	keys := []string{"Schema", "SessionID", "FamilyID", "TenantID", "UserID", "Audience", "Version", "FamilyVersion", "Remember", "Authority", "Lookup", "Authentication", "IssuedAt", "LastActivityAt"}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(b, &envelope) != nil {
		return invalid()
	}
	_, hasCSRF := envelope["CSRF"]
	_, hasOTP := envelope["OTP"]
	_, hasMagicLink := envelope["MagicLink"]
	_, hasMFA := envelope["MFA"]
	_, hasContinuation := envelope["Continuation"]
	if hasCSRF {
		keys = append(keys, "CSRF")
	}
	if hasOTP {
		keys = append(keys, "OTP")
	}
	if hasMagicLink {
		keys = append(keys, "MagicLink")
	}
	if hasMFA {
		keys = append(keys, "MFA")
	}
	if hasContinuation {
		keys = append(keys, "Continuation")
	}
	top, ok := exactObject(b, keys...)
	if !ok {
		return invalid()
	}
	if hasContinuation {
		if hasOTP || hasMagicLink {
			return invalid()
		}
		if _, ok := exactObject(top["Continuation"], "CommandID", "BeforeAuthorityVersion", "BeforeCredentialVersion"); !ok {
			return invalid()
		}
	}
	if hasOTP {
		if _, ok := exactObject(top["OTP"], "CommandID", "SendCommandID", "ChallengeID", "AttemptID", "IdentifierID", "IdentifierKind", "IdentifierVersion", "VerificationVersion", "AuthenticatedAt", "ValidUntil"); !ok {
			return invalid()
		}
	}
	if hasMagicLink {
		if hasOTP {
			return invalid()
		}
		if _, ok := exactObject(top["MagicLink"], "CommandID", "RequestCommandID", "CapabilityID", "IdentifierID", "IdentifierVersion", "VerificationVersion", "AuthenticatedAt", "ValidUntil"); !ok {
			return invalid()
		}
	}
	if hasMFA {
		if !hasMagicLink || hasOTP || hasContinuation {
			return invalid()
		}
		factor, valid := exactObject(top["MFA"], "CommandID", "PrimaryCommandID", "ContinuationID", "ContinuationScopeDigest", "Method", "FactorID", "EnrollmentVersion", "FactorAuthorityVersion", "ContinuationVersion", "Remember", "VerifiedAt", "ValidUntil")
		if !valid {
			return invalid()
		}
		if _, valid := exactObject(factor["Remember"], "Choice", "AbsoluteTTL", "IdleTTL", "RefreshAfter", "FreshFor"); !valid {
			return invalid()
		}
		var digest []*uint8
		if json.Unmarshal(factor["ContinuationScopeDigest"], &digest) != nil || len(digest) != 32 {
			return invalid()
		}
		for _, value := range digest {
			if value == nil {
				return invalid()
			}
		}
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
	if hasCSRF {
		state, valid := exactObject(top["CSRF"], "Binding", "KeyVersion", "Digest")
		if !valid {
			return invalid()
		}
		if _, valid = exactObject(state["Binding"], "TenantID", "SessionID", "SessionVersion"); !valid {
			return invalid()
		}
		var digest []*uint8
		if json.Unmarshal(state["Digest"], &digest) != nil || len(digest) != 32 {
			return invalid()
		}
		for _, value := range digest {
			if value == nil {
				return invalid()
			}
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
	if decoder.Decode(&record) != nil {
		return invalid()
	}
	// Keep historical schemas byte-compatible, but never infer OTP provenance
	// from a method tag or silently downgrade a complete OTP record.
	expectedSchema := uint32(1)
	if hasCSRF {
		expectedSchema++
	}
	if hasOTP {
		expectedSchema += 2
	}
	if hasContinuation {
		expectedSchema += 4
	}
	if hasMagicLink {
		expectedSchema += 6
	}
	if hasMFA {
		expectedSchema += 2
	}
	if record.Schema != expectedSchema || hasOTP != (record.Authentication.Kind == session.AuthenticationOTP) || hasMagicLink != (record.Authentication.Kind == session.AuthenticationMagicLink) {
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
	spec := session.SessionSpec{SessionID: record.SessionID, FamilyID: record.FamilyID, TenantID: record.TenantID, UserID: record.UserID, Audience: record.Audience, Version: record.Version, FamilyVersion: record.FamilyVersion, Remember: remember, Authority: vector, Lookup: record.Lookup, Authentication: record.Authentication, IssuedAt: record.IssuedAt, LastActivityAt: record.LastActivityAt}
	var state session.CSRFState
	if hasCSRF {
		state, err = session.NewCSRFState(*record.CSRF)
		if err != nil {
			return invalid()
		}
	}
	var result session.Session
	if hasContinuation {
		result, err = session.NewContinuedPasswordSession(spec, state, *record.Continuation)
	} else if hasMagicLink {
		metadata, e := session.NewMagicLinkAuthentication(*record.MagicLink)
		if e != nil {
			return invalid()
		}
		if hasMFA {
			factor, e := session.NewMFAAuthentication(*record.MFA)
			if e != nil {
				return invalid()
			}
			if hasCSRF {
				result, err = session.NewSessionWithMagicLinkMFAAndCSRF(spec, metadata, factor, state)
			} else {
				result, err = session.NewSessionWithMagicLinkMFA(spec, metadata, factor)
			}
		} else if hasCSRF {
			result, err = session.NewSessionWithMagicLinkAndCSRF(spec, metadata, state)
		} else {
			result, err = session.NewSessionWithMagicLink(spec, metadata)
		}
	} else if hasOTP {
		metadata, e := session.NewOTPAuthentication(*record.OTP)
		if e != nil {
			return invalid()
		}
		if hasCSRF {
			result, err = session.NewSessionWithOTPAndCSRF(spec, metadata, state)
		} else {
			result, err = session.NewSessionWithOTP(spec, metadata)
		}
	} else if hasCSRF {
		result, err = session.NewSessionWithCSRF(spec, state)
	} else {
		result, err = session.NewSession(spec)
	}
	if err != nil {
		return invalid()
	}
	return result, nil
}

// PostgreSQL jsonb canonicalizes object keys before the read. Every stored
// field, including explicit optional absence, must still be present/non-null.
// No map values are converted through float64, preserving all uint64 versions.
func exactObject(b []byte, keys ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(b))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	object := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		key, e := decoder.Token()
		name, valid := key.(string)
		if e != nil || !valid {
			return nil, false
		}
		if _, duplicate := object[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		object[name] = value
	}
	if end, e := decoder.Token(); e != nil || end != json.Delim('}') {
		return nil, false
	}
	if decoder.Decode(new(any)) != io.EOF || len(object) != len(keys) {
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
