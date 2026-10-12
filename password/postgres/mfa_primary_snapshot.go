package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const maximumMFAEnableSnapshot = 65536

type mfaEnableSnapshot struct {
	Schema                      uint32
	Issuer, Environment         string
	Audience                    string
	MaximumAge, PrimaryFreshFor time.Duration
	Session                     []identity.FeatureField
	Record                      []byte
	Cookie                      bool `json:",omitempty"`
}

// Original returns the immutable original session, not current authority or a
// bearer. Its authentication projection permits the enrollment owner to compare
// the public PrimaryProof without reconstructing another primary identity.
func (a MFAEnableAdmission) Original() (session.Session, error) {
	if a.custody == nil {
		return session.Session{}, password.ErrPasswordWork
	}
	original := a.custody().original
	if _, err := original.Bindings(); err != nil {
		return session.Session{}, password.ErrPasswordWork
	}
	return original, nil
}

// Snapshot explicitly exports bounded original provenance for the native
// enrollment owner's existing authenticated encrypted request preparation.
// It contains no raw bearer, but is sensitive correlated evidence: encrypt it
// under the complete original request/configuration binding and clear the owned
// bytes immediately. Never persist or log plaintext. This is not a new journal,
// authorization proof or independently trusted restoration format.
func (a MFAEnableAdmission) Snapshot() ([]byte, error) {
	if a.custody == nil {
		return nil, password.ErrPasswordWork
	}
	c := a.custody()
	if c.source == nil || c.source.source == nil {
		return nil, password.ErrPasswordWork
	}
	fields, err := sessionpg.OriginalSessionFields(c.original)
	if err != nil {
		return nil, err
	}
	record, err := encodeReauthenticationRecord(c.record)
	if err != nil {
		return nil, err
	}
	defer clear(record)
	s := c.source
	wire, err := json.Marshal(mfaEnableSnapshot{Schema: 1, Issuer: s.source.c.Issuer, Environment: s.source.c.Environment, Audience: s.config.Audience, MaximumAge: s.config.MaximumAge, PrimaryFreshFor: s.config.PrimaryFreshFor, Session: fields, Record: record, Cookie: c.csrf != nil})
	if err != nil || len(wire) > maximumMFAEnableSnapshot {
		clear(wire)
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

// Restore reconstructs original custody only after the native owner has
// authenticated its encrypted request preparation and complete initiating
// intent. It performs no IO, current-clock lookup, proof renewal or consumption;
// expired provenance can therefore reconcile an already committed command.
// Submitted bearer possession is checked against original lookup commitments.
// Naked caller-provided snapshots are not authority: protected Consume still
// compares the exact source session and original signed record with primary SQL
// and fences all current owners. No preparation or return value grants mutation.
func (s *MFAEnablePrimarySource) Restore(ctx context.Context, r MFAEnablePrimaryRequest, wire []byte) (MFAEnableAdmission, error) {
	bad := func() (MFAEnableAdmission, error) { return MFAEnableAdmission{}, password.ErrPasswordWork }
	if ctx == nil || s == nil || s.source == nil || s.source.repository == nil || !s.source.repository.configuredWriter() || s.validator == nil || len(wire) == 0 || len(wire) > maximumMFAEnableSnapshot {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return MFAEnableAdmission{}, err
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return bad()
	}
	if _, err := identity.ParseCommandID(r.FactorID); err != nil {
		return bad()
	}
	var decoded mfaEnableSnapshot
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(&decoded) != nil || d.Decode(new(any)) != io.EOF {
		return bad()
	}
	defer clear(decoded.Record)
	canonical, err := json.Marshal(decoded)
	defer clear(canonical)
	if err != nil || !bytes.Equal(wire, canonical) || decoded.Schema != 1 || decoded.Issuer != s.source.c.Issuer || decoded.Environment != s.source.c.Environment || decoded.Audience != s.config.Audience || decoded.MaximumAge != s.config.MaximumAge || decoded.PrimaryFreshFor != s.config.PrimaryFreshFor {
		return bad()
	}
	if decoded.Cookie != (r.CSRFToken != (session.CSRFToken{})) {
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	user := identity.UserID(r.Caller.Request.Subject.ID)
	// The legacy native Prepare derives tenant/action/policy at its trusted
	// source; Restore must preserve that accepted caller profile. The public
	// enrollment adapter separately requires complete trusted transport scope.
	if r.Caller.Request.Subject.Kind != authorization.SubjectUser {
		return bad()
	}
	original, err := sessionpg.OriginalSessionFromFields(r.TenantID, user, decoded.Session)
	if err != nil {
		return bad()
	}
	b, err := original.Bindings()
	if err != nil || r.Proof.SessionID != b.SessionID || r.Proof.SessionVersion != b.Version || r.Proof.Action != "identity.mfa.enable" {
		return bad()
	}
	record, err := decodeReauthenticationRecord(r.Proof.Proof.ID, string(r.TenantID), string(user), decoded.Record)
	if err != nil || record.Proof != r.Proof || record.Issuer != s.source.c.Issuer || record.Environment != s.source.c.Environment || record.Proof.Proof.Purpose != "identity.password.verify" || record.Proof.Proof.Audience != s.config.Audience || record.CredentialID != b.Authentication.CredentialID || record.CredentialVersion != original.EffectiveCredentialVersion() {
		return bad()
	}
	token, err := session.ParseToken(r.Session.Token())
	if err != nil {
		return bad()
	}
	matched := false
	for _, key := range s.source.c.LookupKeys {
		digest, err := token.Digest(key, string(r.TenantID))
		if err != nil {
			return bad()
		}
		if digest == b.Lookup {
			matched = true
		}
	}
	if !matched {
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.TenantID), Subject: string(user), Purpose: "identity.password.verify", Audience: s.config.Audience}, SessionID: b.SessionID, SessionVersion: b.Version, Action: "identity.mfa.enable", MaximumAge: s.config.MaximumAge}
	fields := slices.Clone(decoded.Session)
	digest := sha256.Sum256(decoded.Record)
	fields = append(fields, identity.FeatureField{Name: "mfa.primary.proof.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(digest[:])}})
	r.Caller = r.Caller.Clone()
	c := mfaEnablePrimaryCustody{source: s, request: r, original: original, record: record, use: use, fields: fields}
	if err = attachMFAEnableCSRF(&c); err != nil {
		return MFAEnableAdmission{}, err
	}
	if err := ctx.Err(); err != nil {
		return MFAEnableAdmission{}, err
	}
	return MFAEnableAdmission{custody: func() mfaEnablePrimaryCustody { return c }}, nil
}
