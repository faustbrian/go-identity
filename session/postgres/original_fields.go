package postgres

import (
	"bytes"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const originalSessionPrefix = "source-session."

// OriginalSessionFields freezes the complete existing authenticated
// session into the owner's closed scalar vocabulary, under source-session.
// It preserves original authentication, remember policy, every authority
// dimension, lookup commitment and optional CSRF state; no raw bearer is exposed.
// Returned fields and byte slices are caller-owned. Credential, OTP and magic-link records
// retain their separate historical provenance. Zero and anonymous records deny
// with ErrInvalidSessionCommand; anonymous admission is a different profile.
// This pure bounded mapping performs no IO, freshness renewal or authentication.
// Native workflows must bind every field into their keyed command, authenticate
// the separate bearer and compare current owners and RequireSession on the sole
// coordinator transaction. Never log these correlated storage projections.
func OriginalSessionFields(original session.Session) ([]identity.FeatureField, error) {
	spec, err := original.Bindings()
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := sessionRecordFieldsKind(original, spec.Authentication.Kind)
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	for i := range fields {
		fields[i].Name = originalSessionPrefix + fields[i].Name
		fields[i].Value.Bytes = slices.Clone(fields[i].Value.Bytes)
	}
	slices.SortFunc(fields, func(a, b identity.FeatureField) int { return strings.Compare(a.Name, b.Name) })
	return fields, nil
}

// OriginalSessionFromFields reconstructs only the complete canonical vocabulary
// emitted by OriginalSessionFields for the exact tenant and user. Order is
// irrelevant; duplicates, omissions, unknown names, inactive union data and
// out-of-bounds inputs deny. At most128 fields, each name at most128 bytes and
// each text/byte value at most4096 bytes, are examined before reconstruction.
// Inputs must remain immutable during the call; the result retains owned copies.
// It grants no provenance, active-state assertion or protected-operation access.
// No IO, clock, callback or resource lifetime is introduced. Native consumers
// still need bearer possession, their exact admission profile and primary checks.
func OriginalSessionFromFields(tenant identity.TenantID, user identity.UserID, fields []identity.FeatureField) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	if len(fields) == 0 || len(fields) > 128 || tenant == "" || user == "" || len(tenant) > 128 || len(user) > 128 {
		return deny()
	}
	values := make(map[string]identity.FeatureValue, len(fields))
	for _, f := range fields {
		if len(f.Name) > 128 || !strings.HasPrefix(f.Name, originalSessionPrefix) || len(f.Value.Text) > 4096 || len(f.Value.Bytes) > 4096 {
			return deny()
		}
		name := strings.TrimPrefix(f.Name, originalSessionPrefix)
		if _, exists := values[name]; exists {
			return deny()
		}
		values[name] = f.Value
	}
	kind := values["authentication.kind"]
	if kind.Kind != identity.FeatureUint64 || kind.Uint64 != uint64(session.AuthenticationVerified) && kind.Uint64 != uint64(session.AuthenticationOTP) && kind.Uint64 != uint64(session.AuthenticationMagicLink) {
		return deny()
	}
	binding := identity.CommandBinding{TenantID: tenant, UserID: user}
	if kind.Uint64 == uint64(session.AuthenticationOTP) {
		// This is the historical authenticating OTP command, not the protected
		// command that now carries the original session as admission metadata.
		binding.CommandID = identity.CommandID(values["otp.command"].Text)
	}
	if kind.Uint64 == uint64(session.AuthenticationMagicLink) {
		binding.CommandID = identity.CommandID(values["magiclink.command"].Text)
	}
	restored, err := sessionRecordFromFieldsKind(binding, values, session.AuthenticationKind(kind.Uint64))
	if err != nil {
		return deny()
	}
	expected, err := OriginalSessionFields(restored)
	if err != nil || len(expected) != len(fields) {
		return deny()
	}
	// Re-encoding through the same owner rejects inactive tagged-union members
	// that structural decoding intentionally does not read. Compare by name so
	// the shared command codec's sorting cannot change admission semantics.
	canonical := make(map[string]identity.FeatureValue, len(expected))
	for _, f := range expected {
		canonical[f.Name] = f.Value
	}
	for _, f := range fields {
		a, b := canonical[f.Name], f.Value
		if a.Kind != b.Kind || a.Text != b.Text || a.Uint64 != b.Uint64 || a.Int64 != b.Int64 || a.Bool != b.Bool || a.Time != b.Time || (a.Bytes == nil) != (b.Bytes == nil) || !bytes.Equal(a.Bytes, b.Bytes) {
			return deny()
		}
	}
	return restored, nil
}
