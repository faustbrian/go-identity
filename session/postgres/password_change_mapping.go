package postgres

import (
	"bytes"
	"strings"

	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// PasswordChangeSessionDisposition is an explicit selection frozen in the
// original password-change command. Zero is invalid; no default is inferred.
// These values express intent, not authentication or a completed durable effect.
type PasswordChangeSessionDisposition uint8

const (
	// PasswordChangePreserveSessions continues eligible existing password
	// sessions. Stale or terminal records must never be upgraded into validity.
	PasswordChangePreserveSessions PasswordChangeSessionDisposition = iota + 1
	// PasswordChangeRevokeOtherSessions retains the authenticated source and
	// terminally revokes every other selected session of the same tenant/user.
	PasswordChangeRevokeOtherSessions
	// PasswordChangeRevokeAllSessions revokes the source and all other selected
	// sessions; no returned historical bearer remains authorized by this choice.
	PasswordChangeRevokeAllSessions
)

// PasswordChangeSessionFields returns owned scalar metadata binding complete
// original-session custody, disposition and a whole-set maximum of 1..100000.
// Append these to CredentialReplacementFields before constructing the original
// password-change command. Never replace the selection after reservation or
// infer it from retries. The maximum counts every selected active-state row,
// including expired/stale rows; it is not a per-page limit.
//
// Only verified single-factor password sessions without organization, factor
// or passkey dimensions are admitted by this initial native profile. Their
// complete history, independent effective credential linkage, remember policy
// and CSRF state are retained. Other profiles require their real owner effects.
// No IO, callback, clock read, permission, current-owner check or session mutation
// occurs. Atomic same-Work execution and original-effect recovery are separately
// required; these fields alone cannot enable preservation. Concurrent immutable
// reads are safe; returned projections must not be logged or exposed to clients.
func PasswordChangeSessionFields(original session.Session, disposition PasswordChangeSessionDisposition, maximum uint32) ([]identity.FeatureField, error) {
	if !validPasswordDisposition(disposition, uint64(maximum)) || !passwordSessionProfile(original) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(original)
	if err != nil {
		return nil, err
	}
	return append(fields,
		identity.FeatureField{Name: "password-sessions.disposition", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(disposition)}},
		identity.FeatureField{Name: "password-sessions.maximum", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(maximum)}},
	), nil
}

func validPasswordDisposition(mode PasswordChangeSessionDisposition, maximum uint64) bool {
	return mode >= PasswordChangePreserveSessions && mode <= PasswordChangeRevokeAllSessions && maximum >= 1 && maximum <= 100000
}

func passwordSessionProfile(record session.Session) bool {
	s, err := record.Bindings()
	if err != nil || s.Authentication.Kind != session.AuthenticationVerified || s.Authentication.Proof.Method != "password" || s.Authentication.Proof.Assurance != authentication.AssuranceSingleFactor {
		return false
	}
	a, err := s.Authority.Bindings()
	return err == nil && !a.Organization.Present && !a.Factor.Present && !a.Passkey.Present
}

type passwordChangeSessionIntent struct {
	original    session.Session
	disposition PasswordChangeSessionDisposition
	maximum     uint32
	replacement kernel.CredentialReplacementIntent
}

func passwordChangeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func passwordChangeMetadata(command identity.Command) (identity.FeatureCommandSpec, bool) {
	if p, ok := command.PasswordChangeFeature(); ok {
		return p, true
	}
	return command.PasswordHashFeature()
}

// Decode only owner namespaces, permitting separately owned risk metadata. The
// registered native password participant must validate the complete command.
func passwordChangeSessions(command identity.Command) (passwordChangeSessionIntent, error) {
	deny := func() (passwordChangeSessionIntent, error) {
		return passwordChangeSessionIntent{}, session.ErrInvalidSessionCommand
	}
	p, ok := passwordChangeMetadata(command)
	if !ok || p.Operation != passwordChangeOperation() || p.Binding.ActorKind != authorization.SubjectUser || string(p.Binding.ActorID) != string(p.Binding.UserID) {
		return deny()
	}
	var originalFields []identity.FeatureField
	credential := make(map[string]identity.FeatureValue, 8)
	selection := make(map[string]identity.FeatureValue, 2)
	for _, f := range p.Fields {
		switch {
		case strings.HasPrefix(f.Name, originalSessionPrefix):
			originalFields = append(originalFields, f)
		case strings.HasPrefix(f.Name, "credential."):
			if _, duplicate := credential[f.Name]; duplicate {
				return deny()
			}
			credential[f.Name] = f.Value
		case strings.HasPrefix(f.Name, "password-sessions."):
			if _, duplicate := selection[f.Name]; duplicate {
				return deny()
			}
			selection[f.Name] = f.Value
		}
	}
	if len(credential) != 8 || len(selection) != 2 {
		return deny()
	}
	mode, maximum := selection["password-sessions.disposition"], selection["password-sessions.maximum"]
	if mode.Uint64 > uint64(PasswordChangeRevokeAllSessions) || !canonicalPasswordNumber(mode) || !canonicalPasswordNumber(maximum) || !validPasswordDisposition(PasswordChangeSessionDisposition(mode.Uint64), maximum.Uint64) {
		return deny()
	}
	original, err := OriginalSessionFromFields(p.Binding.TenantID, p.Binding.UserID, originalFields)
	if err != nil || !passwordSessionProfile(original) {
		return deny()
	}
	s, _ := original.Bindings()
	a, _ := s.Authority.Bindings()
	i := kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: identity.CredentialID(s.Authentication.CredentialID), TenantID: s.TenantID, UserID: s.UserID, Kind: identity.CredentialPassword, Owner: p.Operation.Owner, Version: original.EffectiveCredentialVersion()}, ExpectedUserVersion: credential["credential.expected-user-version"].Uint64, ExpectedAuthorityVersion: a.Credential.Version}
	if p.Binding.RecordID != string(i.Credential.ID) {
		return deny()
	}
	expected, err := kernel.CredentialReplacementFields(i)
	if err != nil {
		return deny()
	}
	for _, f := range expected {
		if got, exists := credential[f.Name]; !exists || !samePasswordField(got, f.Value) {
			return deny()
		}
	}
	return passwordChangeSessionIntent{original: original, disposition: PasswordChangeSessionDisposition(mode.Uint64), maximum: uint32(maximum.Uint64), replacement: i}, nil
}

func canonicalPasswordNumber(v identity.FeatureValue) bool {
	return samePasswordField(v, identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v.Uint64})
}

func samePasswordField(a, b identity.FeatureValue) bool {
	return a.Kind == b.Kind && a.Text == b.Text && a.Uint64 == b.Uint64 && a.Int64 == b.Int64 && a.Bool == b.Bool && a.Time == b.Time && (a.Bytes == nil) == (b.Bytes == nil) && bytes.Equal(a.Bytes, b.Bytes)
}

// Mapping requires the exact original reference and independent user credential
// epoch. Current-owner admission and lifetime checks belong to same-Work use,
// not to this structural helper. User aggregate is deliberately not authority.
func passwordChangeSessionSuccessor(source session.Session, binding identity.CommandBinding, intent kernel.CredentialReplacementIntent) (session.Session, error) {
	s, err := source.Bindings()
	if err != nil || !passwordSessionProfile(source) || s.TenantID != binding.TenantID || s.UserID != binding.UserID || binding.OperationID != passwordChangeOperation().OperationID || binding.RecordID != string(intent.Credential.ID) || intent.Credential.Validate(s.TenantID, s.UserID) != nil || intent.Credential.Kind != identity.CredentialPassword || intent.Credential.Owner != "identity/password" || s.Authentication.CredentialID != string(intent.Credential.ID) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return session.ContinuePasswordSession(source, session.CredentialContinuationSpec{CommandID: binding.CommandID, BeforeAuthorityVersion: intent.ExpectedAuthorityVersion, BeforeCredentialVersion: intent.Credential.Version})
}
