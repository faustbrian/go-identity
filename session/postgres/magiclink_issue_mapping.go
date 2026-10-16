package postgres

import (
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const magicLinkSessionPrefix = "session.result."

// MagicLinkSigninSessionFields freezes the complete prospective email-grant
// session into the session.result namespace before command fingerprinting.
// It preserves original grant, request, identifier versions, remember policy,
// authority and optional CSRF; it never contains a bearer or proof. Returned
// fields and bytes are caller-owned. Only initial single-factor magic-link
// sessions are accepted. This pure bounded mapping proves no consumption or
// current authority: the registered native owner must check both in its Work.
func MagicLinkSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	if !magicLinkSigninRecord(record) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	for i := range fields {
		fields[i].Name = magicLinkSessionPrefix + strings.TrimPrefix(fields[i].Name, originalSessionPrefix)
	}
	return fields, nil
}

// MagicLinkSigninSession restores only the complete session-owned projection
// from the exact anonymous magic-link-consume v1 command. Original command
// identity and tenant must match; the selected user remains separately bound
// without retargeting anonymous scope. Missing, extra, mixed or noncanonical
// session fields deny with ErrInvalidSessionCommand. Other fields are checked
// by the magic-link owner. No proof authentication, consumption, freshness
// renewal or permission to issue is established. Inputs must remain immutable
// during this synchronous bounded call; returned state owns its bytes.
func MagicLinkSigninSession(command identity.Command) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	p, ok := command.Feature()
	if !ok || p.Operation != magicLinkSessionOperation() || p.Binding.UserID != "" || p.Binding.RecordID != "" || p.Binding.AnonymousFlowID == "" {
		return deny()
	}
	return emailGrantSessionFromFeature(p)
}

// Shared scalar restoration preserves the same complete email-grant record;
// each public entry point first admits its own disjoint operation/scope.
func emailGrantSessionFromFeature(p identity.FeatureCommandSpec) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	fields := make([]identity.FeatureField, 0, 64)
	var user identity.UserID
	for _, f := range p.Fields {
		name, owned := strings.CutPrefix(f.Name, magicLinkSessionPrefix)
		if !owned {
			continue
		}
		if name == "user.id" {
			user = identity.UserID(f.Value.Text)
		}
		f.Name = originalSessionPrefix + name
		fields = append(fields, f)
	}
	record, err := OriginalSessionFromFields(p.Binding.TenantID, user, fields)
	if err != nil || !magicLinkSigninRecord(record) {
		return deny()
	}
	meta, _ := record.MagicLinkAuthentication().Bindings()
	if meta.CommandID != p.Binding.CommandID {
		return deny()
	}
	return record, nil
}

func magicLinkSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func magicLinkSigninRecord(record session.Session) bool {
	s, err := record.Bindings()
	if err != nil || s.Authentication.Kind != session.AuthenticationMagicLink || s.Version != 1 || !s.IssuedAt.Equal(s.LastActivityAt) {
		return false
	}
	a, err := s.Authority.Bindings()
	if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return false
	}
	p, err := record.MagicLinkAuthentication().Bindings()
	if err != nil || s.IssuedAt.Before(p.AuthenticatedAt) || !s.IssuedAt.Before(p.ValidUntil) {
		return false
	}
	_, continued := record.CredentialContinuation()
	return !continued
}
