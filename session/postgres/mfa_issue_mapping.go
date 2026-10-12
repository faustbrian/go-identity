package postgres

import (
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const mfaCompletionSessionPrefix = "session.result."

// MFATOTPCompletionSessionFields freezes the complete prospective password or
// magic-link primary/TOTP session before native command fingerprinting.
// It retains original primary, child/factor provenance, every authority dimension,
// resolved remember policy and optional CSRF, never a bearer or submitted code.
// Only the initial native TOTP completion profile is accepted. This bounded
// structural mapping performs no verification, reservation, IO or renewal.
func MFATOTPCompletionSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return mfaCompletionSessionFields(record, "totp")
}

// MFARecoveryCompletionSessionFields freezes complete original-primary and
// recovery-set/factor provenance without submitted code or bearer custody.
// It is structural metadata, never permission to burn a code or issue a session.
func MFARecoveryCompletionSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return mfaCompletionSessionFields(record, "recovery-code")
}

func mfaCompletionSessionFields(record session.Session, method string) ([]identity.FeatureField, error) {
	if !mfaCompletionRecord(record, method) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	for i := range fields {
		fields[i].Name = mfaCompletionSessionPrefix + strings.TrimPrefix(fields[i].Name, originalSessionPrefix)
	}
	return fields, nil
}

// MFATOTPCompletionSession restores only the complete session-owned projection
// of an anonymous TOTP completion v1 command. Completion identity and tenant
// must match; original primary identity remains distinct and cannot retarget the
// browser command. Missing, mixed, noncanonical or extra session fields deny.
// The native owner separately checks non-session fields and original opaque
// code/browser/child custody and actual recorded factor completion. Successful
// reconstruction is not authentication or permission to persist a session.
func MFATOTPCompletionSession(command identity.Command) (session.Session, error) {
	return mfaCompletionSession(command, mfaTOTPCompletionSessionOperation(), "totp")
}

// MFARecoveryCompletionSession restores only exact recovery-use v1 session
// metadata. Missing set epoch, partial fields or TOTP substitution denies.
// The native owner must authenticate original primary/browser/child and prove
// actual recorded recovery burn in the same transaction before persistence.
func MFARecoveryCompletionSession(command identity.Command) (session.Session, error) {
	return mfaCompletionSession(command, mfaRecoveryCompletionSessionOperation(), "recovery-code")
}

func mfaCompletionSession(command identity.Command, operation identity.FeatureOperation, method string) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	p, ok := command.Feature()
	if !ok || p.Operation != operation || p.Binding.UserID != "" || p.Binding.RecordID != "" || p.Binding.AnonymousFlowID == "" {
		return deny()
	}
	fields := make([]identity.FeatureField, 0, 96)
	var user identity.UserID
	var passwordSubject identity.UserID
	var kind session.AuthenticationKind
	for _, f := range p.Fields {
		name, owned := strings.CutPrefix(f.Name, mfaCompletionSessionPrefix)
		if !owned {
			continue
		}
		if name == "user.id" {
			user = identity.UserID(f.Value.Text)
		}
		if name == "proof.subject" {
			passwordSubject = identity.UserID(f.Value.Text)
		}
		if name == "authentication.kind" && f.Value.Kind == identity.FeatureUint64 && f.Value.Uint64 == uint64(session.AuthenticationVerified) {
			kind = session.AuthenticationVerified
		}
		f.Name = originalSessionPrefix + name
		fields = append(fields, f)
	}
	if kind == session.AuthenticationVerified {
		// Verified-credential mappings derive scope from the bound original
		// proof, not the magic-link-specific user.id union member. Complete
		// reconstruction below checks its tenant/subject and rejects mixtures.
		user = passwordSubject
	}
	record, err := OriginalSessionFromFields(p.Binding.TenantID, user, fields)
	if err != nil || !mfaCompletionRecord(record, method) {
		return deny()
	}
	m, _ := record.MFAAuthentication().Bindings()
	if m.CommandID != p.Binding.CommandID {
		return deny()
	}
	return record, nil
}

func mfaTOTPCompletionSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func mfaRecoveryCompletionSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.recovery-use", SchemaID: "mfa-recovery-use", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func mfaTOTPCompletionRecord(record session.Session) bool {
	return mfaCompletionRecord(record, "totp")
}

func mfaCompletionRecord(record session.Session, method string) bool {
	s, err := record.Bindings()
	if err != nil || s.Version != 1 || !s.IssuedAt.Equal(s.LastActivityAt) {
		return false
	}
	a, err := s.Authority.Bindings()
	if err != nil || a.Organization.Present || !a.Factor.Present || a.Passkey.Present {
		return false
	}
	m, err := record.MFAAuthentication().Bindings()
	if err != nil || m.Method != method || m.FactorAuthorityVersion != a.Factor.Binding.Version {
		return false
	}
	switch s.Authentication.Kind {
	case session.AuthenticationMagicLink:
		p, err := record.MagicLinkAuthentication().Bindings()
		if err != nil || m.PrimaryCommandID != p.CommandID {
			return false
		}
	case session.AuthenticationVerified:
		if s.Authentication.Proof.Method != "password" || string(m.PrimaryCommandID) != string(s.Authentication.Proof.ID) {
			return false
		}
	default:
		return false
	}
	_, continued := record.CredentialContinuation()
	return !continued
}
