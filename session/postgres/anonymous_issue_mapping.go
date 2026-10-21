package postgres

import (
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const anonymousSessionPrefix = "session.result."

// AnonymousSigninSessionFields freezes the complete prospective unprivileged
// session in the session.result namespace before command fingerprinting. It
// retains original remember, anonymous creation time, every authority dimension
// and optional CSRF digest, never a bearer or verified credential. Only an
// initial anonymous record is supported. This mapping grants no risk, kernel
// creation, current authority or persistence admission; the native owner must
// establish all of those atomically in its original Work. Returned bytes belong
// to the caller and must not be logged or mutated during use.
func AnonymousSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	if !anonymousSigninRecord(record) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := sessionRecordFieldsKind(record, session.AuthenticationAnonymous)
	if err != nil {
		return nil, err
	}
	for j := range fields {
		fields[j].Name = anonymousSessionPrefix + fields[j].Name
	}
	return fields, nil
}

// AnonymousSigninSession restores only the complete session-owned projection of
// the closed anonymous-flow signin command. Missing/extra/foreign fields deny;
// other namespaces remain the anonymous owner's responsibility. It creates no
// authentication proof, renewal, command authority or permission to issue.
func AnonymousSigninSession(command identity.Command) (session.Session, error) {
	spec, ok := command.Feature()
	if !ok || spec.Operation != anonymousSessionOperation() {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	values := make(map[string]identity.FeatureValue)
	for _, field := range spec.Fields {
		if name, owned := strings.CutPrefix(field.Name, anonymousSessionPrefix); owned {
			values[name] = field.Value
		}
	}
	record, err := sessionRecordFromFieldsKind(spec.Binding, values, session.AuthenticationAnonymous)
	if err != nil || !anonymousSigninRecord(record) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return record, nil
}

func anonymousSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.signin", SchemaID: "identity.anonymous.signin.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func anonymousSigninRecord(record session.Session) bool {
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Kind != session.AuthenticationAnonymous || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.Authentication.AnonymousAt.Equal(spec.IssuedAt) || !spec.LastActivityAt.Equal(spec.IssuedAt) {
		return false
	}
	if _, continued := record.CredentialContinuation(); continued {
		return false
	}
	vector, err := spec.Authority.Bindings()
	return err == nil && !vector.Organization.Present && !vector.Factor.Present && !vector.Passkey.Present
}
