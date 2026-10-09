package postgres

import (
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const otpSessionPrefix = "session.result."

// OTPSigninSessionFields returns the closed scalar session-owned fields for an
// OTP signin command. It preserves the complete original session, authentication,
// authority, remember policy and optional CSRF digest, never a bearer or code.
// The OTP owner must include these fields before command fingerprinting and
// reservation, alongside its own exhaustively validated fields. Construction
// proves neither authentication nor permission to persist the session.
func OTPSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	fields, err := sessionRecordFields(record, true)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		fields[i].Name = otpSessionPrefix + fields[i].Name
	}
	return fields, nil
}

// OTPSigninSession reconstructs the exact session-owned result of a closed v1
// OTP signin command. Unknown or missing session fields fail closed. Other
// fields remain the OTP owner's responsibility. Anonymous command scope stays
// anonymous; the selected session user is separately bound in these fields.
// This structural decoder grants no consumption, issuance or recovery authority.
func OTPSigninSession(command identity.Command) (session.Session, error) {
	p, ok := command.Feature()
	if !ok {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if p.Binding.AnonymousFlowID != "" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	if p.Operation != op {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	values := make(map[string]identity.FeatureValue)
	for _, field := range p.Fields {
		if name, owned := strings.CutPrefix(field.Name, otpSessionPrefix); owned {
			values[name] = field.Value
		}
	}
	return sessionRecordFromFields(p.Binding, values, true)
}
