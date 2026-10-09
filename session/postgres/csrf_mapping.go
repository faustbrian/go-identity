package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Absence emits no fields, preserving historical tokenless command identity.
// Binding is derived from the exact enclosing record, never a second authority.
func appendCSRFFields(fields []identity.FeatureField, prefix string, record session.Session) []identity.FeatureField {
	state, err := record.CSRFState().Bindings()
	if err != nil {
		return fields
	}
	return append(fields,
		identity.FeatureField{Name: prefix + "csrf.key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(state.KeyVersion)}},
		identity.FeatureField{Name: prefix + "csrf.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: state.Digest[:]}},
	)
}

// Consume both extension fields or neither. Partial/unknown extensions cannot
// downgrade to legacy; the enclosing closed decoder rejects leftover fields.
func sessionFromCSRFFields(values map[string]identity.FeatureValue, prefix string, base session.SessionSpec) (session.Session, error) {
	return sessionFromCSRFFieldsWithOTP(values, prefix, base, session.OTPAuthentication{})
}

func sessionFromCSRFFieldsWithOTP(values map[string]identity.FeatureValue, prefix string, base session.SessionSpec, metadata session.OTPAuthentication) (session.Session, error) {
	key, hasKey := values[prefix+"csrf.key-version"]
	digest, hasDigest := values[prefix+"csrf.digest"]
	delete(values, prefix+"csrf.key-version")
	delete(values, prefix+"csrf.digest")
	if !hasKey && !hasDigest {
		if base.Authentication.Kind == session.AuthenticationOTP {
			return session.NewSessionWithOTP(base, metadata)
		}
		return session.NewSession(base)
	}
	if !hasKey || !hasDigest || key.Kind != identity.FeatureUint64 || key.Uint64 == 0 || key.Uint64 > uint64(^uint32(0)) || digest.Kind != identity.FeatureBytes || len(digest.Bytes) != 32 {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	spec := session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: base.TenantID, SessionID: base.SessionID, SessionVersion: base.Version}, KeyVersion: uint32(key.Uint64)}
	copy(spec.Digest[:], digest.Bytes)
	state, err := session.NewCSRFState(spec)
	if err != nil {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	if base.Authentication.Kind == session.AuthenticationOTP {
		return session.NewSessionWithOTPAndCSRF(base, metadata, state)
	}
	return session.NewSessionWithCSRF(base, state)
}
