package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Absence emits no fields, preserving historical tokenless command identity.
// Binding is derived from the exact enclosing record, never a second authority.
func appendCSRFFields(fields []identity.FeatureField, prefix string, record session.Session) []identity.FeatureField {
	if c, ok := record.CredentialContinuation(); ok {
		fields = append(fields,
			identity.FeatureField{Name: prefix + "continuation.command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(c.CommandID)}},
			identity.FeatureField{Name: prefix + "continuation.authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: c.BeforeAuthorityVersion}},
			identity.FeatureField{Name: prefix + "continuation.credential", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: c.BeforeCredentialVersion}},
		)
	}
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
	return sessionFromCSRFFieldsWithProvenance(values, prefix, base, metadata, session.MagicLinkAuthentication{})
}

func sessionFromCSRFFieldsWithProvenance(values map[string]identity.FeatureValue, prefix string, base session.SessionSpec, metadata session.OTPAuthentication, magic session.MagicLinkAuthentication) (session.Session, error) {
	command, hasCommand := values[prefix+"continuation.command"]
	authority, hasAuthority := values[prefix+"continuation.authority"]
	credential, hasCredential := values[prefix+"continuation.credential"]
	delete(values, prefix+"continuation.command")
	delete(values, prefix+"continuation.authority")
	delete(values, prefix+"continuation.credential")
	continued := hasCommand || hasAuthority || hasCredential
	if continued && (!hasCommand || !hasAuthority || !hasCredential || command.Kind != identity.FeatureText || authority.Kind != identity.FeatureUint64 || credential.Kind != identity.FeatureUint64) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	c := session.CredentialContinuationSpec{CommandID: identity.CommandID(command.Text), BeforeAuthorityVersion: authority.Uint64, BeforeCredentialVersion: credential.Uint64}
	key, hasKey := values[prefix+"csrf.key-version"]
	digest, hasDigest := values[prefix+"csrf.digest"]
	delete(values, prefix+"csrf.key-version")
	delete(values, prefix+"csrf.digest")
	if !hasKey && !hasDigest {
		if continued {
			return session.NewContinuedPasswordSession(base, session.CSRFState{}, c)
		}
		if base.Authentication.Kind == session.AuthenticationOTP {
			return session.NewSessionWithOTP(base, metadata)
		}
		if base.Authentication.Kind == session.AuthenticationMagicLink {
			return session.NewSessionWithMagicLink(base, magic)
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
	if continued {
		return session.NewContinuedPasswordSession(base, state, c)
	}
	if base.Authentication.Kind == session.AuthenticationOTP {
		return session.NewSessionWithOTPAndCSRF(base, metadata, state)
	}
	if base.Authentication.Kind == session.AuthenticationMagicLink {
		return session.NewSessionWithMagicLinkAndCSRF(base, magic, state)
	}
	return session.NewSessionWithCSRF(base, state)
}
