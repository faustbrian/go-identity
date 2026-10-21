package postgres

import (
	"bytes"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const anonymousSourcePrefix = "anonymous.source-session."

// AnonymousSourceSessionFields freezes the existing anonymous session's full
// digest-only record in a separate closed namespace. This does not broaden the
// verified OriginalSessionFields profile. It authenticates nothing: the native
// workflow must prove bearer/CSRF possession and current primary owners before
// any protected transition. Caller owns returned fields; never log them.
func AnonymousSourceSessionFields(original session.Session) ([]identity.FeatureField, error) {
	s, err := original.Bindings()
	if err != nil || s.Authentication.Kind != session.AuthenticationAnonymous {
		return nil, session.ErrInvalidSessionCommand
	}
	vector, err := s.Authority.Bindings()
	if err != nil || vector.Organization.Present || vector.Factor.Present || vector.Passkey.Present || original.MFAAuthentication() != (session.MFAAuthentication{}) {
		return nil, session.ErrInvalidSessionCommand
	}
	f, err := sessionRecordFieldsKind(original, session.AuthenticationAnonymous)
	if err != nil {
		return nil, err
	}
	for n := range f {
		f[n].Name = anonymousSourcePrefix + f[n].Name
	}
	return f, nil
}

// AnonymousSourceSessionFromFields restores only the exact frozen anonymous
// projection for this tenant/user. Duplicates, unknown fields, inactive union
// data, omissions and oversized inputs deny. It grants no authentication,
// freshness, authorization, mutation or bearer re-disclosure.
func AnonymousSourceSessionFromFields(tenant identity.TenantID, user identity.UserID, fields []identity.FeatureField) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	if len(fields) == 0 || len(fields) > 128 || !scopeID(string(tenant)) || !scopeID(string(user)) {
		return deny()
	}
	values := make(map[string]identity.FeatureValue, len(fields))
	for _, f := range fields {
		if len(f.Name) > 128 || len(f.Value.Text) > 4096 || len(f.Value.Bytes) > 4096 {
			return deny()
		}
		n, ok := strings.CutPrefix(f.Name, anonymousSourcePrefix)
		if !ok {
			return deny()
		}
		if _, exists := values[n]; exists {
			return deny()
		}
		values[n] = f.Value
	}
	r, err := sessionRecordFromFieldsKind(identity.CommandBinding{TenantID: tenant, UserID: user}, values, session.AuthenticationAnonymous)
	if err != nil {
		return deny()
	}
	canonical, err := AnonymousSourceSessionFields(r)
	if err != nil || len(canonical) != len(fields) {
		return deny()
	}
	values = make(map[string]identity.FeatureValue, len(fields))
	for _, field := range fields {
		values[strings.TrimPrefix(field.Name, anonymousSourcePrefix)] = field.Value
	}
	for _, f := range canonical {
		a := values[strings.TrimPrefix(f.Name, anonymousSourcePrefix)]
		b := f.Value
		if a.Kind != b.Kind || a.Text != b.Text || a.Uint64 != b.Uint64 || a.Int64 != b.Int64 || a.Bool != b.Bool || !a.Time.Equal(b.Time) || !bytes.Equal(a.Bytes, b.Bytes) {
			return deny()
		}
	}
	return r, nil
}
