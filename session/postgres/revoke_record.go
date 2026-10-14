package postgres

import (
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Revocation retains historical possession provenance, not a new issuance
// command. Reuse the original-record codec so a logout's command ID cannot
// replace the authenticating command. Issuance remains on its stricter codec.
func mapRevokeSessionRecord(b identity.CommandBinding, record session.Session) (identity.Command, error) {
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return identity.Command{}, err
	}
	for i := range fields {
		fields[i].Name = strings.TrimPrefix(fields[i].Name, originalSessionPrefix)
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: session.RevokeOneOperation(), Fields: fields})
}

func nativeRevokeSessionRecord(command identity.Command) (identity.CommandBinding, session.Session, error) {
	p, ok := command.Feature()
	if !ok || p.Operation != session.RevokeOneOperation() {
		return identity.CommandBinding{}, session.Session{}, session.ErrInvalidSessionCommand
	}
	fields := make([]identity.FeatureField, len(p.Fields))
	for i, f := range p.Fields {
		f.Name = originalSessionPrefix + f.Name
		fields[i] = f
	}
	record, err := OriginalSessionFromFields(p.Binding.TenantID, p.Binding.UserID, fields)
	if err != nil {
		return identity.CommandBinding{}, session.Session{}, err
	}
	return p.Binding, record, nil
}
