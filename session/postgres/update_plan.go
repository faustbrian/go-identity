package postgres

import (
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func (r *Repository) validateUpdatePlan(command identity.Command, p kernel.CommandPlan) error {
	if r == nil || r.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	native, _, _, err := nativeUpdateIntent(command)
	if err != nil {
		return err
	}
	u, _ := native.Update()
	s, _ := u.Source.Bindings()
	if _, _, _, err = sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), u.Source, u.Binding, s.SessionID, s.Version); err != nil {
		return err
	}
	if p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != session.UpdateOperation() || p.SubjectType != "session" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.updated.v1" || p.Lifecycle.BeforeVersion != s.Version || p.Lifecycle.AfterVersion != s.Version+1 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.update" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}
