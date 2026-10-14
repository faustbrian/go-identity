package postgres

import (
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Validate only the exact declared atomic transition. This performs no
// authorization, admission renewal, IO or registry installation; executor
// custody and native locked authority comparisons remain separate phases.
func (r *Repository) validateRotationPlan(command identity.Command, p kernel.CommandPlan) error {
	if r == nil || r.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	native, _, _, err := nativeRotationIntent(command)
	if err != nil {
		return err
	}
	rotation, _ := native.Rotation()
	source, _ := rotation.Source.Bindings()
	if _, _, _, err = sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), rotation.Source, rotation.Binding, source.SessionID, source.Version); err != nil {
		return err
	}
	if p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != session.RotateOperation() || p.SubjectType != "session" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.rotated.v1" || p.Lifecycle.BeforeVersion != source.Version || p.Lifecycle.AfterVersion != source.Version+1 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.refresh" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}
