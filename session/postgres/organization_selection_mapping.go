package postgres

import (
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const organizationSelectionPrefix = "organization.selection."

// OrganizationSelectionFields maps the complete original session, explicit
// selection/clear and original exclusive admission deadline into the native
// organization's command vocabulary. It contains no raw bearer or permission
// proof. The organization owner must authenticate custody and require actual
// current membership, lifecycle and policy inside the sole coordinator Work.
// Until must already be UTC/microsecond exact; never round its expiry upward.
// Returned fields are owned copies; no IO or validity renewal occurs.
func OrganizationSelectionFields(command session.OrganizationSelectionCommand, until time.Time) ([]identity.FeatureField, error) {
	c, err := command.Bindings()
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	s, _ := c.Source.Bindings()
	life, err := c.Source.Lifetime(s.LastActivityAt)
	if err != nil || !sessionReadTime(until) || until.Nanosecond()%1000 != 0 || !until.After(s.LastActivityAt) || until.After(life.ExpiresAt) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(c.Source)
	if err != nil || len(fields) > 124 {
		return nil, session.ErrInvalidSessionCommand
	}
	// The kernel vocabulary allows128 fields. Leave four slots for the closed
	// selection members rather than silently truncating original provenance.
	return append(fields,
		identity.FeatureField{Name: organizationSelectionPrefix + "id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: c.Selection.OrganizationID}},
		identity.FeatureField{Name: organizationSelectionPrefix + "authority-key", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: c.Selection.Authority.ScopeKey}},
		identity.FeatureField{Name: organizationSelectionPrefix + "authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: c.Selection.Authority.Version}},
		identity.FeatureField{Name: organizationSelectionPrefix + "valid-until", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: until.UTC()}},
	), nil
}

// OrganizationSelectionFromFields reconstructs only structural original intent.
// It validates the kernel's bounded closed scalar union before allocating owned
// field copies. Unknown/duplicate/inactive selection or source-session members
// deny. Other valid field namespaces remain the organization's responsibility;
// this decoder neither admits their domain schema nor authorizes execution.
// Exact tenant, human actor, stable session ID and source CAS must still match.
// Original time/provenance survive reconstruction; no live admission is minted.
func OrganizationSelectionFromFields(b identity.CommandBinding, fields []identity.FeatureField) (session.OrganizationSelectionCommand, time.Time, error) {
	deny := func() (session.OrganizationSelectionCommand, time.Time, error) {
		return session.OrganizationSelectionCommand{}, time.Time{}, session.ErrInvalidSessionCommand
	}
	validated, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: session.OrganizationSelectionOperation(), Fields: fields})
	if err != nil {
		return deny()
	}
	projection, _ := validated.Feature()
	var sourceFields []identity.FeatureField
	selected := make(map[string]identity.FeatureValue, 4)
	for _, field := range projection.Fields {
		switch {
		case strings.HasPrefix(field.Name, originalSessionPrefix):
			sourceFields = append(sourceFields, field)
		case strings.HasPrefix(field.Name, organizationSelectionPrefix):
			switch field.Name {
			case organizationSelectionPrefix + "id", organizationSelectionPrefix + "authority-key", organizationSelectionPrefix + "authority-version", organizationSelectionPrefix + "valid-until":
				selected[field.Name] = field.Value
			default:
				return deny()
			}
		}
	}
	if len(selected) != 4 {
		return deny()
	}
	id, key := selected[organizationSelectionPrefix+"id"], selected[organizationSelectionPrefix+"authority-key"]
	version, deadline := selected[organizationSelectionPrefix+"authority-version"], selected[organizationSelectionPrefix+"valid-until"]
	if id.Kind != identity.FeatureText || key.Kind != identity.FeatureText || version.Kind != identity.FeatureUint64 || deadline.Kind != identity.FeatureTime {
		return deny()
	}
	source, err := OriginalSessionFromFields(b.TenantID, b.UserID, sourceFields)
	if err != nil {
		return deny()
	}
	spec, _ := source.Bindings()
	selection := session.ActiveOrganizationSelection{SessionID: spec.SessionID, TenantID: spec.TenantID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: id.Text, Authority: session.AuthorityBinding{ScopeKey: key.Text, Version: version.Uint64}}
	command, err := session.NewOrganizationSelectionCommand(b, source, selection)
	if err != nil {
		return deny()
	}
	if _, err := OrganizationSelectionFields(command, deadline.Time); err != nil {
		return deny()
	}
	return command, deadline.Time, nil
}
