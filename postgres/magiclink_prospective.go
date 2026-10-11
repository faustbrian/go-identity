package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// RequireProspectiveRecipient fences an unused email and prospective IDs during
// the original native magic-link request Apply. It creates no user, verification
// or empty MFA state. The same kernel tenant/retirement policy used by creation
// owns collision admission; consumption must independently create and recheck.
// Its frozen intent binds staged signed issuance, not current authentication.
// Errors poison Work. Call only in the serial invocation with the enlisted
// repository and retain neither Work nor intent across a callback.
func (d *MagicLinkRegistrationDomain) RequireProspectiveRecipient(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent MagicLinkRegistrationIntent) error {
	if err := w.usable(); err != nil {
		return err
	}
	fail := func(err error) error { return w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil || p == nil {
		return fail(invalidMagicLinkRegistration())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return err
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil || !magicLinkRequestOperation(f.Operation) || f.Contributor != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || b.UserID != "" || b.AnonymousFlowID == "" || intent.ComparisonProfile != d.comparison || intent.EmailPossessionPolicyVersion != d.emailPolicy {
		return fail(invalidMagicLinkRegistration())
	}
	expected := b
	expected.OperationID, expected.AnonymousFlowID, expected.UserID = "identity.user.create", "", intent.Creation.Binding.UserID
	expected.SchemaID, expected.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
	if intent.Creation.Binding != expected {
		return fail(invalidMagicLinkRegistration())
	}
	if _, err := MagicLinkRegistrationFields(intent); err != nil {
		return fail(err)
	}
	enlisted := false
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == d.repository {
			enlisted = true
		}
	}
	if !enlisted {
		return fail(invalidWork())
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	blocked, err := classifyIdentifierReuse(ctx, w, identity.IdentifierChange{Action: identity.IdentifierAttach, TenantID: b.TenantID, UserID: intent.Creation.Binding.UserID, ID: intent.Identifier.ID, Kind: identity.IdentifierEmail, CanonicalValue: intent.Identifier.CanonicalValue}, d.reuse, now, false)
	if err != nil {
		return err
	}
	if blocked {
		return fail(identity.ConflictError{})
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(intent.Creation.Binding.UserID))
	if err != nil {
		return err
	}
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return fail(identity.UnavailableError{})
	}
	rows.Close()
	if exists {
		return fail(identity.ConflictError{})
	}
	// Own the creation attributes rather than retain caller-mutable slices.
	creation, err := identity.NewUserCreationCommand(intent.Creation)
	if err != nil {
		return fail(err)
	}
	intent.Creation, _ = creation.CreateUser()
	w.state.magicLinkRecipient = &magicLinkRecipientAdmission{owner: p, prospective: &intent}
	return nil
}
