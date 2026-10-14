package postgres

import (
	"context"
	"strings"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// AdmitProspectiveMailbox classifies a canonical email only during the exact
// native magic-link original-request preparation invocation. It checks every
// occupant and live retirement under the kernel's tenant fence, not merely
// eligible verified recipients. False is a private no-delivery selection, never
// an existence disclosure. Missing retained keys and infrastructure errors deny.
// The native owner supplies its email-owned canonical projection; this method
// neither normalizes nor proves possession. It allocates no future IDs, stages
// no effect and creates no user, verification, factor state or reusable proof.
// Generate future IDs only after the coordinator acknowledges generation start.
// Preparation releases its locks before generation, so final request Apply must
// repeat SelectProspectiveRecipient and consumption must recheck creation.
// Zero, foreign, reconstructed-command and non-preparation invocations deny.
// Borrow Work serially, close all rows, and retain neither Work nor command.
func (d *MagicLinkRegistrationDomain) AdmitProspectiveMailbox(ctx context.Context, w Work, p FeaturePreparationContributor, command identity.Command, canonical string) (bool, error) {
	if w.usable() != nil || ctx == nil || d == nil || d.repository == nil || p == nil || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != command || w.state.featurePreparationPlan == nil || w.state.featureApplying {
		return false, invalidWork()
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil {
		return false, err
	}
	if !magicLinkRequestOperation(f.Operation) || f.Contributor != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || b.UserID != "" || b.AnonymousFlowID == "" || len(canonical) < 3 || len(canonical) > 254 || !utf8.ValidString(canonical) || strings.ContainsAny(canonical, "\x00\r\n") {
		return false, w.fail(ctx, invalidMagicLinkRegistration())
	}
	enlisted := false
	for _, entry := range w.state.featurePreparationPlan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == d.repository {
			enlisted = true
		}
	}
	if !enlisted {
		return false, w.fail(ctx, invalidWork())
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return false, err
	}
	// Replace's canonical classifier omits new-ID reservation. Empty user/ID
	// excludes no actual occupant; no mutation or replacement is performed.
	blocked, err := classifyIdentifierReuse(ctx, w, identity.IdentifierChange{Action: identity.IdentifierReplace, TenantID: b.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: canonical}, d.reuse, now, true)
	if err != nil {
		return false, err
	}
	return !blocked, nil
}

// RequireProspectiveRecipient fences an unused email and prospective IDs during
// the original native magic-link request Apply. It creates no user, verification
// or empty MFA state. The same kernel tenant/retirement policy used by creation
// owns collision admission; consumption must independently create and recheck.
// Its frozen intent binds staged signed issuance, not current authentication.
// Errors poison Work. Call only in the serial invocation with the enlisted
// repository and retain neither Work nor intent across a callback.
func (d *MagicLinkRegistrationDomain) RequireProspectiveRecipient(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent MagicLinkRegistrationIntent) error {
	_, err := d.selectProspectiveRecipient(ctx, w, p, command, intent, false)
	return err
}

// SelectProspectiveRecipient classifies prospective request availability under
// the enlisted kernel transaction's existing tenant and retirement fences.
// Canonical occupancy or live retirement returns false without poisoning Work,
// so the native request can commit its neutral acknowledgement without delivery.
// It never reveals the occupant or treats an unverified/blocked occupant as absent.
// Structural future-ID conflicts, invalid intent and unavailable authority remain
// errors that poison Work. A true result admits only this original request's
// prospective issuance: it creates no account or reusable availability proof.
// Preparation-time absence cannot replace this request Apply fence; consumption independently
// enforces creation eligibility. Call serially with the enlisted contributor;
// retain neither Work nor intent across callbacks.
func (d *MagicLinkRegistrationDomain) SelectProspectiveRecipient(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent MagicLinkRegistrationIntent) (bool, error) {
	return d.selectProspectiveRecipient(ctx, w, p, command, intent, true)
}

func (d *MagicLinkRegistrationDomain) selectProspectiveRecipient(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent MagicLinkRegistrationIntent, neutral bool) (bool, error) {
	if err := w.usable(); err != nil {
		return false, err
	}
	fail := func(err error) (bool, error) { return false, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil || p == nil {
		return fail(invalidMagicLinkRegistration())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return false, err
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
		return false, err
	}
	blocked, err := classifyIdentifierReuse(ctx, w, identity.IdentifierChange{Action: identity.IdentifierAttach, TenantID: b.TenantID, UserID: intent.Creation.Binding.UserID, ID: intent.Identifier.ID, Kind: identity.IdentifierEmail, CanonicalValue: intent.Identifier.CanonicalValue}, d.reuse, now, neutral)
	if err != nil {
		return false, err
	}
	if blocked && !neutral {
		return fail(identity.ConflictError{})
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(intent.Creation.Binding.UserID))
	if err != nil {
		return false, err
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
	if blocked {
		plan := w.state.execution.reservation.plan
		if plan.magicLinkRequestAcceptance {
			if w.state.magicLinkRecipient != nil || w.state.magicLinkRequestAccepted || plan.issuance != nil && plan.issuance.MagicLinkRecipientUserID != intent.Creation.Binding.UserID {
				return fail(invalidWork())
			}
			w.state.magicLinkRequestAccepted = true
		}
		return false, nil
	}
	// Own the creation attributes rather than retain caller-mutable slices.
	creation, err := identity.NewUserCreationCommand(intent.Creation)
	if err != nil {
		return fail(err)
	}
	intent.Creation, _ = creation.CreateUser()
	w.state.magicLinkRecipient = &magicLinkRecipientAdmission{owner: p, prospective: &intent}
	return true, nil
}

// Effect suppression is selected only by the protected kernel classifier, never
// a contributor result or an absent staged effect. The frozen declaration must
// independently admit the exact alternate branch. No receipt is created here.
func neutralEffectsDeclared(w Work) bool {
	if w.state == nil || w.state.execution == nil || w.state.execution.reservation == nil || w.state.execution.reservation.plan == nil {
		return false
	}
	s, p := w.state, w.state.execution.reservation.plan
	if s.registrationAccepted {
		return !s.magicLinkRequestAccepted && p.signupAcceptance && !p.magicLinkRequestAcceptance
	}
	return s.magicLinkRequestAccepted && !p.signupAcceptance && p.magicLinkRequestAcceptance && s.magicLinkRecipient == nil && p.feature != nil && magicLinkRequestOperation(p.feature.Operation) && p.feature.Contributor == (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1})
}
