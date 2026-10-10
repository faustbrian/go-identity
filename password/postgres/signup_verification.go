package passwordpostgres

import (
	"context"
	"net/url"
	"time"

	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type signupVerificationPreparation struct {
	address  email.AddressParser
	policy   *email.RegistrationVerificationPolicy
	issuer   *issuerpg.Issuer
	lifetime time.Duration
}

// Only the original generation invocation may call this after current risk and
// HIBP admission. The existing preparation journal owns whether generation runs;
// this helper neither claims that journal nor permits regeneration after Unknown.
// Original primary input time, flow expiry and callback are retained, not read
// from a retry or a renewed clock. Signing stays outside the protected SQL Work.
// The caller must encrypt proof custody for original output, then stage the same
// batch with account creation; no sender or response receives this preparation.
func (r *Repository) prepareSignupVerification(ctx context.Context, b identity.CommandBinding, selected kernel.PasswordRegistrationIntent, flow session.PreAuthTransaction, at time.Time, c signupVerificationPreparation) (spec email.RegistrationVerificationSpec, prepared issuerpg.PreparedIssuance, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			// Once signing succeeds, even a cancellation between return and this
			// defer must destroy the unpublished proof rather than abandon custody.
			if plan, e := prepared.Plan(); e == nil {
				for i := range plan.Grants {
					_ = prepared.TransferForDelivery(context.Background(), uint16(i), func(context.Context, []byte) error { return nil })
				}
			}
			spec, prepared = email.RegistrationVerificationSpec{}, issuerpg.PreparedIssuance{}
		}
	}()
	if ctx == nil || !r.configuredWriter() || c.policy == nil || c.issuer == nil || c.lifetime <= 0 || c.lifetime > 24*time.Hour || c.lifetime%time.Second != 0 || b.ValidateFor(passwordSignupOperation()) != nil {
		return spec, prepared, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return spec, prepared, err
	}
	original, err := flow.Bindings()
	if err != nil || original.Binding.ID != identity.PreAuthTransactionID(b.AnonymousFlowID) || original.Binding.Intent.TenantID != b.TenantID || original.Binding.Intent.Action != b.OperationID || original.Binding.Intent.PolicyID != b.PolicyID || original.Binding.Intent.PolicyVersion != b.PolicyVersion || at.IsZero() || at.Before(original.Binding.IssuedAt) || !at.Before(original.Binding.ExpiresAt) {
		return spec, prepared, password.ErrPasswordWork
	}
	expected := b
	expected.OperationID, expected.AnonymousFlowID = "identity.user.create", ""
	expected.UserID, expected.SchemaID, expected.SchemaVersion = selected.Creation.Binding.UserID, selected.Creation.Binding.SchemaID, selected.Creation.Binding.SchemaVersion
	if selected.Creation.Binding != expected {
		return spec, prepared, password.ErrPasswordWork
	}
	if _, err := kernel.PasswordRegistrationFields(selected); err != nil {
		return spec, prepared, password.ErrPasswordWork
	}
	address, err := c.address.Parse(email.AddressInput(selected.Identifier.CanonicalValue))
	callback := original.Binding.Intent.CallbackURL
	if err != nil || len(callback) > 2048 {
		return spec, prepared, password.ErrPasswordWork
	}
	redirect, err := url.Parse(callback)
	if err != nil {
		return spec, prepared, password.ErrPasswordWork
	}
	issued := at.UTC().Truncate(time.Second)
	until := issued.Add(c.lifetime)
	if expiry := original.Binding.ExpiresAt.UTC().Truncate(time.Second); expiry.Before(until) {
		until = expiry
	}
	spec = email.RegistrationVerificationSpec{Binding: b, IdentifierID: selected.Identifier.ID, IdentifierVersion: selected.Identifier.Version, VerificationVersion: 1, Payload: email.CapabilityPayload{TenantID: b.TenantID, SubjectID: identity.SubjectID(selected.Creation.Binding.UserID), CanonicalAddress: address.Canonical(), Purpose: "identity.identifier.verify", Redirect: *redirect, Version: 1}, IssuedAt: issued, ExpiresAt: until}
	payload, err := c.policy.Payload(spec)
	if err != nil {
		return spec, prepared, password.ErrPasswordWork
	}
	prepared, err = c.issuer.PrepareRegistration(ctx, b, selected.Creation.Binding.UserID, []capability.Payload{payload})
	if err != nil {
		return spec, prepared, readerFailure(ctx)
	}
	return spec, prepared, nil
}
