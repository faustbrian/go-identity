package passwordpostgres

import (
	"context"
	"reflect"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
)

type signupGenerationPreparation struct {
	screening    password.HashPreparationConfig
	verification signupVerificationPreparation
	delivery     signupDeliveryPreparation
	codec        *issuerpg.IssuancePreparationCodec
	crypto       *envelope.Service
	envelopeKey  string
	profile      [32]byte
}

// Only the native journal's acknowledged original generation calls this.
// Screening/hash precede grant generation; the real issuer transfers its sole
// borrowed bearer directly into delivery encryption and its original encrypted
// checkpoint. No sender, transaction or second issuance workflow runs here.
// Unknown generation must be recovered from these bytes, never called again.
func (r *Repository) generateSignupOutput(ctx context.Context, original identity.Command, selected kernel.PasswordRegistrationIntent, flow session.PreAuthTransaction, at time.Time, admission risk.AuthenticationAdmission, generation uint64, c signupGenerationPreparation) (wire []byte, err error) {
	var issuance issuerpg.PreparedIssuance
	var issuanceWire, deliveryWire []byte
	defer func() {
		clear(issuanceWire)
		clear(deliveryWire)
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			clear(wire)
			wire = nil
			// Failure before transfer must destroy the unpublished proof as well.
			if plan, e := issuance.Plan(); e == nil {
				for n := range plan.Grants {
					_ = issuance.TransferForDelivery(context.Background(), uint16(n), func(context.Context, []byte) error { return nil })
				}
			}
		}
	}()
	spec, ok := original.PasswordSignupInputFeature()
	candidate, cookie, custody := original.PasswordSignupInputCustody()
	if ctx == nil || !r.configuredWriter() || !ok || !custody || spec.Operation != passwordSignupOperation() || generation == 0 || c.profile == ([32]byte{}) || c.crypto == nil || c.codec == nil || c.verification.issuer == nil || c.verification.policy == nil || c.delivery.policy != c.verification.policy || c.delivery.owner == nil || !reauthenticationText(c.envelopeKey, 256) {
		return nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fields, err := kernel.PasswordRegistrationFields(selected)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	// The root owner freezes and orders fields before fingerprinting; compare
	// those owned canonical projections, not the intent builder's input order.
	expected, err := identity.NewFeaturePasswordSignupInputCommand(identity.FeatureCommandSpec{Binding: spec.Binding, Operation: spec.Operation, Fields: fields}, candidate, cookie)
	expectedSpec, valid := expected.PasswordSignupInputFeature()
	if err != nil || !valid || !reflect.DeepEqual(expectedSpec, spec) {
		return nil, password.ErrPasswordWork
	}
	scope := admission.Prepared().Scope
	if scope.Tenant != string(spec.Binding.TenantID) || scope.Operation != risk.Action(spec.Binding.OperationID) || scope.Attempt != string(spec.Binding.CommandID) {
		return nil, password.ErrPasswordWork
	}
	hash, facts, err := r.prepareSignupHash(ctx, c.screening, admission, scope, candidate)
	if err != nil {
		return nil, err
	}
	verification, issuance, err := r.prepareSignupVerification(ctx, spec.Binding, selected, flow, at, c.verification)
	if err != nil {
		return nil, err
	}
	plan, err := issuance.Plan()
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	issuanceWire, err = c.codec.CheckpointPreparation(ctx, issuance, generation, func(ctx context.Context, index uint16, token []byte) error {
		if index != 0 || len(deliveryWire) != 0 {
			return password.ErrPasswordWork
		}
		var message deliverypg.PreparedDelivery
		message, err := r.prepareSignupDelivery(ctx, verification, token, c.screening.Now(), c.delivery)
		if err != nil {
			return err
		}
		deliveryWire, err = c.delivery.owner.CheckpointPreparation(ctx, message, generation)
		return err
	})
	if err != nil || len(deliveryWire) == 0 || admission.Check(ctx) != nil {
		return nil, password.ErrPasswordWork
	}
	if err := checkSignupScreening(ctx, c.screening.Policy, scope, facts, c.screening.Now()); err != nil {
		return nil, err
	}
	return r.sealSignupOutput(ctx, c.crypto, c.envelopeKey, original, generation, c.profile, c.verification.issuer, signupGeneratedOutput{Schema: 1, Hash: hash.String(), Admission: signupStoredAdmission(admission.Prepared()), Facts: facts, Issuance: plan, IssuanceWire: issuanceWire, DeliveryWire: deliveryWire})
}
