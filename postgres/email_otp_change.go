package postgres

import (
	"context"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequireOTPEmailChangeTarget locks and checks the exact original pending
// candidate and verified predecessor before any OTP comparison or debit.
// Only the registered change-specific input-admission owner may call it during
// the existing coordinator Work. It writes nothing, grants no reservation and
// cannot authorize verification-only mutation. Explicit initial-primary intents
// additionally require no primary and exactly one verified predecessor under the
// same partition lock. Lock lifetime and cancellation match
// RequireOTPEmailVerificationTarget.
func (w Work) RequireOTPEmailChangeTarget(ctx context.Context, owner ManagedEmailVerificationContributor, command identity.Command) error {
	return w.requireOTPEmailTarget(ctx, owner, command, otpEmailChangeOperation())
}

func otpEmailChangeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-change-confirm", SchemaID: "identity.otp.email-change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func otpEmailMutationOperation(op identity.FeatureOperation) bool {
	return op == otpEmailVerificationOperation() || op == otpEmailChangeOperation()
}

// OTPEmailChangeFields binds primary replacement to its original committed
// change request and a distinct independently issued OTP send. The native owner
// authenticates that original custody; caller metadata is not authority. Only
// genuine-primary replacement is selected, never generic pending verification
// or initial-primary establishment. Include fields before fingerprinting and
// consuming reservation. No IO, normalization or credential work occurs here.
func OTPEmailChangeFields(i ManagedEmailVerificationIntent, send identity.CommandID) ([]identity.FeatureField, error) {
	if !i.Previous.Primary {
		return nil, invalidEmailVerification()
	}
	return otpEmailChangeFields(i, send)
}

// OTPEmailInitialPrimaryFields explicitly selects first-primary establishment
// from an original sole-verified/no-primary change policy. Existing replacement
// fields remain primary-only. This encodes intent, not authority: the registered
// owner and locked complete partition must prove the original predecessor,
// zero primaries and exactly one verified old email before comparison or debit.
// Fingerprinting, protected notice and consuming protocol match replacement.
func OTPEmailInitialPrimaryFields(i ManagedEmailVerificationIntent, send identity.CommandID) ([]identity.FeatureField, error) {
	if i.Previous.Primary || !i.Previous.AllowInitialPrimary {
		return nil, invalidEmailVerification()
	}
	return otpEmailChangeFields(i, send)
}

func otpEmailChangeFields(i ManagedEmailVerificationIntent, send identity.CommandID) ([]identity.FeatureField, error) {
	if i.Change.Action != identity.IdentifierVerifyPrimary || i.RequestCommandID == send {
		return nil, invalidEmailVerification()
	}
	if _, err := identity.ParseCommandID(string(send)); err != nil {
		return nil, invalidEmailVerification()
	}
	fields, err := ManagedEmailVerificationFields(i)
	if err != nil {
		return nil, err
	}
	return append(fields,
		identity.FeatureField{Name: "email-otp.recovery-path", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "email_change_otp"}},
		identity.FeatureField{Name: "email-otp.send-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(send)}},
	), nil
}

func validateOTPEmailChangeScope(s identity.FeatureCommandSpec, plan CommandPlan) error {
	b := s.Binding
	if s.Operation != otpEmailChangeOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != otpDescriptor() || plan.Capability != nil || plan.OTP == nil || plan.OTP.Mode != OTPConsume || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || plan.CapabilityIssuance != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.primary-changed.v1" || !validDeliveryPlan(plan.Delivery) || len(plan.Delivery.Intents) != 1 || plan.Delivery.Intents[0].Purpose != "identity.email.change-notification" || plan.Delivery.Intents[0].SubjectID != string(b.UserID) {
		return invalidEmailVerification()
	}
	if len(plan.Contributors) < 2 || plan.Contributors[len(plan.Contributors)-1] != plan.Delivery.Contributor {
		return invalidEmailVerification()
	}
	var path, send string
	count := 0
	for _, field := range s.Fields {
		if field.Name != "email-otp.recovery-path" && field.Name != "email-otp.send-command" {
			if strings.HasPrefix(field.Name, "email-otp.") {
				return invalidEmailVerification()
			}
			continue
		}
		if field.Value.Kind != identity.FeatureText {
			return invalidEmailVerification()
		}
		if field.Name == "email-otp.recovery-path" {
			path = field.Value.Text
		} else {
			send = field.Value.Text
		}
		count++
	}
	if count != 2 || path != "email_change_otp" || send != plan.OTP.ChallengeID || send == string(b.CommandID) {
		return invalidEmailVerification()
	}
	if _, err := identity.ParseCommandID(send); err != nil {
		return invalidEmailVerification()
	}
	return nil
}
