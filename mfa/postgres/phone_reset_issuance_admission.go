package mfapostgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// RequirePhoneResetIssuancePreparation locks the original confirmed encrypted
// TOTP factor for the exact registered phone-reset request preparation. Call
// after primary, original pre-auth and verified-recipient admission, before OTP
// send-family/lockout/challenge locks. It retains user→aggregate→factor locks
// only in the borrowed Work, without decryption, comparison or replay mutation.
// Original is the actual recovery pre-auth admitted by its native owner, not an
// application clearance. Its original absolute expiry is never extended. This
// is eligibility only; Apply must independently repeat all current fences.
func RequirePhoneResetIssuancePreparation(ctx context.Context, w kernel.Work, owner kernel.FeaturePreparationContributor, command identity.Command, snapshot TOTPFactorSnapshot, original session.PreAuthTransaction) error {
	return requirePhoneResetIssuance(ctx, w, owner, command, snapshot, original)
}

// RequirePhoneResetIssuance repeats the full original factor fence in the exact
// phone request's live Apply Work. It grants no factor proof, capability, risk
// allowance or permission to issue SMS by itself. Every error must abort the
// parent transaction. No SQL transaction, callback, crypto or retry is created.
func RequirePhoneResetIssuance(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, snapshot TOTPFactorSnapshot, original session.PreAuthTransaction) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	return requirePhoneResetIssuance(ctx, w, owner, command, snapshot, original)
}

func requirePhoneResetIssuance(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, snapshot TOTPFactorSnapshot, original session.PreAuthTransaction) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, ok := command.Feature()
	b, registration, life, err := w.FeatureScope(owner)
	if !ok || err != nil || b != spec.Binding || registration.Operation != spec.Operation ||
		registration.Contributor != (kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) ||
		life.EventType != "otp.sent.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 ||
		phoneResetIssuanceSpec(spec, snapshot, original) != nil {
		return invalidAuthority()
	}
	if _, ok := command.PreAuthCookie(); !ok {
		return invalidAuthority()
	}
	f, _ := original.Bindings()
	now, err := lockPhoneRecoveryTOTP(ctx, completionTOTPStore(w), snapshot, f.Binding.ExpiresAt)
	if err != nil {
		return err
	}
	if now.Before(f.Binding.IssuedAt) {
		return invalidAuthority()
	}
	// A snapshot or a completed SQL query cannot outlive the synchronous native
	// callback which authorized the borrowed Work.
	_, _, _, err = w.FeatureScope(owner)
	return err
}

func phoneResetIssuanceSpec(f identity.FeatureCommandSpec, snapshot TOTPFactorSnapshot, original session.PreAuthTransaction) error {
	m, err := snapshot.Metadata()
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s, flowErr := original.Bindings()
	b := f.Binding
	if err != nil || !phoneRecoverySnapshot(m) || flowErr != nil || f.Operation != op || b.ValidateFor(op) != nil ||
		b.UserID != m.UserID || b.TenantID != m.TenantID || b.RecordID != string(b.CommandID) ||
		s.Binding.Intent.Purpose != session.PreAuthPhonePasswordRecovery || s.Binding.Intent.Action != b.OperationID ||
		s.Binding.Intent.TenantID != b.TenantID || s.Binding.Intent.PolicyID != b.PolicyID || s.Binding.Intent.PolicyVersion != b.PolicyVersion ||
		s.Binding.Intent.IdentifierBinding == ([32]byte{}) || s.Binding.Intent.Remember != (session.RememberPolicy{}) {
		return invalidAuthority()
	}
	var id, enrollment, authority bool
	for _, field := range f.Fields {
		switch field.Name {
		case "phone.reset.factor-id":
			if id || field.Value.Kind != identity.FeatureText || field.Value.Text != m.FactorID {
				return invalidAuthority()
			}
			id = true
		case "phone.reset.factor-version":
			if enrollment || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != m.EnrollmentVersion {
				return invalidAuthority()
			}
			enrollment = true
		case "phone.reset.factor-authority-version":
			if authority || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != m.FactorAuthorityVersion {
				return invalidAuthority()
			}
			authority = true
		default:
			if strings.HasPrefix(field.Name, "phone.reset.factor-") {
				return invalidAuthority()
			}
		}
	}
	if !id || !enrollment || !authority {
		return invalidAuthority()
	}
	return nil
}
