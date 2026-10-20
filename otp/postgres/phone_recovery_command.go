package postgres

import (
	"context"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MapPhonePasswordResetWithAuthority freezes the original server-issued SMS
// attempt and primary expectations inside one joint phone-reset input command.
// It preserves the borrowed password, canonical capability, SMS, independent
// TOTP and actual browser cookie; no factor is verified or consumed. Only the
// exact sessionless, user-targeted SMS password-recovery profile is accepted.
// Original must include its existing password credential and user authority.
// This method does not authenticate caller-supplied authority projections.
//
// The existing encrypted attempt codec owns the map-once representation. Raw
// codes, password, capability and cookie never enter its encrypted metadata.
// Keep the returned command unchanged through retries/ambiguity; remapping it
// denies. Generic Feature/OneTimeCode remain closed. No SQL, callback, provider,
// challenge comparison, factor proof, journal or workflow is introduced. Native
// compound verification, current authority and atomic effects remain required.
// Earlier deadlines win; failed mapping returns zero outputs and redacted errors.
func (c *AttemptCodec) MapPhonePasswordResetWithAuthority(ctx context.Context, attempt otp.AttemptCommand, digestKeyVersion uint32, input identity.Command, original AttemptAuthority) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func(err error) (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	if c == nil || c.crypto == nil || ctx == nil {
		return bad(ErrInvalidCommand)
	}
	bounded, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return bad(err)
	}
	spec, ok := input.PhonePasswordResetInputFeature()
	password, proof, sms, totp, custody := input.PhonePasswordResetInputCustody()
	cookie, present := input.PhonePasswordResetPreAuthCookie()
	if !ok || !custody || !present || original.Credential.Kind != identity.CredentialPassword || original.Credential.Owner != "identity/password" || string(original.Credential.ID) != spec.Binding.RecordID {
		return bad(ErrInvalidCommand)
	}
	b, err := attempt.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	issuer, retained := c.issuers[b.FingerprintKeyVersion]
	if !retained {
		return bad(ErrInvalidCommand)
	}
	record, err := issuer.SealForCommand(attempt)
	if err != nil || record.Binding != spec.Binding || record.Operation != spec.Operation || !phoneRecoveryAttemptRecord(record) {
		return bad(ErrInvalidCommand)
	}
	// Authenticate the actual joint SMS against the existing server attempt;
	// borrowing its plan or another attempt's code must not replace that input.
	if _, err := issuer.RestoreForCommand(record, sms); err != nil {
		return bad(ErrInvalidCommand)
	}
	mapped, plan, err := c.mapAttempt(bounded, attempt, digestKeyVersion, spec, &original)
	if err != nil {
		return bad(err)
	}
	metadata, _ := mapped.Feature()
	joint, err := identity.NewFeaturePhonePasswordResetInputCommand(metadata, password, proof, sms, totp)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	joint, err = identity.BindPhonePasswordResetPreAuth(joint, cookie)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if err := bounded.Err(); err != nil {
		return bad(err)
	}
	return joint, plan, nil
}

func phoneRecoveryAttemptRecord(record otp.CommandAttemptRecord) bool {
	b, err := record.Attempt.Continuation.Bindings()
	if err != nil || record.Operation != (identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) || record.Attempt.Mode != otp.AttemptModeConsume || record.Binding.UserID == "" || b.Scope.SubjectID != string(record.Binding.UserID) || b.Scope.Purpose != otp.PurposePasswordReset || b.Scope.Channel != otp.ChannelSMS || b.RememberPolicy != (session.RememberPolicy{}) {
		return false
	}
	original, bound := b.Authorization.PreAuthTransaction()
	flow, err := original.Bindings()
	return bound && err == nil && flow.Binding.Intent.Purpose == session.PreAuthPhonePasswordRecovery && flow.Binding.Intent.IdentifierBinding != ([32]byte{}) && flow.Binding.Intent.TenantID == record.Binding.TenantID
}

// This private borrow does not project the command into legacy one-code custody.
// Only the exact root-owned compound variants are reachable; Contributor.original
// remains independently closed until its compound-verification profile is selected.
func phoneRecoveryAttemptCustody(command identity.Command) (identity.FeatureCommandSpec, auth.OneTimeCode, auth.BearerCredential, bool) {
	spec, ok := command.PhonePasswordResetInputFeature()
	_, _, sms, _, custody := command.PhonePasswordResetInputCustody()
	if !ok {
		spec, ok = command.PhonePasswordResetFeature()
		_, _, sms, _, custody = command.PhonePasswordResetCustody()
	}
	cookie, present := command.PhonePasswordResetPreAuthCookie()
	return spec, sms, cookie, ok && custody && present
}
