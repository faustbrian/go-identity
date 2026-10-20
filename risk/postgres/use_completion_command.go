package postgres

import (
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PreparePhoneResetCompletionEvidenceUse adds authenticated completion-only
// risk scope to an exact sealed input or generated phone-reset command. The
// original password or verifier, canonical capability, SMS, independent TOTP and
// bound browser cookie retain their original owners; no partial Feature or
// OneTimeCode command is produced. UseIssuer must match current configuration.
// The precheck must consume an independently issued PhoneResetCompletion row.
// Raw scope stays only in encrypted command custody, never the returned plan.
// This bounded pure preparation performs no IO, callbacks or time observation
// and grants no current allowance, proof authentication or mutation authority.
// Failure returns zero outputs and a redacted error. Inputs must not be mutated
// concurrently; destroy/discard borrowed secret owners after bounded use.
func (r *Repository) PreparePhoneResetCompletionEvidenceUse(command identity.Command, original risk.PhoneEvidenceRequest, use risk.EvidenceUse) (identity.Command, identitypostgres.RiskEvidencePlan, error) {
	fail := func() (identity.Command, identitypostgres.RiskEvidencePlan, error) {
		return identity.Command{}, identitypostgres.RiskEvidencePlan{}, risk.ErrInvalidEvidenceExecution
	}
	spec, ok := nativeUseSpec(command)
	if !ok || spec.Operation != nativeCompletionUseOperation() {
		return fail()
	}
	spec, plan, err := r.prepareUseScope(spec, original, use)
	if err != nil {
		return fail()
	}
	var mapped identity.Command
	if password, proof, sms, totp, input := command.PhonePasswordResetInputCustody(); input {
		mapped, err = identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	} else if hash, proof, sms, totp, generated := command.PhonePasswordResetCustody(); generated {
		mapped, err = identity.NewFeaturePhonePasswordResetCommand(spec, hash, proof, sms, totp)
	} else {
		return fail()
	}
	if err != nil {
		return fail()
	}
	cookie, _ := command.PhonePasswordResetPreAuthCookie()
	mapped, err = identity.BindPhonePasswordResetPreAuth(mapped, cookie)
	if err != nil || r.ValidateRiskEvidenceCommand(mapped, plan) != nil {
		return fail()
	}
	return mapped, plan, nil
}

func nativeCompletionUseOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
