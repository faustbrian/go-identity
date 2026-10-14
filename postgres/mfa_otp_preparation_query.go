package postgres

import (
	"context"
	"encoding/base64"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// QueryMFAOTPPreparation restores code-free native mapped metadata from the
// existing immutable declaration, including a checkpoint before session
// generation. Current query/admission policy and the original opaque
// code/browser fingerprint must match. Native OTP and counter owners validate
// the reconstructed command; this read grants no comparison or execution.
// Original intent must contain the immutable trusted transport.network field;
// raw network/base intent is never persisted in the preparation declaration.
// Authorized absence returns false; present incomplete/corrupt/retired evidence
// fails closed and cannot justify remapping or renewed freshness. Fields are
// independent trusted-adapter custody, never HTTP/diagnostic response data.
// Pool remains borrowed; cancellation and MaximumDuration bound all reads.
func (c *Coordinator) QueryMFAOTPPreparation(ctx context.Context, original identity.Command, caller authorization.DecisionContext) (identity.FeatureCommandSpec, CommandPlan, bool, error) {
	var metadata identity.FeatureCommandSpec
	var declaration CommandPlan
	_, found, err := c.withMFACommandObservation(ctx, original, caller, "identity.mfa.otp-verify", func(ctx context.Context, base identity.FeatureCommandSpec, fp [32]byte, observed commandObservation) (identity.CommandResult, error) {
		if c.pool == nil || c.pool.Raw() == nil || c.registry == nil || observed.state == nil {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(base.Binding.CommandID))
		var wire []byte
		err := c.pool.Raw().QueryRow(ctx, `SELECT CASE WHEN octet_length(j.preparation_declaration) BETWEEN 1 AND 65536 THEN j.preparation_declaration END
FROM identity.identity_command_id_claims c JOIN identity.commands j USING(command_id)
WHERE c.command_id=$1 AND c.tenant_id=$2 AND c.purpose=$3 AND NOT c.retired
AND c.safe_fields=$4 AND c.fingerprint=$5 AND c.fingerprint_key_version=$6
AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose AND j.preparation_profile IN (3,4)
AND j.state=$7`, id, string(base.Binding.TenantID), base.Binding.OperationID, observed.scope, observed.fingerprint, observed.fingerprintKeyVersion, *observed.state).Scan(&wire)
		if err != nil {
			return identity.CommandResult{}, readFailure(ctx, err)
		}
		defer clear(wire)
		mapped, plan, err := decodeMFAOTPPreparation(base.Binding, fp, wire)
		if err != nil || mapped.Operation != base.Operation {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		mapped, err = restoreMFAOTPPreparationSpec(base, mapped, plan)
		if err != nil {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		code, codeOK := original.OneTimeCode()
		cookie, cookieOK := original.PreAuthCookie()
		if !codeOK || !cookieOK {
			return identity.CommandResult{}, invalidPreparation()
		}
		command, err := identity.NewFeatureOneTimeCodePreAuthCommand(mapped, code, cookie)
		if err != nil {
			return identity.CommandResult{}, invalidPreparation()
		}
		admitted, err := c.registry.admitFeaturePlan(base.Binding, fp, plan)
		if err != nil {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		if _, _, err := c.originalMFAClaim(original, command, admitted); err != nil {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		metadata, declaration = mapped, plan
		return identity.CommandResult{}, nil
	})
	if err != nil {
		return identity.FeatureCommandSpec{}, CommandPlan{}, found, err
	}
	return metadata, declaration, found, nil
}
