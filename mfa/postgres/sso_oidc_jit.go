package mfapostgres

import (
	"context"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// InitializeSSOOIDCJIT establishes known-empty factor authority only for the
// active initial user actually created by this original enterprise callback's
// protected Work. The kernel retains that creation evidence; a caller-supplied
// user or missing factor row cannot establish it. The native SSO owner must
// separately fence its provider, assertion, organization and enrollment policy.
//
// Call after native identity creation, before issuing the session against factor
// generation 1. This inserts into the same MFA authority used by enrollment and
// later session checks; it neither upserts nor resets existing state. Propagate
// every error so identity, membership, factor and session effects abort together
// under the sole coordinator. No transaction, retry or authentication is created.
// All SSOOIDCJITFactorMigrationSource steps must be installed first. SSO uses
// its distinct provenance column so unchanged optional signup migrations retain
// their original purpose CHECKs and remain installable after populated JIT.
func InitializeSSOOIDCJIT(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	user, err := w.SSOOIDCJITUser(ctx, owner, command)
	if err != nil {
		return err
	}
	binding, err := w.Scope()
	if err != nil {
		return err
	}
	if binding.OperationID != "identity.sso.oidc-callback" || user.Validate(binding.TenantID) != nil || user.Status != identity.StatusActive || user.Version != 1 {
		return invalidAuthority()
	}
	commandID, err := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
	if err != nil || len(commandID) != 16 {
		return invalidAuthority()
	}
	defer clear(commandID)

	inserted, err := w.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,sso_oidc_initialized_purpose) VALUES($1,$2,1,0,$3,$4)`, string(user.TenantID), string(user.ID), commandID, binding.OperationID)
	if err != nil {
		return identity.UnavailableError{}
	}
	if inserted != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
