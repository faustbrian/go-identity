package postgres

import (
	"context"
	"encoding/base64"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// OAuthProxyOriginRetirementGrant returns the exact non-bearer locator in this
// retirement's original committed Start or Bind plan. It reads only the local
// coordinator's retained history from Work, regardless of proof expiry or
// ciphertext erasure. Missing, pruned or mismatched history returns no grant.
// The native owner must still authenticate the relevant retirement source and
// local proxy custody. This lookup cannot revive or settle any callback.
func (w Work) OAuthProxyOriginRetirementGrant(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (CapabilityPlan, error) {
	scope, err := w.OAuthProxyOriginRetirementScope(ctx, owner, command)
	if err != nil {
		return CapabilityPlan{}, err
	}
	op, ok := oauthProxyRetirementIssuanceOperation(scope.GrantPurpose)
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(scope.OriginCommandID))
	if err != nil || !ok {
		return CapabilityPlan{}, w.fail(ctx, invalidPlan())
	}
	rows, err := w.Query(ctx, oauthProxyRetirementGrantSQL, id, string(scope.TenantID), op.OperationID)
	if err != nil {
		return CapabilityPlan{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return CapabilityPlan{}, err
		}
		return CapabilityPlan{}, w.fail(ctx, identity.ForbiddenError{})
	}
	var safe, fingerprint, plan []byte
	defer func() { clear(safe); clear(fingerprint); clear(plan) }()
	if err := rows.Scan(&safe, &fingerprint, &plan); err != nil {
		return CapabilityPlan{}, err
	}
	if rows.Next() {
		return CapabilityPlan{}, w.fail(ctx, identity.UnavailableError{})
	}
	if err := rows.Err(); err != nil {
		return CapabilityPlan{}, err
	}
	grant, err := decodeOAuthProxyRetirementGrant(scope, safe, fingerprint, plan)
	if err != nil {
		return CapabilityPlan{}, w.fail(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityPlan{}, w.fail(ctx, err)
	}
	return grant, nil
}

// Both the claim and the journal have an exact command key. Read the final
// plan, never the earlier preparation declaration or retained ciphertext.
const oauthProxyRetirementGrantSQL = `SELECT c.safe_fields,c.fingerprint,j.command_plan
 FROM identity.identity_command_id_claims c JOIN identity.commands j
 ON j.command_id=c.command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose
 WHERE c.command_id=$1 AND c.tenant_id=$2 AND c.purpose=$3 AND NOT c.retired
 AND j.state='committed' AND j.terminal_class='committed' AND j.command_plan IS NOT NULL`

func oauthProxyRetirementIssuanceOperation(purpose string) (identity.FeatureOperation, bool) {
	switch purpose {
	case oauthProxyForwardPurpose:
		return OAuthProxyStartOperation(), true
	case "identity.oauth.callback":
		return oauthRPInitiationOperation(true), true
	default:
		return identity.FeatureOperation{}, false
	}
}

func decodeOAuthProxyRetirementGrant(scope OAuthProxyOriginRetirementScope, safeFields, fingerprint, wire []byte) (CapabilityPlan, error) {
	want, selected := oauthProxyRetirementIssuanceOperation(scope.GrantPurpose)
	flow, flowErr := identity.ParsePreAuthTransactionID(string(scope.FlowID))
	if len(fingerprint) != 32 || [32]byte(fingerprint) == ([32]byte{}) || !selected || flowErr != nil {
		return CapabilityPlan{}, identity.ForbiddenError{}
	}
	b, operation, err := decodeObservedScope(safeFields)
	if err != nil || operation == nil || *operation != want || b.TenantID != scope.TenantID || b.CommandID != scope.OriginCommandID ||
		b.ActorKind != authorization.SubjectServiceAccount || b.UserID != "" || b.AnonymousFlowID != string(flow) ||
		b.RecordID != string(flow) || b.CorrelationID != string(b.CommandID) || string(flow) == string(b.CommandID) {
		return CapabilityPlan{}, identity.ForbiddenError{}
	}
	plan, err := decodeFeaturePlan(b, [32]byte(fingerprint), wire)
	if err != nil || plan.Feature == nil || plan.Feature.Operation != want || plan.CapabilityIssuance == nil || len(plan.CapabilityIssuance.Grants) != 1 {
		return CapabilityPlan{}, identity.ForbiddenError{}
	}
	if scope.GrantPurpose == oauthProxyForwardPurpose && !validOAuthProxyStartPlan(b, plan) ||
		scope.GrantPurpose == "identity.oauth.callback" && !validOAuthRPInitiation(b, plan) {
		return CapabilityPlan{}, identity.ForbiddenError{}
	}
	grant := plan.CapabilityIssuance.Grants[0]
	if string(grant.Purpose) != scope.GrantPurpose {
		return CapabilityPlan{}, identity.ForbiddenError{}
	}
	return grant, nil
}
