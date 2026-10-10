package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"math"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// QueryRequestPreparation reads only original encrypted input from an enrolled
// immutable request-key mapping. It does not need a password, initiating key,
// generated output or committed command. The exact registered input owner and
// current CommandQueryPolicy must admit the request. Namespace/key/feature and
// original actor/tenant/POST route provenance must match; retained fingerprint
// keys remain required. An existing claim must match full query scope and its
// journal. Retired, foreign or corrupt claims fail closed. Pending preparation
// may precede the final command plan; reading input does not approve that plan.
//
// A mapping may precede its journal. In that case actor/tenant/route identify the
// mapping, but subject/flow/record cannot be checked until its native ciphertext
// is authenticated. The owner MUST authenticate every returned binding field,
// compare the decrypted original scope with q, and check original possession
// and current disclosure authority before returning any result to its caller.
// Encrypted input is not a receipt, proof of rollback or execution permission.
// QueryCommand and RecoverFeatureCommand remain the sole outcome/reconciliation
// owners; a missing journal never establishes NotCommitted.
//
// No input preparation, generation, participant, takeover or mutation runs.
// Input bytes are caller-owned; clear them after use and never log/serialize
// them. Earlier deadlines win over MaximumDuration. Errors return zero custody
// and stay redacted. The pool remains borrowed; immutable configuration permits
// concurrent calls. QueryPreparedFeature retains its committed-output contract.
func (c *Coordinator) QueryRequestPreparation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyPreparationContributor) (RequestKeyPreparationBinding, []byte, error) {
	zero := RequestKeyPreparationBinding{}
	scope := RequestKeyScope{TenantID: q.TenantID, ActorID: q.ActorID, ActorKind: q.ActorKind, Method: "POST", RouteID: q.OperationID}
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.commandRead == nil || c.requestKeys == nil || !validRequestKeyConfig(*c.requestKeys) || c.queryPolicy == nil || !validCommandQueryPolicy(*c.queryPolicy) || c.maximumDuration <= 0 || c.maximumDuration > time.Minute || !validRequestKeyScope(scope) || c.validateRequestPreparation(scope, feature, owner) != nil {
		return zero, nil, invalidPreparation()
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil || !validQuerySubject(q) || q.RecordID != "" && !queryScopeText(q.RecordID) {
		return zero, nil, invalidPreparation()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	if err := ctx.Err(); err != nil {
		return zero, nil, readFailure(ctx, err)
	}
	allowed, policyErr := c.authorizeCommandQuery(ctx, q, caller)
	// Denied and missing requests take the same primary observation shape. No
	// policy callback runs in a transaction or after input has been disclosed.
	observed, observeErr := c.commandRead(ctx, q.CommandID)
	missing := errors.Is(observeErr, pgx.ErrNoRows)
	binding, input, err := c.readRequestPreparation(ctx, q, feature, observed, missing)
	if ctx.Err() != nil || observeErr != nil && !missing {
		clear(input)
		return zero, nil, readFailure(ctx, observeErr)
	}
	if policyErr != nil || !allowed {
		clear(input)
		if policyErr != nil {
			return zero, nil, identity.UnavailableError{}
		}
		return zero, nil, identity.ForbiddenError{}
	}
	return binding, input, err
}

// Both original-actor recovery and confirmation use this single immutable
// custody reader after their distinct policy checks. It grants no disclosure,
// receipt or generation authority by itself.
func (c *Coordinator) readRequestPreparation(ctx context.Context, q identity.RecoveryQuery, feature FeatureRegistration, observed commandObservation, missing bool) (RequestKeyPreparationBinding, []byte, error) {
	zero := RequestKeyPreparationBinding{}
	scope := RequestKeyScope{TenantID: q.TenantID, ActorID: q.ActorID, ActorKind: q.ActorKind, Method: "POST", RouteID: q.OperationID}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	var safe, digest, identityDigest, namespace, input []byte
	var keyVersion int64
	var profile int16
	var method string
	err := c.pool.Raw().QueryRow(ctx, `SELECT r.safe_fields,r.fingerprint,r.fingerprint_key_version,r.request_preparation_identity,n.key_identity,r.method,
CASE WHEN octet_length(r.request_preparation_ciphertext) BETWEEN 1 AND 1048576 THEN r.request_preparation_ciphertext END,coalesce(j.preparation_profile,0)
FROM identity.request_key_mappings r JOIN identity.request_key_namespaces n USING(namespace)
LEFT JOIN identity.identity_command_id_claims c ON c.command_id=r.command_id
LEFT JOIN identity.commands j ON j.command_id=c.command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose
WHERE r.command_id=$1 AND r.namespace=$2 AND r.tenant_id=$3 AND r.actor_id=$4 AND r.actor_kind=$5 AND r.route_id=$6
AND (($7::boolean AND c.command_id IS NULL) OR (NOT $7 AND c.command_id IS NOT NULL AND NOT c.retired AND c.safe_fields=$8 AND c.fingerprint=$9))`, id, c.requestKeys.Namespace, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.RouteID, missing, observed.scope, observed.fingerprint).Scan(&safe, &digest, &keyVersion, &identityDigest, &namespace, &method, &input, &profile)
	defer clear(input)
	if err != nil {
		return zero, nil, readFailure(ctx, err)
	}
	if !missing {
		if err := requestPreparationClaimScope(q, feature, observed, profile); err != nil {
			return zero, nil, err
		}
	}
	expectedIdentity := requestPreparationIdentity(feature)
	expectedNamespace := requestNamespaceIdentity(c.requestKeys.Namespace, c.requestKeys.lookupKey())
	if method != scope.Method || keyVersion < 1 || keyVersion > math.MaxUint32 || len(digest) != 32 || len(input) == 0 || !hmac.Equal(identityDigest, expectedIdentity[:]) || !hmac.Equal(namespace, expectedNamespace[:]) {
		return zero, nil, identity.UnavailableError{}
	}
	if key, ok := c.keys.retained[uint32(keyVersion)]; !ok || key == ([32]byte{}) {
		return zero, nil, identity.UnavailableError{}
	}
	policy, err := preparationRequestPolicy(scope, safe)
	if err != nil {
		return zero, nil, err
	}
	binding := RequestKeyPreparationBinding{Namespace: c.requestKeys.Namespace, Scope: scope, Admission: RequestKeyAdmission{CommandID: q.CommandID, FingerprintKeyVersion: uint32(keyVersion)}, Feature: feature, PolicyVersion: policy, IntentDigest: [32]byte(digest)}
	return binding, bytes.Clone(input), nil
}

func requestPreparationClaimScope(q identity.RecoveryQuery, feature FeatureRegistration, observed commandObservation, profile int16) error {
	b, op, err := decodeObservedScope(observed.scope)
	if err != nil || op == nil || len(observed.fingerprint) != 32 {
		return identity.UnavailableError{}
	}
	if observed.retired || observed.tenant != string(q.TenantID) || observed.purpose != q.OperationID || *op != feature.Operation || b.CommandID != q.CommandID || b.TenantID != q.TenantID || b.UserID != q.UserID || b.AnonymousFlowID != q.AnonymousFlowID || b.ActorID != q.ActorID || b.ActorKind != q.ActorKind || b.OperationID != q.OperationID || b.RecordID != q.RecordID || b.LinkMode != q.LinkMode {
		return identity.ForbiddenError{}
	}
	if len(observed.plan) == 0 {
		// The original generation is acknowledged before final output/plan.
		// This arm reads custody only; it cannot become an outcome observation.
		if profile < 1 || profile > 4 || observed.state == nil || *observed.state != "pending" || observed.until == nil || !postgresExactTime(*observed.until) || !postgresExactTime(observed.now) || observed.resultVersion != nil || observed.class != nil || observed.result != nil {
			return identity.UnavailableError{}
		}
		return nil
	}
	receipt, receiptErr := commandReceipt(q, observed, nil)
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return receiptErr
	}
	plan, err := decodeFeaturePlan(b, [32]byte(observed.fingerprint), observed.plan)
	if err != nil || plan.Feature == nil || *plan.Feature != feature {
		return identity.ForbiddenError{}
	}
	return nil
}
