package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// QueryFeaturePreparation reads existing encrypted native output by exact
// original CommandID without requiring a request-key mapping. The configured
// current QueryPolicy and exact registered preparation owner must admit it.
// Pending output may precede final-plan attachment; terminal output may outlive
// today's aggregate version. Neither case grants execution or bearer authority.
// The native owner must authenticate configuration, binding, original generation
// and signed scope, then submit caller input to ExecutePreparedFeature for its
// complete original password/proof fingerprint comparison. Recovery instead
// uses RecoverFeatureCommand and never reconstructs an executable input.
//
// Missing/retired/foreign history denies; incomplete, corrupt or absent output
// fails unavailable, never proving rollback or permission to regenerate. Reads
// neither reserve, take over, renew nor invoke participants/providers. Returned
// ciphertext is an independent caller-owned copy: clear after use and never
// log or serialize it. Failures return zero bytes/generation and redacted errors.
// The borrowed pool remains caller-owned. Immutable configuration permits
// concurrent calls; MaximumDuration and earlier caller deadlines bound all IO.
func (c *Coordinator) QueryFeaturePreparation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner FeaturePreparationContributor) ([]byte, uint64, error) {
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.commandRead == nil || c.queryPolicy == nil || !validCommandQueryPolicy(*c.queryPolicy) || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return nil, 0, invalidPreparation()
	}
	entry, err := c.registry.selectFeatureOperation(feature)
	if err != nil || !sameParticipant(entry.contributor, owner) {
		return nil, 0, invalidPreparation()
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil || !validQuerySubject(q) {
		return nil, 0, invalidPreparation()
	}
	for _, text := range []string{string(q.TenantID), string(q.ActorID), string(q.ActorKind), q.OperationID} {
		if !queryScopeText(text) {
			return nil, 0, invalidPreparation()
		}
	}
	if q.RecordID != "" && !queryScopeText(q.RecordID) {
		return nil, 0, invalidPreparation()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	allowed, policyErr := c.authorizeCommandQuery(ctx, q, caller)
	// Denied/missing valid inputs perform the same bounded primary observation;
	// no caller callback executes under an open SQL transaction.
	observed, readErr := c.commandRead(ctx, q.CommandID)
	if readErr != nil && !errors.Is(readErr, pgx.ErrNoRows) || ctx.Err() != nil {
		return nil, 0, readFailure(ctx, readErr)
	}
	if policyErr != nil {
		return nil, 0, identity.UnavailableError{}
	}
	if !allowed {
		return nil, 0, identity.ForbiddenError{}
	}
	binding, operation, err := commandObservationScope(q, observed, readErr)
	if err != nil {
		return nil, 0, err
	}
	if operation == nil || *operation != feature.Operation {
		return nil, 0, identity.ForbiddenError{}
	}
	return c.readFeaturePreparation(ctx, q, binding, feature, owner, observed)
}

// Both readers conserve the exact original journal output. Authorization and
// permissible historical/current scope differences are established separately.
func (c *Coordinator) readFeaturePreparation(ctx context.Context, q identity.RecoveryQuery, binding identity.CommandBinding, feature FeatureRegistration, owner FeaturePreparationContributor, observed commandObservation) ([]byte, uint64, error) {
	if observed.state == nil || observed.until == nil || !postgresExactTime(*observed.until) || !postgresExactTime(observed.now) || len(observed.fingerprint) != 32 || observed.fingerprintKeyVersion < 1 || observed.fingerprintKeyVersion > math.MaxUint32 {
		return nil, 0, identity.UnavailableError{}
	}
	if key, ok := c.keys.retained[uint32(observed.fingerprintKeyVersion)]; !ok || key == ([32]byte{}) {
		return nil, 0, identity.UnavailableError{}
	}
	var attached *CommandPlan
	if len(observed.plan) == 0 {
		if *observed.state != "pending" || observed.resultVersion != nil || observed.class != nil || observed.result != nil {
			return nil, 0, identity.UnavailableError{}
		}
	} else {
		receipt, _ := commandReceipt(q, observed, nil)
		plan, err := decodeFeaturePlan(binding, [32]byte(observed.fingerprint), observed.plan)
		if receipt.Validate() != nil || err != nil || plan.Feature == nil || *plan.Feature != feature {
			return nil, 0, identity.UnavailableError{}
		}
		attached = &plan
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	var output []byte
	defer func() { clear(output) }()
	var original, started, current string
	var profile int16
	err := c.pool.Raw().QueryRow(ctx, `SELECT
CASE WHEN octet_length(j.preparation_ciphertext) BETWEEN 1 AND 1048576 THEN j.preparation_ciphertext END,
coalesce(j.preparation_ciphertext_generation::text,''),coalesce(j.preparation_started_generation::text,''),j.generation::text,coalesce(j.preparation_profile,0)
FROM identity.identity_command_id_claims c JOIN identity.commands j ON j.command_id=c.command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose
WHERE c.command_id=$1 AND NOT c.retired AND c.safe_fields=$2 AND c.fingerprint=$3 AND c.fingerprint_key_version=$4
AND j.command_plan IS NOT DISTINCT FROM $5::bytea AND j.state=$6`, id, observed.scope, observed.fingerprint, observed.fingerprintKeyVersion, observed.plan, *observed.state).Scan(&output, &original, &started, &current, &profile)
	if err != nil {
		return nil, 0, readFailure(ctx, err)
	}
	generation, err := strconv.ParseUint(original, 10, 64)
	currentGeneration, currentErr := strconv.ParseUint(current, 10, 64)
	_, gated := owner.(FeatureAdmissionPreparationContributor)
	validProfile := !gated && (profile == 1 || profile == 3) || gated && (profile == 2 || profile == 4)
	if attached != nil {
		validProfile = validProfile && ((attached.CommandCounters == nil && profile <= 2) || (attached.CommandCounters != nil && profile >= 3))
	}
	if err != nil || generation == 0 || started != original || currentErr != nil || currentGeneration < generation || !validProfile || len(output) == 0 {
		return nil, 0, identity.UnavailableError{}
	}
	return bytes.Clone(output), generation, nil
}
