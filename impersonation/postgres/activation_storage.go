package impersonationpostgres

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// The online authority is distinct from v1 immutable approved intent. No raw
// bearer, synchronizer or sensitive reason is copied into this projection.
type activationRecord struct {
	tenant                                                                 identity.TenantID
	grantID                                                                impersonation.GrantID
	commandID, approvalID                                                  identity.CommandID
	actor, target, approver                                                identity.UserID
	requestDigest                                                          [32]byte
	scope                                                                  impersonation.Scope
	policy                                                                 impersonation.Policy
	actorVersion, targetVersion, approverVersion, approverAuthorityVersion uint64
	authorityNamespace                                                     string
	parentID                                                               string
	parentVersion                                                          uint64
	parentDigest, derivedDigest                                            session.TokenDigest
	startedAt, expiresAt                                                   time.Time
	version                                                                uint64
	status                                                                 impersonation.Status
}

const activationInsertSQL = `INSERT INTO identity_impersonation.active_grants
 (tenant_id,grant_id,activation_command_id,approval_command_id,actor_id,target_id,approver_id,
 request_digest,scope,policy_id,policy_version,actor_version,target_version,approver_version,
 approver_authority_version,authority_namespace,parent_id,parent_version,parent_digest_key,
 parent_digest,derived_digest_key,derived_digest,started_at,expires_at,state,version)
 SELECT g.tenant_id,g.grant_id,$3,$4,g.requester_id,g.target_id,a.approver_id,
 g.request_digest,convert_from($9,'UTF8')::jsonb,$10,$11::text::numeric,$12::text::numeric,
 $13::text::numeric,$14::text::numeric,$15::text::numeric,$16,$17,$18::text::numeric,
 $19::text::bigint,$20,$21::text::bigint,$22,$23,$24,'active',3
 FROM identity_impersonation.grants g
 JOIN identity_impersonation.approvals a ON a.tenant_id=g.tenant_id AND a.grant_id=g.grant_id
 WHERE g.tenant_id=$1 AND g.grant_id=$2 AND g.state='approved' AND g.version=2
 AND g.requester_id=$5 AND g.target_id=$6 AND g.request_digest=$8
 AND a.command_id=$4 AND a.requester_id=g.requester_id AND a.target_id=g.target_id
 AND a.request_digest=g.request_digest AND a.approver_id=$7
 AND a.approver_id<>g.requester_id AND a.approver_id<>g.target_id
 AND g.requested_at<=a.decided_at AND a.decided_at<=$23 AND g.expires_at>$23
 AND $3<>g.grant_id AND $3<>a.command_id`

const activationSelectSQL = `SELECT tenant_id,grant_id,activation_command_id,approval_command_id,
 actor_id,target_id,approver_id,request_digest,scope,policy_id,policy_version::text,
 actor_version::text,target_version::text,approver_version::text,approver_authority_version::text,
 authority_namespace,parent_id,parent_version::text,parent_digest_key::text,parent_digest,
 derived_digest_key::text,derived_digest,started_at,expires_at,state,version
 FROM identity_impersonation.active_grants
 WHERE tenant_id=$1 AND derived_digest_key=$2::text::bigint AND derived_digest=$3`

const activationRecoverySQL = `SELECT 1 FROM identity_impersonation.active_grants
 WHERE tenant_id=$1 AND grant_id=$2 AND activation_command_id=$3 AND actor_id=$4 AND target_id=$5
 AND policy_id=$6 AND policy_version=$7::text::numeric`

func activationInsertArgs(row activationRecord) []any {
	scope, _ := json.Marshal(row.scope.Permissions())
	return []any{
		string(row.tenant), string(row.grantID), string(row.commandID), string(row.approvalID),
		string(row.actor), string(row.target), string(row.approver), row.requestDigest[:], scope,
		row.policy.ID(), strconv.FormatUint(row.policy.Version(), 10), strconv.FormatUint(row.actorVersion, 10),
		strconv.FormatUint(row.targetVersion, 10), strconv.FormatUint(row.approverVersion, 10), strconv.FormatUint(row.approverAuthorityVersion, 10),
		row.authorityNamespace, row.parentID, strconv.FormatUint(row.parentVersion, 10),
		strconv.FormatUint(uint64(row.parentDigest.KeyVersion), 10), row.parentDigest.Sum[:],
		strconv.FormatUint(uint64(row.derivedDigest.KeyVersion), 10), row.derivedDigest.Sum[:], row.startedAt, row.expiresAt,
	}
}

// Only a native start contributor's original Work can persist this effect.
// Uniqueness makes the grant, command and derived digest single-winner keys;
// the exact retained approval is selected in the same insert statement.
func insertActivation(ctx context.Context, w kernel.Work, row activationRecord) error {
	if ctx == nil || !validActivation(row) || row.status != impersonation.StatusActive || row.version != 3 {
		return invalidStorageInput()
	}
	binding, err := w.Scope()
	if err != nil {
		return err
	}
	if _, _, err := activationRecoveryQuery(binding); err != nil {
		return err
	}
	if binding.TenantID != row.tenant || binding.RecordID != string(row.grantID) || binding.CommandID != row.commandID || identity.UserID(binding.ActorID) != row.actor || binding.UserID != row.target || binding.PolicyID != row.policy.ID() || binding.PolicyVersion != row.policy.Version() {
		return impersonation.ErrConflict
	}
	count, err := w.Exec(ctx, activationInsertSQL, activationInsertArgs(row)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return impersonation.ErrConflict
	}
	return nil
}

// readActivation is an uncached primary snapshot, not authorization. Callers
// must reject terminal state and revalidate original parent/current authority.
func readActivation(ctx context.Context, pool *database.Pool, tenant identity.TenantID, digest session.TokenDigest) (activationRecord, error) {
	if ctx == nil || pool == nil || !validStorageID(string(tenant)) || digest.KeyVersion == 0 {
		return activationRecord{}, invalidStorageInput()
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	rows, err := pool.Raw().Query(bounded, activationSelectSQL, string(tenant), strconv.FormatUint(uint64(digest.KeyVersion), 10), digest.Sum[:])
	if err != nil {
		return activationRecord{}, storageReadError(bounded)
	}
	row, err := decodeActivation(bounded, rows)
	if err != nil {
		return activationRecord{}, err
	}
	if row.tenant != tenant || row.derivedDigest != digest {
		return activationRecord{}, identity.UnavailableError{}
	}
	return row, nil
}

// Recovery proves only the exact historical activation effect, including after
// expiry or terminal transition. It does not renew authority or recover a bearer.
func recoverActivationEffect(ctx context.Context, w kernel.RecoveryWork, binding identity.CommandBinding) (kernel.RecoveryStatus, error) {
	if ctx == nil {
		return kernel.RecoveryUnknown, invalidStorageInput()
	}
	scope, err := w.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if scope != binding {
		return kernel.RecoveryUnknown, invalidStorageInput()
	}
	query, args, err := activationRecoveryQuery(binding)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, query, args...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return decodeGrantEffect(ctx, rows)
}

func activationRecoveryQuery(b identity.CommandBinding) (string, []any, error) {
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.start", SchemaID: "impersonation-start", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || identity.UserID(b.ActorID) == b.UserID || !validStoredGrantKey(b.TenantID, impersonation.GrantID(b.RecordID)) || string(b.CommandID) == b.RecordID {
		return "", nil, invalidStorageInput()
	}
	return activationRecoverySQL, []any{string(b.TenantID), b.RecordID, string(b.CommandID), string(b.ActorID), string(b.UserID), b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10)}, nil
}

func decodeActivation(ctx context.Context, rows storedGrantRows) (activationRecord, error) {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return activationRecord{}, storageReadError(ctx)
		}
		return activationRecord{}, identity.ForbiddenError{}
	}
	var tenant, grant, command, approval, actor, target, approver, policy, status string
	var requestDigest, scope, parentDigest, derivedDigest []byte
	var policyVersion, actorVersion, targetVersion, approverVersion, authorityVersion, parentVersion, parentKey, derivedKey string
	var version int16
	var row activationRecord
	err := rows.Scan(&tenant, &grant, &command, &approval, &actor, &target, &approver, &requestDigest, &scope, &policy, &policyVersion,
		&actorVersion, &targetVersion, &approverVersion, &authorityVersion, &row.authorityNamespace, &row.parentID, &parentVersion,
		&parentKey, &parentDigest, &derivedKey, &derivedDigest, &row.startedAt, &row.expiresAt, &status, &version)
	if err != nil || len(requestDigest) != 32 || len(parentDigest) != 32 || len(derivedDigest) != 32 || version < 3 || version > 4 {
		return activationRecord{}, storageReadError(ctx)
	}
	row.tenant, row.grantID, row.commandID, row.approvalID = identity.TenantID(tenant), impersonation.GrantID(grant), identity.CommandID(command), identity.CommandID(approval)
	row.actor, row.target, row.approver = identity.UserID(actor), identity.UserID(target), identity.UserID(approver)
	copy(row.requestDigest[:], requestDigest)
	copy(row.parentDigest.Sum[:], parentDigest)
	copy(row.derivedDigest.Sum[:], derivedDigest)
	var permissions []string
	if json.Unmarshal(scope, &permissions) != nil {
		return activationRecord{}, storageReadError(ctx)
	}
	row.scope, err = impersonation.NewScope(permissions)
	if err != nil || !slices.Equal(permissions, row.scope.Permissions()) {
		return activationRecord{}, storageReadError(ctx)
	}
	versions := []struct {
		text string
		dest *uint64
	}{
		{actorVersion, &row.actorVersion}, {targetVersion, &row.targetVersion}, {approverVersion, &row.approverVersion},
		{authorityVersion, &row.approverAuthorityVersion}, {parentVersion, &row.parentVersion},
	}
	for _, v := range versions {
		*v.dest, err = strconv.ParseUint(v.text, 10, 64)
		if err != nil {
			return activationRecord{}, storageReadError(ctx)
		}
	}
	policyNumber, err := strconv.ParseUint(policyVersion, 10, 64)
	if err != nil {
		return activationRecord{}, storageReadError(ctx)
	}
	row.policy, err = impersonation.NewPolicy(policy, policyNumber)
	if err != nil {
		return activationRecord{}, storageReadError(ctx)
	}
	parentNumber, err := strconv.ParseUint(parentKey, 10, 32)
	if err != nil {
		return activationRecord{}, storageReadError(ctx)
	}
	derivedNumber, err := strconv.ParseUint(derivedKey, 10, 32)
	if err != nil {
		return activationRecord{}, storageReadError(ctx)
	}
	row.parentDigest.KeyVersion, row.derivedDigest.KeyVersion = uint32(parentNumber), uint32(derivedNumber)
	row.startedAt, row.expiresAt = row.startedAt.UTC(), row.expiresAt.UTC()
	row.version, row.status = uint64(version), impersonation.Status(status)
	if rows.Next() || rows.Err() != nil || !validActivation(row) {
		return activationRecord{}, storageReadError(ctx)
	}
	return row, nil
}

func validActivation(row activationRecord) bool {
	_, commandErr := identity.ParseCommandID(string(row.commandID))
	_, approvalErr := identity.ParseCommandID(string(row.approvalID))
	_, policyErr := impersonation.NewPolicy(row.policy.ID(), row.policy.Version())
	permissions := row.scope.Permissions()
	_, scopeErr := impersonation.NewScope(permissions)
	if commandErr != nil || approvalErr != nil || policyErr != nil || scopeErr != nil || !validStoredGrantKey(row.tenant, row.grantID) {
		return false
	}
	if string(row.commandID) == string(row.grantID) || string(row.approvalID) == string(row.grantID) || row.commandID == row.approvalID {
		return false
	}
	if !validStorageID(string(row.actor)) || !validStorageID(string(row.target)) || !validStorageID(string(row.approver)) || row.actor == row.target || row.actor == row.approver || row.target == row.approver {
		return false
	}
	if !validStorageID(row.authorityNamespace) || row.actorVersion == 0 || row.targetVersion == 0 || row.approverVersion == 0 || row.approverAuthorityVersion == 0 || row.parentVersion == 0 || row.parentDigest.KeyVersion == 0 || row.derivedDigest.KeyVersion == 0 {
		return false
	}
	if len(row.parentID) == 0 || len(row.parentID) > 128 {
		return false
	}
	for i := range len(row.parentID) {
		if row.parentID[i] < 0x21 || row.parentID[i] > 0x7e {
			return false
		}
	}
	if !storageExactTime(row.startedAt) || !storageExactTime(row.expiresAt) || !row.expiresAt.After(row.startedAt) || row.expiresAt.Sub(row.startedAt) > impersonation.MaximumDuration {
		return false
	}
	return row.status == impersonation.StatusActive && row.version == 3 || (row.status == impersonation.StatusStopped || row.status == impersonation.StatusRevoked || row.status == impersonation.StatusExpired) && row.version == 4
}
