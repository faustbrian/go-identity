package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// StatusConsumerContract identifies one immutable public consumer contract.
// Fingerprint is its reviewed nonzero SHA-256 identity, not an acknowledgement
// or a running adapter. Unavailable consumers must remain in the manifest.
type StatusConsumerContract struct {
	Version     uint32
	Fingerprint [32]byte
}

// StatusUnitOfWorkConfig declares immutable owner policy and the entire
// identity-lifecycle-consumers-v1 union before use. PolicyVersion is positive;
// change it for any policy, reason, deadline or consumer-contract change. Reasons
// has 1..32 distinct bounded non-whitespace codes. MaximumCascadeDuration is
// microsecond-exact, positive and at most 87,600 hours. ConsumerContracts must
// contain exactly the 12 suspend/ban consumers, including restore's nine.
// RetentionPolicyVersion has CreationUnitOfWorkConfig semantics. Configuration
// is trusted deployment metadata, never authentication or caller permission.
type StatusUnitOfWorkConfig struct {
	RetentionPolicyVersion uint64
	PolicyVersion          uint64
	Policy                 identity.StatusPolicy
	Reasons                []string
	MaximumCascadeDuration time.Duration
	ConsumerContracts      map[string]StatusConsumerContract
}

type statusOwnerPolicy struct {
	config     StatusUnitOfWorkConfig
	definition []byte
}

// StatusUnitOfWork implements the core status command seam through the sole
// Coordinator with exact enlisted repository/audit/outbox instances. Direct
// calls do not authorize callers: compose behind identity.UserStatusService.
// Immutable copied policy supports concurrent calls. It owns no pool, worker,
// callback, transaction protocol or consumer closure. Zero is invalid.
type StatusUnitOfWork struct{ owner *CreationUnitOfWork }

var _ identity.UnitOfWork = (*StatusUnitOfWork)(nil)

// NewStatusUnitOfWork copies and validates policy without I/O or callbacks.
// Apply StatusMigrationSource before use. Every consumer starts pending; naming
// one or storing its fingerprint never asserts that its cleanup has run.
func NewStatusUnitOfWork(c *Coordinator, r *Repository, config StatusUnitOfWorkConfig) (*StatusUnitOfWork, error) {
	policy, err := freezeStatusPolicy(config)
	if err != nil {
		return nil, err
	}
	owner, err := NewCreationUnitOfWork(c, r, CreationUnitOfWorkConfig{RetentionPolicyVersion: config.RetentionPolicyVersion})
	if err != nil {
		return nil, err
	}
	owner.status = policy
	return &StatusUnitOfWork{owner: owner}, nil
}

// Execute resolves exact replay before locked dual-version CAS. A fresh
// command advances aggregate and user-security epochs once, persists policy,
// reason/absolute expiry, pending cascade/consumer snapshot, required audit,
// lifecycle and original receipt in one commit. Restore and unban cannot revive
// old credentials. Ambiguous closure returns Unknown, never a fabricated user.
func (o *StatusUnitOfWork) Execute(ctx context.Context, command identity.Command) (identity.CommandResult, error) {
	if o == nil || o.owner == nil {
		return identity.CommandResult{}, coordinatorError()
	}
	spec, ok := command.UserStatus()
	if !ok || !statusOperation(spec.Binding.OperationID) {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "status_command"}
	}
	return o.owner.execute(ctx, command, spec.Binding.OperationID)
}

// Recover observes the exact original receipt without another mutation or
// cascade. Core current authorization/redaction governs disclosure. Expired
// pending work requires all original participants' evidence; current status
// alone never proves commitment. Preserve the original scope and command ID.
func (o *StatusUnitOfWork) Recover(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	if o == nil || o.owner == nil || !statusOperation(q.OperationID) {
		return identity.CommandResult{}, coordinatorError()
	}
	return o.owner.recover(ctx, q, q.OperationID)
}

// Format hides runtime composition and retained policy data.
func (StatusUnitOfWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.StatusUnitOfWork(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition.
func (StatusUnitOfWork) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }

// Format hides private policy and consumer configuration.
func (StatusUnitOfWorkConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.StatusUnitOfWorkConfig(redacted)"))
}

// MarshalJSON rejects serialization of private configuration.
func (StatusUnitOfWorkConfig) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }

func statusOperation(op string) bool {
	return op == "identity.user.suspend" || op == "identity.user.restore" || op == "identity.admin.user-ban" || op == "identity.admin.user-unban"
}

func freezeStatusPolicy(c StatusUnitOfWorkConfig) (*statusOwnerPolicy, error) {
	invalid := func() (*statusOwnerPolicy, error) {
		return nil, identity.InvalidInputError{Field: "status_configuration"}
	}
	if c.RetentionPolicyVersion == 0 || c.PolicyVersion == 0 || c.Policy.Validate() != nil || len(c.Reasons) == 0 || len(c.Reasons) > 32 || c.MaximumCascadeDuration <= 0 || c.MaximumCascadeDuration > 87600*time.Hour || c.MaximumCascadeDuration%time.Microsecond != 0 {
		return invalid()
	}
	c.Reasons = slices.Clone(c.Reasons)
	for i, reason := range c.Reasons {
		if len(reason) == 0 || len(reason) > 512 || !utf8.ValidString(reason) || slices.Contains(c.Reasons[:i], reason) {
			return invalid()
		}
		for _, r := range reason {
			if unicode.IsSpace(r) || unicode.IsControl(r) {
				return invalid()
			}
		}
	}
	c.Policy.AllowedTransitions = slices.Clone(c.Policy.AllowedTransitions)
	ids := (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: "identity.user.suspend"}}).RequiredConsumers()
	if len(c.ConsumerContracts) != len(ids) {
		return invalid()
	}
	contracts := make(map[string]StatusConsumerContract, len(ids))
	encoded := make([][]byte, 0, len(ids))
	for _, id := range ids {
		contract, ok := c.ConsumerContracts[id]
		if !ok || contract.Version == 0 || contract.Fingerprint == ([32]byte{}) {
			return invalid()
		}
		contracts[id] = contract
		encoded = append(encoded, cborMap(map[string][]byte{"id": cborText(id), "version": cborUint(uint64(contract.Version)), "fingerprint": cborBytes(contract.Fingerprint[:])}))
	}
	c.ConsumerContracts = contracts
	edges := make([][]byte, 0, len(c.Policy.AllowedTransitions))
	for _, e := range c.Policy.AllowedTransitions {
		edges = append(edges, cborMap(map[string][]byte{"from": cborText(string(e.From)), "to": cborText(string(e.To)), "reason_required": cborBool(e.ReasonRequired)}))
	}
	reasons := make([][]byte, len(c.Reasons))
	for i, reason := range c.Reasons {
		reasons[i] = cborText(reason)
	}
	definition := cborMap(map[string][]byte{"profile": cborText("identity-status-policy-v1"), "consumers": cborArray(encoded), "edges": cborArray(edges), "reasons": cborArray(reasons), "maximum_suspension": cborUint(uint64(c.Policy.MaximumSuspension)), "reuse_cooldown": cborUint(uint64(c.Policy.IdentifierReuseCooldown)), "ban_requires_reason": cborBool(c.Policy.BanRequiresReason), "cascade_duration": cborUint(uint64(c.MaximumCascadeDuration))})
	return &statusOwnerPolicy{config: c, definition: definition}, nil
}

func (o *CreationUnitOfWork) applyStatus(ctx context.Context, w Work, command identity.Command, now time.Time) (identity.CommandResult, error) {
	invalid := func(e error) (identity.CommandResult, error) { return identity.CommandResult{}, w.fail(ctx, e) }
	if o == nil || o.status == nil || o.repository == nil || w.usable() != nil || w.state.execution == nil || w.state.execution.coordinator != o.coordinator || w.state.status != nil || w.state.creation != nil || w.state.profile != nil || w.state.update != nil {
		return invalid(invalidWork())
	}
	spec, ok := command.UserStatus()
	if !ok || spec.Binding != w.state.binding {
		return invalid(identity.InvalidInputError{Field: "status_command"})
	}
	q, err := prepareClaim(command, o.coordinator.keys.retained[o.coordinator.keys.current])
	if err != nil || !bytes.Equal(q.canonical, w.state.execution.reservation.request.canonical) {
		return invalid(identity.ConflictError{})
	}
	enlisted := false
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.contributor == o.repository && entry.descriptor.Owner == "identity/postgres" {
			enlisted = true
		}
	}
	if !enlisted {
		return invalid(invalidWork())
	}
	c := o.status.config
	if spec.StatusPolicyVersion != c.PolicyVersion || spec.TargetStatus != identity.StatusActive && !slices.Contains(c.Reasons, spec.Reason) {
		return invalid(identity.ForbiddenError{})
	}
	version := strconv.FormatUint(c.PolicyVersion, 10)
	if _, err := w.Exec(ctx, `INSERT INTO identity.status_policies(tenant_id,policy_version,definition) VALUES($1,$2::numeric,$3) ON CONFLICT DO NOTHING`, string(spec.Binding.TenantID), version, o.status.definition); err != nil {
		return identity.CommandResult{}, err
	}
	rows, err := w.Query(ctx, `SELECT definition FROM identity.status_policies WHERE tenant_id=$1 AND policy_version=$2::numeric`, string(spec.Binding.TenantID), version)
	if err != nil {
		return identity.CommandResult{}, err
	}
	var retained []byte
	valid := rows.Next() && rows.Scan(&retained) == nil && !rows.Next() && rows.Err() == nil && bytes.Equal(retained, o.status.definition)
	rows.Close()
	if !valid {
		return invalid(identity.ConflictError{})
	}
	rows, err = w.Query(ctx, `SELECT tenant_id,user_id,status,version::text,authority_version::text,legal_hold,legal_hold_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(spec.Binding.TenantID), string(spec.Binding.UserID))
	if err != nil {
		return identity.CommandResult{}, err
	}
	var tenant, id, status, aggregate, authority, holdVersion string
	var hold bool
	valid = rows.Next() && rows.Scan(&tenant, &id, &status, &aggregate, &authority, &hold, &holdVersion) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	if !valid {
		return invalid(identity.ForbiddenError{})
	}
	current, err := decodeStatus(identity.UserStatusQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID}, tenant, id, status, aggregate, authority)
	hv, he := strconv.ParseUint(holdVersion, 10, 64)
	if err != nil || he != nil || hv == 0 || strconv.FormatUint(hv, 10) != holdVersion {
		return invalid(identity.UnavailableError{})
	}
	if current.User.Version != spec.ExpectedVersion || current.AuthorityVersion != spec.ExpectedAuthorityVersion {
		return invalid(identity.ConflictError{})
	}
	if current.User.Status == identity.StatusDeleted || current.User.Status == identity.StatusAnonymized || spec.Binding.OperationID == "identity.user.restore" && current.User.Status != identity.StatusSuspended || spec.Binding.OperationID == "identity.admin.user-unban" && current.User.Status != identity.StatusBanned {
		return invalid(identity.ForbiddenError{})
	}
	// A row-lock wait must not admit an expiry against a pre-wait timestamp.
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return identity.CommandResult{}, err
	}
	restriction := time.Duration(0)
	if !spec.ExpiresAt.IsZero() {
		if !spec.ExpiresAt.After(now) || spec.ExpiresAt.After(now.Add(c.Policy.MaximumSuspension)) {
			return invalid(identity.InvalidInputError{Field: "status_expiry"})
		}
		restriction = spec.ExpiresAt.Sub(now)
	}
	if err := c.Policy.CheckTransition(current.User.Status, spec.TargetStatus, spec.Reason != "", restriction); err != nil {
		return invalid(identity.ForbiddenError{})
	}
	deadline := now.Add(c.MaximumCascadeDuration)
	if !postgresExactTime(deadline) {
		return invalid(identity.InvalidInputError{Field: "cascade_deadline"})
	}
	cascade, err := identity.NewCascadeID()
	if err != nil {
		return invalid(identity.UnavailableError{})
	}
	var reason, expires any
	if spec.Reason != "" {
		reason = spec.Reason
	}
	if !spec.ExpiresAt.IsZero() {
		expires = spec.ExpiresAt
	}
	count, err := w.Exec(ctx, `UPDATE identity.users SET status=$3,version=version+1,authority_version=authority_version+1,status_reason=$6,status_expires_at=$7 WHERE tenant_id=$1 AND user_id=$2 AND version=$4::numeric AND authority_version=$5::numeric`, tenant, id, string(spec.TargetStatus), aggregate, authority, reason, expires)
	if err != nil {
		return identity.CommandResult{}, err
	}
	if count != 1 {
		return invalid(identity.ConflictError{})
	}
	current.User.Status, current.User.Version = spec.TargetStatus, spec.ExpectedVersion+1
	revocation := identity.RevocationOutcome{CascadeID: cascade, Generation: 1, AuthorityVersion: spec.ExpectedAuthorityVersion + 1, Status: identity.RevocationPending}
	if err := w.StageLifecycle(0, now); err != nil {
		return identity.CommandResult{}, err
	}
	event := w.state.lifecycle.record
	key, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
	if _, err := w.Exec(ctx, `INSERT INTO identity.status_cascades(cascade_id,tenant_id,user_id,command_id,command_key,operation,generation,manifest_version,policy_version,authority_version,aggregate_version,trigger_event_id,trigger_event_type,trigger_schema_version,requested_at,deadline,legal_hold,legal_hold_version,state) VALUES($1,$2,$3,$4,$5,$6,1,'identity-lifecycle-consumers-v1',$7::numeric,$8::numeric,$9::numeric,$10,$11,1,$12,$13,$14,$15::numeric,'pending')`, string(cascade), tenant, id, string(spec.Binding.CommandID), key, spec.Binding.OperationID, version, strconv.FormatUint(revocation.AuthorityVersion, 10), strconv.FormatUint(current.User.Version, 10), event.ID, event.EventType, now, deadline, hold, holdVersion); err != nil {
		return identity.CommandResult{}, err
	}
	for i, consumer := range spec.RequiredConsumers() {
		contract := c.ConsumerContracts[consumer]
		if _, err := w.Exec(ctx, `INSERT INTO identity.status_consumers(tenant_id,cascade_id,ordinal,consumer_id,contract_version,contract_fingerprint,state) VALUES($1,$2,$3,$4,$5,$6,'pending')`, tenant, string(cascade), int16(i), consumer, uint64(contract.Version), contract.Fingerprint[:]); err != nil {
			return identity.CommandResult{}, err
		}
		revocation.Owners = append(revocation.Owners, identity.RevocationOwnerReceipt{Owner: consumer, Status: identity.RevocationPending})
	}
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted, User: current.User, ExpectedVersion: spec.ExpectedVersion, Revocation: &revocation}
	w.state.status = &result
	return result, nil
}
