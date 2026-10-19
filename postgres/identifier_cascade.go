package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// IdentifierRemovalCascadeConfig freezes the exact ten-consumer pending
// admission. Contract fingerprints describe reviewed semantic contracts, not
// running adapters or acknowledgements. PolicyVersion shares the identity-owned
// cascade policy namespace with StatusUnitOfWorkConfig; incompatible stored
// definitions at the same tenant/version fail closed. Reasons are registered
// codes, not free text. MaximumDuration is microsecond-exact, positive and <=10y.
type IdentifierRemovalCascadeConfig struct {
	PolicyVersion     uint64
	Reasons           []string
	MaximumDuration   time.Duration
	ConsumerContracts map[string]StatusConsumerContract
}

type identifierRemovalCascadePolicy struct {
	config     IdentifierRemovalCascadeConfig
	definition []byte
}

func freezeIdentifierRemovalCascade(c IdentifierRemovalCascadeConfig) (*identifierRemovalCascadePolicy, error) {
	invalid := func() (*identifierRemovalCascadePolicy, error) { return nil, invalidEmailRemoval() }
	ids := identity.IdentifierRemovalConsumers()
	if c.PolicyVersion == 0 || len(c.Reasons) == 0 || len(c.Reasons) > 32 || c.MaximumDuration <= 0 || c.MaximumDuration > 87600*time.Hour || c.MaximumDuration%time.Microsecond != 0 || len(c.ConsumerContracts) != len(ids) {
		return invalid()
	}
	c.Reasons = slices.Clone(c.Reasons)
	reasons := make([][]byte, len(c.Reasons))
	for n, reason := range c.Reasons {
		if len(reason) > 64 || !featureEventName(reason) || slices.Contains(c.Reasons[:n], reason) {
			return invalid()
		}
		reasons[n] = cborText(reason)
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
	definition := cborMap(map[string][]byte{"profile": cborText("identity-identifier-removal-policy-v1"), "manifest": cborText("identity-lifecycle-consumers-v1"), "consumers": cborArray(encoded), "reasons": cborArray(reasons), "duration": cborUint(uint64(c.MaximumDuration))})
	return &identifierRemovalCascadePolicy{config: c, definition: definition}, nil
}

// admitIdentifierRemovalCascade runs after the kernel mutation and lifecycle
// staging, before journal terminalization. It reuses identity's existing
// cascade/policy/consumer storage and coordinator transaction. No consumer is
// acknowledged and no asynchronous completion is inferred from owner admission.
func admitIdentifierRemovalCascade(ctx context.Context, w Work) error {
	p := identifierRemovalProgressFor(w)
	if p == nil || !p.applied || p.cascade != nil || p.domain == nil || p.domain.cascade == nil || w.state.lifecycle == nil || w.state.lifecycle.record == nil {
		return w.fail(ctx, invalidEmailRemoval())
	}
	b, event, policy := w.state.binding, w.state.lifecycle.record, p.domain.cascade
	if event.CommandID != b.CommandID || event.EventType != "identifier.removed.v1" || event.SubjectID != b.RecordID || !slices.Contains(policy.config.Reasons, p.intent.Reason) {
		return w.fail(ctx, invalidEmailRemoval())
	}
	version := strconv.FormatUint(policy.config.PolicyVersion, 10)
	if _, err := w.Exec(ctx, `INSERT INTO identity.status_policies(tenant_id,policy_version,definition) VALUES($1,$2::numeric,$3) ON CONFLICT DO NOTHING`, string(b.TenantID), version, policy.definition); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT definition FROM identity.status_policies WHERE tenant_id=$1 AND policy_version=$2::numeric FOR SHARE`, string(b.TenantID), version)
	if err != nil {
		return err
	}
	var retained []byte
	valid := rows.Next() && rows.Scan(&retained) == nil && !rows.Next() && rows.Err() == nil && bytes.Equal(retained, policy.definition)
	rows.Close()
	clear(retained)
	if !valid {
		return w.fail(ctx, identity.ConflictError{})
	}
	rows, err = w.Query(ctx, `SELECT legal_hold,legal_hold_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$3::numeric AND identifier_version=$4::numeric`, string(b.TenantID), string(b.UserID), p.mutation.State.User.Version, p.mutation.State.AuthorityVersion)
	if err != nil {
		return err
	}
	var hold bool
	var holdVersion string
	valid = rows.Next() && rows.Scan(&hold, &holdVersion) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	parsed, parseErr := strconv.ParseUint(holdVersion, 10, 64)
	if !valid || parseErr != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != holdVersion {
		return w.fail(ctx, identity.UnavailableError{})
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	deadline := now.Add(policy.config.MaximumDuration)
	if !postgresExactTime(deadline) || !deadline.After(now) {
		return w.fail(ctx, invalidEmailRemoval())
	}
	id, err := identity.NewCascadeID()
	if err != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return w.fail(ctx, invalidEmailRemoval())
	}
	count, err := w.Exec(ctx, `INSERT INTO identity.status_cascades(cascade_id,tenant_id,user_id,command_id,command_key,operation,generation,manifest_version,policy_version,authority_version,aggregate_version,trigger_event_id,trigger_event_type,trigger_schema_version,requested_at,deadline,legal_hold,legal_hold_version,state,cascade_kind,authority_dimension,identifier_id) VALUES($1,$2,$3,$4,$5,$6,1,'identity-lifecycle-consumers-v1',$7::numeric,$8::numeric,$9::numeric,$10,'identifier.removed.v1',1,$11,$12,$13,$14::numeric,'pending','lifecycle.cascade.identifier_remove','identifier',$15)`, string(id), string(b.TenantID), string(b.UserID), string(b.CommandID), key, b.OperationID, version, p.mutation.State.AuthorityVersion, p.mutation.State.User.Version, event.ID, now, deadline, hold, holdVersion, b.RecordID)
	if err != nil {
		return err
	}
	if count != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	receipt := identity.LifecycleCascadeAdmission{CascadeID: id, Generation: 1, Kind: identity.IdentifierRemovalCascade, TenantID: b.TenantID, UserID: b.UserID, IdentifierID: identity.IdentifierID(b.RecordID), AuthorityVersion: p.mutation.State.AuthorityVersion, ManifestVersion: "identity-lifecycle-consumers-v1", Status: identity.RevocationPending}
	for n, consumer := range identity.IdentifierRemovalConsumers() {
		contract := policy.config.ConsumerContracts[consumer]
		count, err := w.Exec(ctx, `INSERT INTO identity.status_consumers(tenant_id,cascade_id,ordinal,consumer_id,contract_version,contract_fingerprint,state) VALUES($1,$2,$3,$4,$5,$6,'pending')`, string(b.TenantID), string(id), n, consumer, uint64(contract.Version), contract.Fingerprint[:])
		if err != nil {
			return err
		}
		if count != 1 {
			return w.fail(ctx, identity.ConflictError{})
		}
		receipt.Owners = append(receipt.Owners, identity.RevocationOwnerReceipt{Owner: consumer, Status: identity.RevocationPending})
	}
	if receipt.Validate(b) != nil {
		return w.fail(ctx, invalidEmailRemoval())
	}
	p.cascade = &receipt
	event.CascadeID, event.CascadeGeneration = id, 1
	return nil
}

func identifierRemovalProgressFor(w Work) *emailRemovalProgress {
	if w.state == nil || w.state.feature == nil {
		return nil
	}
	switch w.state.feature.Operation {
	case emailRemovalOperation():
		return w.state.emailRemoval
	case phoneRemovalOperation():
		return w.state.phoneRemoval
	default:
		return nil
	}
}
