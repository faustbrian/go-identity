package anonymouspostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func upgradeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func upgradeMergeDigest(p anonymous.MergePlan) ([32]byte, error) {
	p, err := p.Validated()
	if err != nil {
		return [32]byte{}, err
	}
	s, _ := p.Source.Record()
	h := sha256.New()
	h.Write([]byte("identity-anonymous-merge-plan-v1\x00"))
	// Fixed uint64 lengths/values and canonical UTC timestamps bind only this
	// bounded typed scope. No generic serialization of privacy-protected public
	// values, arbitrary resource payload or serializer-dependent object ordering.
	integer := func(value uint64) {
		var wire [8]byte
		binary.BigEndian.PutUint64(wire[:], value)
		h.Write(wire[:])
	}
	text := func(value string) { integer(uint64(len(value))); h.Write([]byte(value)) }
	for _, value := range []string{string(s.TenantID), string(s.ID), string(s.UserID), string(p.Target), s.CreatedAt.Format(time.RFC3339Nano), s.ExpiresAt.Format(time.RFC3339Nano)} {
		text(value)
	}
	for _, value := range []uint64{s.Version, uint64(s.State), uint64(s.Cleanup), uint64(len(p.Conflicts))} {
		integer(value)
	}
	for _, decision := range p.Conflicts {
		text(decision.Field)
		integer(uint64(decision.Disposition))
	}
	return [32]byte(h.Sum(nil)), nil
}

// UpgradeFields commits the bounded original source, permanent target and
// canonical typed merge plan before command fingerprinting. It carries no
// credential or resource payload and grants no authentication/transfer authority.
// The native owner must retain the complete plan in encrypted preparation;
// unsupported resource transfers still deny before mutation.
func UpgradeFields(p anonymous.MergePlan) ([]identity.FeatureField, error) {
	p, err := p.Validated()
	if err != nil {
		return nil, err
	}
	s, _ := p.Source.Record()
	digest, err := upgradeMergeDigest(p)
	if err != nil {
		return nil, err
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.upgrade." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	u := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.upgrade." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{text("id", string(s.ID)), text("user", string(s.UserID)), {Name: "anonymous.upgrade.created", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: s.CreatedAt}}, {Name: "anonymous.upgrade.expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: s.ExpiresAt}}, u("state", uint64(s.State)), u("version", s.Version), u("cleanup", uint64(s.Cleanup)), text("target", string(p.Target)), {Name: "anonymous.upgrade.merge-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}, nil
}

// ValidateUpgradePlan checks exact native command/typed plan agreement without
// IO, a clock, permission, proof consumption or mutation. Target UserID/ActorID
// remain distinct from the guest RecordID. Other owner namespaces are untouched.
func ValidateUpgradePlan(command identity.Command, plan anonymous.MergePlan) error {
	f, ok := command.Feature()
	p, err := plan.Validated()
	if !ok || err != nil || f.Operation != upgradeOperation() || f.Binding.ValidateFor(f.Operation) != nil {
		return anonymous.ErrInvalidInput
	}
	s, _ := p.Source.Record()
	b := f.Binding
	if b.TenantID != s.TenantID || b.UserID != identity.UserID(p.Target) || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(p.Target) || b.RecordID != string(s.UserID) {
		return anonymous.ErrInvalidInput
	}
	want, err := UpgradeFields(p)
	if err != nil {
		return err
	}
	values := make(map[string]identity.FeatureValue, len(want))
	for _, field := range f.Fields {
		if strings.HasPrefix(field.Name, "anonymous.upgrade.") {
			values[field.Name] = field.Value
		}
	}
	if len(values) != len(want) {
		return anonymous.ErrInvalidInput
	}
	for _, field := range want {
		value, exists := values[field.Name]
		if !exists || value.Kind != field.Value.Kind || value.Text != field.Value.Text || value.Uint64 != field.Value.Uint64 || !value.Time.Equal(field.Value.Time) || !bytes.Equal(value.Bytes, field.Value.Bytes) {
			return anonymous.ErrInvalidInput
		}
	}
	return nil
}

// This finite profile preserves the target and transfers no application data or
// credentials. Never silently ignore a requested transfer/reject decision. Full
// resource-owner callbacks remain a separate unsupported profile, not a fallback.
func supportedUpgradePlan(p anonymous.MergePlan) bool {
	return len(p.Conflicts) == 0 || len(p.Conflicts) == 1 && p.Conflicts[0] == (anonymous.Conflict{Field: "profile.display_name", Disposition: anonymous.KeepTarget})
}

func upgradeScope(w kernel.Work, owner kernel.AnonymousUpgradeContributor, command identity.Command, plan anonymous.MergePlan) (identity.CommandBinding, anonymous.SubjectSpec, error) {
	if owner == nil || ValidateUpgradePlan(command, plan) != nil || !supportedUpgradePlan(plan) {
		return identity.CommandBinding{}, anonymous.SubjectSpec{}, anonymous.ErrInvalidInput
	}
	b, f, l, err := w.FeatureScope(owner)
	s, _ := plan.Source.Record()
	c, _ := command.Feature()
	if err != nil || owner.Descriptor() != creationOwner() || f.Operation != upgradeOperation() || c.Binding != b || l != (kernel.LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}) {
		return identity.CommandBinding{}, anonymous.SubjectSpec{}, anonymous.ErrInvalidInput
	}
	return b, s, nil
}

// StageUpgrade writes only anonymous lifecycle and bounded merge metadata after
// the actual kernel's guest disposal and provisional one-use consumption in the
// same exact native Work. It never writes target identity, credentials, bearer
// or application data. Missing/changed source loses the optimistic race. Errors
// abort every owner; success is provisional until the coordinator commits.
func (r *Repository) StageUpgrade(ctx context.Context, w kernel.Work, owner kernel.AnonymousUpgradeContributor, command identity.Command, plan anonymous.MergePlan) error {
	if ctx == nil || r == nil || r.pool == nil || r.maximum <= 0 {
		return anonymous.ErrInvalidInput
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, expected, err := upgradeScope(w, owner, command, plan)
	if err != nil {
		return err
	}
	guest, err := w.AnonymousUpgradeDisposal(owner)
	if err != nil || guest.TenantID != b.TenantID || string(guest.ID) != b.RecordID {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, subjectSelect(r.schema)+" WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE", string(b.TenantID), b.RecordID)
	if err != nil {
		return err
	}
	current, err := readSubject(rows)
	rows.Close()
	if err != nil {
		return err
	}
	actual, _ := current.Record()
	if actual != expected {
		return identity.ConflictError{}
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if err := current.RequireActive(b.TenantID, now); err != nil {
		return err
	}
	before, after := strconv.FormatUint(expected.Version, 10), strconv.FormatUint(expected.Version+1, 10)
	n, err := w.Exec(bounded, `UPDATE `+r.schema+`.subjects SET state=2,version=$4::numeric WHERE tenant_id=$1 AND user_id=$2 AND state=1 AND version=$3::numeric`, string(b.TenantID), b.RecordID, before, after)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	digest, err := upgradeMergeDigest(plan)
	if err != nil {
		return err
	}
	// Work intentionally accepts only bounded scalar parameters/destinations,
	// not driver array codecs. This selected no-transfer profile has at most one
	// decision, so construct the schema's arrays from explicit scalar values.
	field, disposition := "", int16(0)
	if len(plan.Conflicts) == 1 {
		field, disposition = plan.Conflicts[0].Field, int16(plan.Conflicts[0].Disposition)
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return anonymous.ErrInvalidInput
	}
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.upgrades(tenant_id,purpose,command_id,user_id,target_user_id,before_version,after_version,cleanup,created_at,expires_at,merge_fields,merge_dispositions,merge_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10,CASE WHEN $11::text='' THEN ARRAY[]::text[] ELSE ARRAY[$11::text] END,CASE WHEN $11::text='' THEN ARRAY[]::smallint[] ELSE ARRAY[$12::smallint] END,$13)`, string(b.TenantID), b.OperationID, id, b.RecordID, string(b.UserID), before, after, int16(expected.Cleanup), expected.CreatedAt, expected.ExpiresAt, field, disposition, digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// RequireUpgrade repeats this owner's exact upgraded lifecycle, original merge
// decision and expiry under the same Work after all downstream effects. It is
// read-only and does not infer target authentication or extend validity.
func (r *Repository) RequireUpgrade(ctx context.Context, w kernel.Work, owner kernel.AnonymousUpgradeContributor, command identity.Command, plan anonymous.MergePlan) error {
	if ctx == nil || r == nil || r.pool == nil || r.maximum <= 0 {
		return anonymous.ErrInvalidInput
	}
	b, expected, err := upgradeScope(w, owner, command, plan)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, subjectSelect(r.schema)+" WHERE tenant_id=$1 AND user_id=$2 FOR SHARE", string(b.TenantID), b.RecordID)
	if err != nil {
		return err
	}
	current, err := readSubject(rows)
	rows.Close()
	if err != nil {
		return err
	}
	after := expected
	after.State, after.Version = anonymous.StateUpgraded, expected.Version+1
	actual, _ := current.Record()
	if actual != after {
		return identity.ForbiddenError{}
	}
	found, err := r.requireUpgradeRecord(bounded, w.Query, b, plan)
	if err != nil {
		return err
	}
	if !found {
		return identity.UnavailableError{}
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if now.Before(expected.CreatedAt) || !now.Before(expected.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

// RecoverUpgrade reads the exact retained source/target/typed-plan correlation
// only under the original coordinator's recovery invocation. It does not infer
// commitment from an absent guest row, authenticate a target or return a bearer.
// The caller must reconcile kernel, capability, password, session and required
// effects; mismatched or missing evidence cannot independently prove success.
func (r *Repository) RecoverUpgrade(ctx context.Context, w kernel.RecoveryWork, owner kernel.AnonymousUpgradeContributor, plan anonymous.MergePlan) (kernel.RecoveryStatus, error) {
	if ctx == nil || r == nil || r.pool == nil || r.maximum <= 0 || owner == nil {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	p, err := plan.Validated()
	if err != nil || !supportedUpgradePlan(p) {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	s, _ := p.Source.Record()
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || owner.Descriptor() != creationOwner() || f.Operation != upgradeOperation() || b.TenantID != s.TenantID || b.RecordID != string(s.UserID) || b.UserID != identity.UserID(p.Target) || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(p.Target) || l != (kernel.LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}) {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	found, err := r.requireUpgradeRecord(bounded, w.Query, b, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if !found {
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryCommitted, nil
}

type upgradeQuery func(context.Context, string, ...any) (*kernel.WorkRows, error)

func (r *Repository) requireUpgradeRecord(ctx context.Context, query upgradeQuery, b identity.CommandBinding, plan anonymous.MergePlan) (bool, error) {
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return false, anonymous.ErrInvalidInput
	}
	rows, err := query(ctx, `SELECT user_id,target_user_id,before_version::text,after_version::text,cleanup,created_at,expires_at,
 cardinality(merge_fields),cardinality(merge_dispositions),
 CASE WHEN cardinality(merge_fields)=1 AND octet_length(merge_fields[1])<=128 THEN merge_fields[1] ELSE ''::text END,
 CASE WHEN cardinality(merge_dispositions)=1 THEN merge_dispositions[1] ELSE 0::smallint END,
 CASE WHEN octet_length(merge_digest)=32 THEN merge_digest ELSE ''::bytea END
 FROM `+r.schema+`.upgrades WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return false, rows.Err()
	}
	var user, target, before, after string
	var cleanup int16
	var created, expires time.Time
	var count, dispositionCount int
	var field string
	var disposition int16
	var digest []byte
	if err := rows.Scan(&user, &target, &before, &after, &cleanup, &created, &expires, &count, &dispositionCount, &field, &disposition, &digest); err != nil {
		return false, err
	}
	s, _ := plan.Source.Record()
	want, err := upgradeMergeDigest(plan)
	if err != nil || rows.Next() || rows.Err() != nil || user != b.RecordID || target != string(b.UserID) || before != strconv.FormatUint(s.Version, 10) || after != strconv.FormatUint(s.Version+1, 10) || cleanup != int16(s.Cleanup) || !created.Equal(s.CreatedAt) || !expires.Equal(s.ExpiresAt) || count != len(plan.Conflicts) || count > 1 || dispositionCount != count || count == 0 && (field != "" || disposition != 0) || !bytes.Equal(digest, want[:]) {
		return false, identity.UnavailableError{}
	}
	for _, decision := range plan.Conflicts {
		if field != decision.Field || disposition != int16(decision.Disposition) {
			return false, identity.UnavailableError{}
		}
	}
	return true, nil
}
