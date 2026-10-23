package postgres

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// AnonymousDisposalEffect terminally revokes all of this anonymous user's
// sessions and families in the existing delete command's sole Work. It owns no
// transaction, callbacks or goroutines. The actual kernel disposal must already
// have applied, and the exact original source must still be active/unexpired.
// Immutable composition supports independent concurrent invocations.
type AnonymousDisposalEffect struct {
	config Config
	schema string
}

// NewAnonymousDisposalEffect validates trusted schema/budget without IO. Install
// AnonymousDisposalMigrationSource in the session and kernel owners first. A
// complete bounded set (at most100000 sessions/families) commits or all rolls
// back; no selected prefix may be reported as successful disposal.
func NewAnonymousDisposalEffect(c Config) (*AnonymousDisposalEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	return &AnonymousDisposalEffect{config: c, schema: pgx.Identifier{c.Schema}.Sanitize()}, nil
}
func anonymousDeleteOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.delete", SchemaID: "identity.anonymous.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

type anonymousDisposalSessionMode uint8

const (
	anonymousSessionSelf anonymousDisposalSessionMode = iota + 1
	anonymousSessionUpgrade
	anonymousSessionExpired
)

func anonymousExpirySessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.expire", SchemaID: "identity.anonymous.expire.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func anonymousExpiryBinding(b identity.CommandBinding, op identity.FeatureOperation, l kernel.LifecyclePlan, d kernel.ContributorDescriptor) bool {
	return b.ValidateFor(op) == nil && op == anonymousExpirySessionOperation() && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(b.UserID) && d == (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) && l.EventType == "anonymous.expired.v1" && l.BeforeVersion > 0 && l.BeforeVersion < ^uint64(0) && l.AfterVersion == l.BeforeVersion+1
}

func anonymousDisposalScopeForSession(w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, mode anonymousDisposalSessionMode) (identity.CommandBinding, kernel.LifecyclePlan, error) {
	if mode == anonymousSessionSelf || mode == anonymousSessionUpgrade {
		return anonymousDisposalSessionScope(w, p, c, mode == anonymousSessionUpgrade)
	}
	if mode != anonymousSessionExpired {
		return identity.CommandBinding{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(p)
	spec, ok := c.Feature()
	if err != nil || !ok || spec.Binding != b || spec.Operation != f.Operation || !anonymousExpiryBinding(b, f.Operation, l, p.Descriptor()) {
		return identity.CommandBinding{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	return b, l, nil
}
func anonymousDeleteScope(w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command) (identity.CommandBinding, kernel.LifecyclePlan, error) {
	b, f, l, err := w.FeatureScope(p)
	spec, ok := c.Feature()
	if err != nil || !ok || spec.Binding != b || spec.Operation != anonymousDeleteOperation() || f.Operation != spec.Operation || p.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) || b.RecordID != string(b.UserID) || string(b.ActorID) != string(b.UserID) || l.EventType != "anonymous.deleted.v1" || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 {
		return identity.CommandBinding{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	return b, l, nil
}

func anonymousDeletionSource(c identity.Command, source session.Session) error {
	f, ok := c.Feature()
	if !ok || f.Operation != anonymousDeleteOperation() {
		return session.ErrInvalidSessionCommand
	}
	fields := make([]identity.FeatureField, 0, 100)
	for _, field := range f.Fields {
		if strings.HasPrefix(field.Name, anonymousSourcePrefix) {
			fields = append(fields, field)
		}
	}
	restored, err := AnonymousSourceSessionFromFields(f.Binding.TenantID, f.Binding.UserID, fields)
	if err != nil {
		return err
	}
	actual, _, err := encodeRecord(restored)
	expected, _, se := encodeRecord(source)
	if err != nil || se != nil || !bytes.Equal(actual, expected) {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

// Apply verifies exact original source custody and stages complete terminal
// revocation, including expired active-state siblings and empty families.
// Non-anonymous sibling records deny rather than erase a permanent identity's
// sessions. Risk, lifecycle and retention admission remain their owners' work.
// Returned receipt is provisional and contains no bearer.
func (e *AnonymousDisposalEffect) Apply(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, source session.Session) (identity.FeatureReceipt, error) {
	return e.apply(ctx, w, p, c, source, false)
}

func (e *AnonymousDisposalEffect) apply(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, source session.Session, upgrade bool) (identity.FeatureReceipt, error) {
	mode := anonymousSessionSelf
	if upgrade {
		mode = anonymousSessionUpgrade
	}
	return e.applyFor(ctx, w, p, c, source, mode)
}

// ApplyExpired revokes the complete guest set without requiring a live source
// session. Only the exact trusted service-expiry invocation with an actual
// provisional kernel disposal is admitted. An empty or already-pruned set is
// valid; non-anonymous contamination or an excess bound aborts the entire Work.
// The native owner supplies expiry, service policy and retention fences.
func (e *AnonymousDisposalEffect) ApplyExpired(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command) (identity.FeatureReceipt, error) {
	return e.applyFor(ctx, w, p, c, session.Session{}, anonymousSessionExpired)
}

func (e *AnonymousDisposalEffect) applyFor(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, source session.Session, mode anonymousDisposalSessionMode) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if mode == anonymousSessionSelf {
		if err := anonymousDeletionSource(c, source); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	b, l, err := anonymousDisposalScopeForSession(w, p, c, mode)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var u identity.User
	if mode == anonymousSessionUpgrade {
		typed, ok := p.(kernel.AnonymousUpgradeContributor)
		if !ok {
			return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
		}
		u, err = w.AnonymousUpgradeDisposal(typed)
	} else if mode == anonymousSessionExpired {
		u, err = w.AnonymousExpiredDisposal(p)
	} else {
		u, err = w.AnonymousDisposal(p)
	}
	s, se := source.Bindings()
	sourceUser := b.UserID
	if mode == anonymousSessionUpgrade {
		sourceUser = identity.UserID(b.RecordID)
	}
	if err != nil || u.ID != sourceUser || u.TenantID != b.TenantID || u.Status != identity.StatusDeleted && u.Status != identity.StatusAnonymized || mode != anonymousSessionExpired && (se != nil || u.ID != s.UserID || u.TenantID != s.TenantID || s.Authentication.Kind != session.AuthenticationAnonymous) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	var original []byte
	if mode != anonymousSessionExpired {
		if err := RequireSession(bounded, w, e.config, source); err != nil {
			return identity.FeatureReceipt{}, err
		}
		original, _, err = encodeRecord(source)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	cursor := ""
	count := uint32(0)
	chain := resetSessionChain()
	found := false
	for {
		rows, err := w.Query(bounded, `SELECT s.record::text,s.state,f.state,f.version::text,s.expires_at,s.tenant_id,s.session_id,s.user_id,s.family_id,s.version::text,s.family_version::text,s.digest_version,s.digest FROM `+e.schema+`.sessions s JOIN `+e.schema+`.families f USING(tenant_id,family_id,user_id) WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.state='active' AND s.session_id>$3 ORDER BY s.session_id LIMIT 16 FOR UPDATE OF s`, string(b.TenantID), string(sourceUser), cursor)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		type row struct {
			id      string
			version uint64
		}
		page := make([]row, 0, 16)
		for rows.Next() {
			r := primaryStoredRow{}
			if err = r.scan(rows); err != nil {
				break
			}
			stored, de := r.decode(b.TenantID, "", nil)
			if de != nil {
				err = de
				break
			}
			spec, be := stored.Session.Bindings()
			if be != nil || spec.UserID != sourceUser || spec.Authentication.Kind != session.AuthenticationAnonymous || spec.SessionID <= cursor || len(page) == 16 {
				err = ErrInvalidRecord
				break
			}
			if mode != anonymousSessionExpired && spec.SessionID == s.SessionID {
				encoded, _, ee := encodeRecord(stored.Session)
				if ee != nil || !bytes.Equal(encoded, original) {
					err = identity.ConflictError{}
					break
				}
				found = true
			}
			cursor = spec.SessionID
			page = append(page, row{cursor, spec.Version})
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if uint64(count)+uint64(len(page)) > 100000 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		for _, r := range page {
			n, err := w.Exec(bounded, `UPDATE `+e.schema+`.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND state='active' AND version=$4::numeric`, string(b.TenantID), string(sourceUser), r.id, strconv.FormatUint(r.version, 10))
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
			if n != 1 {
				return identity.FeatureReceipt{}, identity.ConflictError{}
			}
			count++
			chain = resetSessionNext(chain, r.id, r.version)
		}
		if len(page) < 16 {
			break
		}
	}
	if mode != anonymousSessionExpired && (!found || count == 0) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	// The kernel tenant mutex serializes every session/family writer. Count
	// families before their one bounded set update; excess aborts all prior rows.
	rows, err := w.Query(bounded, `SELECT count(*) FROM `+e.schema+`.families WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(b.TenantID), string(sourceUser))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var families int64
	if !rows.Next() || rows.Scan(&families) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.FeatureReceipt{}, ErrInvalidRecord
	}
	rows.Close()
	if families < 0 || families > 100000 || mode != anonymousSessionExpired && families == 0 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	n, err := w.Exec(bounded, `UPDATE `+e.schema+`.families SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(b.TenantID), string(sourceUser))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != families {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, binding := revocationEvidence(b, l)
	result := anonymousDisposalSessionDigest(binding, source, count, uint32(families), chain)
	var sourceID any
	if mode != anonymousSessionExpired {
		sourceID = s.SessionID
	}
	n, err = w.Exec(bounded, `INSERT INTO `+e.schema+`.anonymous_disposals(tenant_id,command_id,purpose,user_id,source_id,before_version,after_version,revoked_count,family_count,effects_digest,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10,$11,$12)`, string(b.TenantID), id, b.OperationID, string(sourceUser), sourceID, strconv.FormatUint(l.BeforeVersion, 10), strconv.FormatUint(l.AfterVersion, 10), int64(count), families, chain[:], binding[:], result[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	f, _ := c.Feature()
	return identity.FeatureReceipt{Operation: f.Operation, BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}

func anonymousDisposalSessionDigest(binding [32]byte, source session.Session, count, families uint32, chain [32]byte) [32]byte {
	s, _ := source.Bindings()
	// Reuse the session owner's existing chain/digest algorithm, not a second
	// authority. The source ID/version and family count remain domain-separated.
	// Service expiry has no source session: its zero tuple is separated from
	// browser disposal by the original operation-bound command digest.
	base := resetSessionDigest(binding, s.Version, uint64(families), s.FamilyVersion, count, chain)
	return resetSessionNext(base, s.SessionID, s.Version)
}

// Check verifies terminal source/all-sibling/family state in the same final
// invocation, preserving original lifetime and admission deadline. It does not
// read a revoked source as current authentication or reopen a session.
func (e *AnonymousDisposalEffect) Check(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, source session.Session, until time.Time) error {
	return e.check(ctx, w, p, c, source, until, false)
}

func (e *AnonymousDisposalEffect) check(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, source session.Session, until time.Time, upgrade bool) error {
	mode := anonymousSessionSelf
	if upgrade {
		mode = anonymousSessionUpgrade
	}
	return e.checkFor(ctx, w, p, c, source, until, mode)
}

// CheckExpired fences the absence of every active guest session and family in
// the original service admission window. No expired or invented source session
// is authenticated, and no observation deadline is renewed.
func (e *AnonymousDisposalEffect) CheckExpired(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, until time.Time) error {
	return e.checkFor(ctx, w, p, c, session.Session{}, until, anonymousSessionExpired)
}

func (e *AnonymousDisposalEffect) checkFor(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, source session.Session, until time.Time, mode anonymousDisposalSessionMode) error {
	if ctx == nil || e == nil {
		return session.ErrInvalidSessionCommand
	}
	if mode == anonymousSessionSelf {
		if err := anonymousDeletionSource(c, source); err != nil {
			return err
		}
	}
	b, _, err := anonymousDisposalScopeForSession(w, p, c, mode)
	if err != nil {
		return err
	}
	s, err := source.Bindings()
	sourceUser := b.UserID
	if mode == anonymousSessionUpgrade {
		sourceUser = identity.UserID(b.RecordID)
	}
	if mode != anonymousSessionExpired && (err != nil || s.UserID != sourceUser || s.TenantID != b.TenantID) {
		return session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	rows, err := w.Query(bounded, `SELECT EXISTS(SELECT 1 FROM `+e.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active') OR EXISTS(SELECT 1 FROM `+e.schema+`.families WHERE tenant_id=$1 AND user_id=$2 AND state='active')`, string(b.TenantID), string(sourceUser))
	if err != nil {
		return err
	}
	var live bool
	if !rows.Next() || rows.Scan(&live) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return ErrInvalidRecord
	}
	rows.Close()
	if live {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if mode != anonymousSessionExpired {
		_, err = source.Lifetime(now)
	}
	if err != nil || !now.Before(until) || until.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover reads retained original effect evidence, not prunable live sessions.
// It neither grants current access nor restores tokens; the existing coordinator
// must reconcile every owner before declaring the command terminal.
func (e *AnonymousDisposalEffect) Recover(ctx context.Context, w kernel.RecoveryWork, p kernel.FeatureExecutionContributor, source session.Session) (kernel.RecoveryStatus, error) {
	return e.recover(ctx, w, p, source, false)
}

func (e *AnonymousDisposalEffect) recover(ctx context.Context, w kernel.RecoveryWork, p kernel.FeatureExecutionContributor, source session.Session, upgrade bool) (kernel.RecoveryStatus, error) {
	mode := anonymousSessionSelf
	if upgrade {
		mode = anonymousSessionUpgrade
	}
	return e.recoverFor(ctx, w, p, source, mode)
}

// RecoverExpired reads retained service-expiry effects even after every guest
// session payload is pruned. Absence is participant evidence only: the existing
// coordinator must reconcile all owners before declaring the original outcome.
// This returns no bearer and never re-executes cleanup.
func (e *AnonymousDisposalEffect) RecoverExpired(ctx context.Context, w kernel.RecoveryWork, p kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	return e.recoverFor(ctx, w, p, session.Session{}, anonymousSessionExpired)
}

func (e *AnonymousDisposalEffect) recoverFor(ctx context.Context, w kernel.RecoveryWork, p kernel.FeatureExecutionContributor, source session.Session, mode anonymousDisposalSessionMode) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(p)
	s, se := source.Bindings()
	op, event, sourceUser := anonymousDeleteOperation(), "anonymous.deleted.v1", b.UserID
	if mode == anonymousSessionUpgrade {
		op, event, sourceUser = anonymousUpgradeSessionOperation(), "anonymous.upgraded.v1", identity.UserID(b.RecordID)
	} else if mode == anonymousSessionExpired {
		op, event = anonymousExpirySessionOperation(), "anonymous.expired.v1"
	}
	if err != nil || f.Operation != op || p.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) || l.EventType != event || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 || mode == anonymousSessionUpgrade && b.UserID == sourceUser || mode == anonymousSessionExpired && !anonymousExpiryBinding(b, f.Operation, l, p.Descriptor()) || mode != anonymousSessionExpired && (se != nil || s.UserID != sourceUser || s.TenantID != b.TenantID) || mode < anonymousSessionSelf || mode > anonymousSessionExpired {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, binding := revocationEvidence(b, l)
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	rows, err := w.Query(bounded, `SELECT user_id,source_id,before_version::text,after_version::text,revoked_count,family_count,effects_digest,binding_digest,result_digest FROM `+e.schema+`.anonymous_disposals WHERE tenant_id=$1 AND command_id=$2 AND purpose=$3`, string(b.TenantID), id, b.OperationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var user, before, after string
	var sourceID *string
	var count, families int64
	var effects, savedBinding, savedResult []byte
	if err := rows.Scan(&user, &sourceID, &before, &after, &count, &families, &effects, &savedBinding, &savedResult); err != nil {
		return kernel.RecoveryUnknown, err
	}
	validSource := sourceID == nil
	minimum := int64(0)
	if mode != anonymousSessionExpired {
		validSource = sourceID != nil && *sourceID == s.SessionID
		minimum = 1
	}
	if rows.Next() || rows.Err() != nil || user != string(sourceUser) || !validSource || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || count < minimum || count > 100000 || families < minimum || families > 100000 || len(effects) != 32 || subtle.ConstantTimeCompare(binding[:], savedBinding) != 1 {
		return kernel.RecoveryUnknown, ErrInvalidRecord
	}
	var chain [32]byte
	copy(chain[:], effects)
	expected := anonymousDisposalSessionDigest(binding, source, uint32(count), uint32(families), chain)
	if chain == ([32]byte{}) || subtle.ConstantTimeCompare(expected[:], savedResult) != 1 {
		return kernel.RecoveryUnknown, ErrInvalidRecord
	}
	return kernel.RecoveryCommitted, nil
}
func (*AnonymousDisposalEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousDisposalEffect(redacted)"))
}
func (*AnonymousDisposalEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (*AnonymousDisposalEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
