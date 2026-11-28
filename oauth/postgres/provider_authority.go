package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	outbox "github.com/faustbrian/go-transactional-outbox/v2"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	providerAuthorityRecordPrefix = "oauth-provider-authority:"
	providerAuthorityDisableAudit = "identity.oauth.provider.disable"
)

// ProviderAuthorityKey identifies one social-provider connection. ProviderID
// is the registered configuration ID, never an issuer or user-supplied URL.
type ProviderAuthorityKey struct {
	TenantID   identity.TenantID
	ProviderID string
}

// ProviderAuthorityState is one current primary observation, not a cache
// entry or an authorization lease. Zero is unavailable, never enabled.
type ProviderAuthorityState struct {
	Version        uint64 // Live connection epoch; always advances on change.
	ProfileVersion uint64 // Immutable protocol configuration selected by that epoch.
	Enabled        bool
}

// ProviderAuthorityChange is a trusted operator command. Register with an
// expected version of zero and a positive enabled configuration. Subsequent
// changes require the exact current version and a strictly newer version.
type ProviderAuthorityChange struct {
	Key             ProviderAuthorityKey
	ExpectedVersion uint64
	Next            ProviderAuthorityState
	CommandID       identity.CommandID
}

// ProviderAuthority reads the generic connection record from its shared
// primary. Runtime readers need SELECT only and should use a different pool
// role from the operator. The caller owns the pool and its lifecycle.
type ProviderAuthority struct {
	pool            *database.Pool
	table           string
	cascadeTable    string
	proxyPairsTable string
	timeout         time.Duration
}

func NewProviderAuthority(pool *database.Pool, schema string, timeout time.Duration) (*ProviderAuthority, error) {
	if pool == nil || pool.Raw() == nil || !providerAuthoritySchema(schema) || timeout < time.Millisecond || timeout > 20*time.Second {
		return nil, providerAuthorityInvalid()
	}
	namespace := rpQuotedSchema(schema)
	return &ProviderAuthority{pool: pool, table: namespace + `.provider_authorities`,
		cascadeTable: namespace + ".provider_disable_cascades", proxyPairsTable: namespace + ".provider_disable_proxy_pairs", timeout: timeout}, nil
}

// Current reads the exact tenant/connection without a positive cache. A
// missing registration denies. Read failure returns no state.
func (a *ProviderAuthority) Current(ctx context.Context, key ProviderAuthorityKey) (ProviderAuthorityState, error) {
	if a == nil || a.pool == nil || ctx == nil || !validProviderAuthorityKey(key) {
		return ProviderAuthorityState{}, providerAuthorityInvalid()
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var raw, profileRaw string
	var enabled bool
	err := a.pool.Raw().QueryRow(ctx, a.currentQuery(), string(key.TenantID), key.ProviderID).Scan(&raw, &profileRaw, &enabled)
	if ctx.Err() != nil {
		return ProviderAuthorityState{}, ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderAuthorityState{}, identity.ForbiddenError{}
	}
	version, parseErr := strconv.ParseUint(raw, 10, 64)
	profileVersion, profileErr := strconv.ParseUint(profileRaw, 10, 64)
	if err != nil || parseErr != nil || profileErr != nil || version == 0 || profileVersion == 0 {
		return ProviderAuthorityState{}, identity.UnavailableError{}
	}
	return ProviderAuthorityState{Version: version, ProfileVersion: profileVersion, Enabled: enabled}, nil
}

// ProviderAuthorityOperator borrows a separately authorized primary role.
// This is a trusted deployment capability, not a request authorization or
// HTTP administration service. It stages audit and the existing outbox in
// the same transaction as the connection authority change.
type ProviderAuthorityOperator struct {
	authority *ProviderAuthority
	actor     identity.ActorID
	redactor  audit.Redactor
	outbox    *outboxpg.Writer
}

func NewProviderAuthorityOperator(authority *ProviderAuthority, actor identity.ActorID) (*ProviderAuthorityOperator, error) {
	if authority == nil || authority.pool == nil || !rpDirectoryID(string(actor)) {
		return nil, providerAuthorityInvalid()
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true,
		AllowedAttributes: []string{"connection.previous_version", "connection.version", "connection.profile_version"}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	writer, err := outboxpg.NewWriter(outboxpg.WriterConfig{MaxBatchSize: 1})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return &ProviderAuthorityOperator{authority: authority, actor: actor, redactor: redactor, outbox: writer}, nil
}

// Apply advances one current connection. An exact retry of the latest
// command is side-effect-free; superseded or conflicting commands cannot
// repeat or restore old authority. If commit is ambiguous, read current
// authority or retry the exact command; never infer it from the error.
func (o *ProviderAuthorityOperator) Apply(ctx context.Context, c ProviderAuthorityChange) (ProviderAuthorityState, error) {
	return o.apply(ctx, c, nil)
}

func (o *ProviderAuthorityOperator) apply(ctx context.Context, c ProviderAuthorityChange, cascade *providerDisableCascadeSelection) (ProviderAuthorityState, error) {
	if o == nil || o.authority == nil || ctx == nil || !validProviderAuthorityKey(c.Key) ||
		c.Next.Version <= c.ExpectedVersion || c.Next.ProfileVersion == 0 || c.ExpectedVersion == 0 && !c.Next.Enabled {
		return ProviderAuthorityState{}, providerAuthorityInvalid()
	}
	if _, err := identity.ParseCommandID(string(c.CommandID)); err != nil {
		return ProviderAuthorityState{}, providerAuthorityInvalid()
	}
	a := o.authority
	ctx, stop := context.WithTimeout(ctx, a.timeout)
	defer stop()
	tx, err := a.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ProviderAuthorityState{}, providerAuthorityFailure(ctx)
	}
	defer rollbackProviderAuthority(tx)

	if cascade != nil {
		stored, err := o.readDisableCascade(ctx, tx, c, cascade)
		if err != nil {
			return ProviderAuthorityState{}, err
		}
		if stored.CascadeID != "" {
			cascade.admission = stored
			return c.Next, nil
		}
	}
	acceptedAt, err := o.advance(ctx, tx, c)
	var conflict identity.ConflictError
	if cascade != nil && (err == nil && acceptedAt.IsZero() || errors.As(err, &conflict)) {
		// A concurrent exact command can commit between the first read and
		// the authority CAS. Read its immutable generation, not current state.
		stored, readErr := o.readDisableCascade(ctx, tx, c, cascade)
		if readErr != nil {
			return ProviderAuthorityState{}, readErr
		}
		if stored.CascadeID == "" {
			// Never backfill a legacy disable or convert a stale command.
			return ProviderAuthorityState{}, identity.ConflictError{}
		}
		cascade.admission = stored
		return c.Next, nil
	}
	if err != nil {
		return ProviderAuthorityState{}, err
	}
	if err := ctx.Err(); err != nil {
		return ProviderAuthorityState{}, err
	}
	if acceptedAt.IsZero() { // The existing state was an exact replay.
		return c.Next, nil
	}
	if cascade != nil {
		cascade.admission, err = o.stageDisableCascade(ctx, tx, c, acceptedAt, cascade.window)
		if err != nil {
			return ProviderAuthorityState{}, err
		}
		if cascade.proxyPair != nil {
			if err := stageProxyDisablePair(ctx, tx, a.proxyPairsTable, cascade.admission, *cascade.proxyPair); err != nil {
				return ProviderAuthorityState{}, err
			}
		}
	}
	if err := o.stage(ctx, tx, c, acceptedAt); err != nil {
		return ProviderAuthorityState{}, err
	}
	if err := ctx.Err(); err != nil {
		return ProviderAuthorityState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, pgx.ErrTxCommitRollback) {
			return ProviderAuthorityState{}, identity.UnavailableError{}
		}
		return ProviderAuthorityState{}, identity.UnknownCommitError{CommandID: c.CommandID}
	}
	return c.Next, nil
}

func (o *ProviderAuthorityOperator) advance(ctx context.Context, tx pgx.Tx, c ProviderAuthorityChange) (time.Time, error) {
	a := o.authority
	tenant, provider := string(c.Key.TenantID), c.Key.ProviderID
	expected, next := strconv.FormatUint(c.ExpectedVersion, 10), strconv.FormatUint(c.Next.Version, 10)
	profile := strconv.FormatUint(c.Next.ProfileVersion, 10)
	command, actor := string(c.CommandID), string(o.actor)
	sql := a.advanceQuery()
	if c.ExpectedVersion == 0 {
		sql = a.registerQuery()
	}
	var acceptedAt time.Time
	err := tx.QueryRow(ctx, sql, tenant, provider, providerAuthorityVersion(c.Next.Version), c.Next.Enabled,
		providerAuthorityVersion(c.ExpectedVersion), command, actor, providerAuthorityVersion(c.Next.ProfileVersion)).Scan(&acceptedAt)
	if err == nil && !acceptedAt.IsZero() {
		return acceptedAt.UTC(), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, providerAuthorityFailure(ctx)
	}
	var previous, version, seenCommand, seenActor, seenProfile string
	var enabled bool
	err = tx.QueryRow(ctx, a.replayQuery(), tenant, provider).Scan(&previous, &version, &enabled, &seenCommand, &seenActor, &seenProfile)
	if err == nil && previous == expected && version == next && seenProfile == profile && enabled == c.Next.Enabled && seenCommand == command && seenActor == actor {
		return time.Time{}, nil
	}
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, identity.ConflictError{}
	}
	return time.Time{}, providerAuthorityFailure(ctx)
}

func (a *ProviderAuthority) currentQuery() string {
	return `SELECT version::text,profile_version::text,enabled FROM ` + a.table + ` WHERE tenant_id=$1 AND provider_id=$2`
}

func (a *ProviderAuthority) replayQuery() string {
	return `SELECT previous_version::text,version::text,enabled,command_id,command_actor,profile_version::text FROM ` + a.table + ` WHERE tenant_id=$1 AND provider_id=$2`
}

func (a *ProviderAuthority) advanceQuery() string {
	return `UPDATE ` + a.table + ` SET version=$3::numeric,enabled=$4,previous_version=$5::numeric,command_id=$6,command_actor=$7,profile_version=$8::numeric
 WHERE tenant_id=$1 AND provider_id=$2 AND version=$5::numeric AND command_id<>$6
 AND (($4 AND profile_version<=$8::numeric) OR (NOT $4 AND enabled AND profile_version=$8::numeric)) RETURNING clock_timestamp()`
}

func (a *ProviderAuthority) registerQuery() string {
	return `INSERT INTO ` + a.table + `(tenant_id,provider_id,version,enabled,previous_version,command_id,command_actor,profile_version)
 VALUES($1,$2,$3::numeric,$4,$5::numeric,$6,$7,$8::numeric) ON CONFLICT (tenant_id,provider_id) DO NOTHING RETURNING clock_timestamp()`
}

func (o *ProviderAuthorityOperator) stage(ctx context.Context, tx pgx.Tx, c ProviderAuthorityChange, now time.Time) error {
	action, topic := "identity.oauth.provider.configure", "social_provider.configuration_changed.v1"
	if !c.Next.Enabled {
		action, topic = providerAuthorityDisableAudit, providerDisableCascadeTopic
	}
	command, tenant := string(c.CommandID), string(c.Key.TenantID)
	// The native audit store retains accepted record identities after payload
	// pruning. A duplicate effect must abort this transaction even when its
	// outbox message was already delivered and removed.
	builder, err := audit.NewBuilder(audit.BuilderConfig{Clock: func() time.Time { return now },
		IDGenerator: func() (string, error) { return providerAuthorityRecordPrefix + command, nil }})
	if err != nil {
		return identity.UnavailableError{}
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: action, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(o.actor)}, Subject: audit.SubjectInput{Type: "social_connection", ID: c.Key.ProviderID},
		Context: audit.ContextInput{TenantID: tenant, CorrelationID: command}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"connection.previous_version": strconv.FormatUint(c.ExpectedVersion, 10),
			"connection.version": strconv.FormatUint(c.Next.Version, 10), "connection.profile_version": strconv.FormatUint(c.Next.ProfileVersion, 10)}})
	if err != nil {
		return identity.UnavailableError{}
	}
	record, err = o.redactor.Redact(ctx, record)
	if err != nil {
		return providerAuthorityFailure(ctx)
	}
	auditor, err := auditpg.NewTx(tx, auditpg.Config{})
	if err != nil {
		return identity.UnavailableError{}
	}
	result, err := auditor.Stage(ctx, []audit.Record{record})
	if errors.Is(err, audit.ErrDuplicateConflict) {
		return identity.ConflictError{}
	}
	if err != nil {
		return providerAuthorityFailure(ctx)
	}
	if len(result.Results) != 1 || result.Results[0].Status != audit.AppendAccepted {
		return identity.ConflictError{}
	}
	payload, err := json.Marshal(struct {
		TenantID        string `json:"tenant_id"`
		ProviderID      string `json:"provider_id"`
		PreviousVersion uint64 `json:"previous_version"`
		Version         uint64 `json:"version"`
		ProfileVersion  uint64 `json:"profile_version"`
		Enabled         bool   `json:"enabled"`
	}{tenant, c.Key.ProviderID, c.ExpectedVersion, c.Next.Version, c.Next.ProfileVersion, c.Next.Enabled})
	if err != nil {
		return identity.UnavailableError{}
	}
	scope := sha256.Sum256([]byte(tenant + "\x00" + c.Key.ProviderID))
	if err := o.outbox.Insert(ctx, tx, outbox.Envelope{ID: command, Topic: topic, Payload: payload, PayloadVersion: 1,
		OrderingKey: hex.EncodeToString(scope[:]), IdempotencyKey: command, AvailableAt: now, CreatedAt: now}); err != nil {
		return providerAuthorityFailure(ctx)
	}
	return nil
}

func rollbackProviderAuthority(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func validProviderAuthorityKey(k ProviderAuthorityKey) bool {
	return rpDirectoryID(string(k.TenantID)) && rpProviderID(k.ProviderID)
}

func providerAuthorityInvalid() error {
	return identity.InvalidInputError{Field: "oauth_provider_authority"}
}

func providerAuthorityVersion(version uint64) pgtype.Numeric {
	return pgtype.Numeric{Int: new(big.Int).SetUint64(version), Valid: true}
}

func providerAuthorityFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.UnavailableError{}
}
