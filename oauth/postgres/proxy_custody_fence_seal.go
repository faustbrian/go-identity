package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ProxyCustodyFenceOperatorConfig pins one local custody origin, its tenant
// and the actor whose durable provider-primary admissions it trusts.
type ProxyCustodyFenceOperatorConfig struct {
	Schema          string
	Kind            kernel.OAuthProxyRetirementKind
	TenantID        identity.TenantID
	ActorID         identity.ActorID
	MaximumDuration time.Duration
}

// ProxyCustodyFenceSealRequest identifies the pending admission to reread.
// Callers cannot supply a cutoff, provider, manifest or authority epoch.
type ProxyCustodyFenceSealRequest struct {
	TenantID        identity.TenantID
	SourceCommandID identity.CommandID
	CascadeID       identity.CascadeID
	Generation      uint64
}

// ProxyCustodyFenceSeal is the acknowledged local cutoff for one verified
// source. DeniedThrough may be newer if a later disable already sealed.
// This is not a scan checkpoint or a cleanup acknowledgement.
type ProxyCustodyFenceSeal struct {
	TenantID        identity.TenantID
	SourceCommandID identity.CommandID
	CascadeID       identity.CascadeID
	Generation      uint64
	Kind            kernel.OAuthProxyRetirementKind
	ProviderID      string
	DeniedThrough   uint64
}

// ProxyCustodyFenceOperator borrows separate pools for the read-only
// designated provider primary and the privileged local fence mutation.
// Keep both outside callback service composition.
type ProxyCustodyFenceOperator struct {
	local                *database.Pool
	primary              *ProviderAuthority
	config               ProxyCustodyFenceOperatorConfig
	custody, fence, gate string
}

// NewProxyCustodyFenceOperator validates trusted selection without I/O.
// The local role reads and mutates only its fence table, not custody; the
// provider-primary role needs SELECT on the durable admission table.
func NewProxyCustodyFenceOperator(local *database.Pool, primary *ProviderAuthority, c ProxyCustodyFenceOperatorConfig) (*ProxyCustodyFenceOperator, error) {
	custody, fence, role := proxyCustodyFenceStorage(c.Kind)
	if local == nil || local.Raw() == nil || primary == nil || primary.pool == nil || primary.pool.Raw() == nil ||
		local.Raw() == primary.pool.Raw() || role == "" || !providerAuthoritySchema(c.Schema) ||
		!rpDirectoryID(string(c.TenantID)) || !rpDirectoryID(string(c.ActorID)) ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > proxyAuthorityLifetime {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_custody_fence_operator"}
	}
	return &ProxyCustodyFenceOperator{local: local, primary: primary, config: c, custody: custody,
		fence: rpQuotedSchema(c.Schema) + "." + fence, gate: "enforce_proxy_" + role + "_write_fence"}, nil
}

func validateProxyCustodyFenceSealRequest(r ProxyCustodyFenceSealRequest) error {
	_, commandErr := identity.ParseCommandID(string(r.SourceCommandID))
	_, cascadeErr := identity.ParseCascadeID(string(r.CascadeID))
	if !rpDirectoryID(string(r.TenantID)) || r.Generation != 1 || commandErr != nil || cascadeErr != nil {
		return identity.InvalidInputError{Field: "oauth_proxy_custody_fence_source"}
	}
	return nil
}

// SealAdmittedProviderDisable verifies the exact durable admission on the
// configured primary before acquiring any local lock. It advances the cutoff
// only on the selected origin with an activated writer gate; older retries
// never lower it. Re-enable does not invalidate historical admission. Retry
// an unknown commit using exactly the same selector. This does not complete
// a drain or acknowledge any lifecycle consumer.
func (o *ProxyCustodyFenceOperator) SealAdmittedProviderDisable(ctx context.Context, r ProxyCustodyFenceSealRequest) (ProxyCustodyFenceSeal, error) {
	if o == nil || o.local == nil || o.primary == nil || ctx == nil {
		return ProxyCustodyFenceSeal{}, identity.ForbiddenError{}
	}
	if err := validateProxyCustodyFenceSealRequest(r); err != nil {
		return ProxyCustodyFenceSeal{}, err
	}
	if r.TenantID != o.config.TenantID {
		return ProxyCustodyFenceSeal{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, o.config.MaximumDuration)
	defer stop()
	source, err := o.authoritativeDisable(ctx, r)
	if err != nil {
		return ProxyCustodyFenceSeal{}, err
	}
	floor, err := o.sealLocal(ctx, source)
	if err != nil {
		return ProxyCustodyFenceSeal{}, err
	}
	return ProxyCustodyFenceSeal{TenantID: r.TenantID, SourceCommandID: r.SourceCommandID, CascadeID: source.CascadeID,
		Generation: source.Generation, Kind: o.config.Kind, ProviderID: source.Disable.Key.ProviderID, DeniedThrough: floor}, nil
}

func (o *ProxyCustodyFenceOperator) authoritativeDisable(ctx context.Context, r ProxyCustodyFenceSealRequest) (ProviderDisableAdmission, error) {
	ctx, stop := context.WithTimeout(ctx, o.primary.timeout)
	defer stop()
	row := o.primary.pool.Raw().QueryRow(ctx, providerDisableCascadeReadSQL(o.primary.cascadeTable), string(r.TenantID), string(r.SourceCommandID))
	admission, err := decodeProviderDisableAdmission(ctx, row, r.TenantID, r.SourceCommandID, o.config.ActorID)
	if err != nil {
		return ProviderDisableAdmission{}, err
	}
	if admission.CascadeID != r.CascadeID || admission.Generation != r.Generation {
		return ProviderDisableAdmission{}, identity.ForbiddenError{}
	}
	return admission, nil
}

// Inspect the ordinary, initially deferred AFTER INSERT ROW gate (tgtype=5)
// on the exact selected relation. Migration and DDL privileges stay separate.
const proxyCustodyFenceActiveSQL = `SELECT EXISTS (
 SELECT 1 FROM pg_catalog.pg_trigger t
 JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
 JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
 WHERE t.tgrelid=pg_catalog.to_regclass($1) AND t.tgname='proxy_custody_write_fence'
 AND NOT t.tgisinternal AND t.tgenabled IN ('O','A') AND t.tgtype=5
 AND t.tgdeferrable AND t.tginitdeferred AND t.tgqual IS NULL
 AND p.pronamespace=c.relnamespace AND p.proname=$2 AND p.provolatile='v' AND NOT p.prosecdef
)`

const proxyCustodyFenceExclusiveSQL = `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
 pg_catalog.jsonb_build_array('identity.oauth.proxy.custody-fence.v1', $1::text,$2::text,$3::text,$4::text)::text,0))`

func proxyCustodyFenceAdvanceSQL(table string) string {
	return `INSERT INTO ` + table + ` AS fence(tenant_id,provider_id,denied_through)
 VALUES($1,$2,$3::numeric) ON CONFLICT(tenant_id,provider_id) DO UPDATE
 SET denied_through=EXCLUDED.denied_through WHERE fence.denied_through<EXCLUDED.denied_through
 RETURNING denied_through::text`
}

func proxyCustodyFenceFloorSQL(table string) string {
	return `SELECT denied_through::text FROM ` + table + ` WHERE tenant_id=$1 AND provider_id=$2`
}

func (o *ProxyCustodyFenceOperator) sealLocal(ctx context.Context, source ProviderDisableAdmission) (uint64, error) {
	tx, err := o.local.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, providerAuthorityFailure(ctx)
	}
	defer rollbackProviderAuthority(tx)
	var active bool
	c := o.config
	if err := tx.QueryRow(ctx, proxyCustodyFenceActiveSQL, rpQuotedSchema(c.Schema)+"."+o.custody, o.gate).Scan(&active); err != nil {
		return 0, providerAuthorityFailure(ctx)
	}
	if !active {
		return 0, identity.ForbiddenError{}
	}
	tenant, provider := string(source.Disable.Key.TenantID), source.Disable.Key.ProviderID
	if _, err := tx.Exec(ctx, proxyCustodyFenceExclusiveSQL, c.Schema, o.custody, tenant, provider); err != nil {
		return 0, providerAuthorityFailure(ctx)
	}
	var observed string
	cutoff := source.Disable.ExpectedVersion
	err = tx.QueryRow(ctx, proxyCustodyFenceAdvanceSQL(o.fence), tenant, provider, providerAuthorityVersion(cutoff)).Scan(&observed)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, proxyCustodyFenceFloorSQL(o.fence), tenant, provider).Scan(&observed)
	}
	floor, parseErr := strconv.ParseUint(observed, 10, 64)
	if err != nil || parseErr != nil || floor < cutoff || ctx.Err() != nil {
		return 0, providerAuthorityFailure(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, pgx.ErrTxCommitRollback) {
			return 0, identity.UnavailableError{}
		}
		return 0, identity.UnknownCommitError{CommandID: source.Disable.CommandID}
	}
	return floor, nil
}
