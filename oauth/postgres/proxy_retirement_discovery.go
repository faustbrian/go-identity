package postgres

import (
	"context"
	"encoding/base64"
	"math"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

const proxyRetirementDiscoveryMaxScan = 32

// ProxyRetirementDiscoveryRequest selects one exact retained provider disable
// and a bounded scan of local custody. Use an empty AfterFlowID to start.
// ScanLimit counts visible custody rows, not matches, and must be in [1, 32].
type ProxyRetirementDiscoveryRequest struct {
	Disable     ProviderAuthorityChange
	AfterFlowID identity.PreAuthTransactionID
	ScanLimit   uint16
}

// ProxyRetirementOrigin identifies one authenticated original, not a grant
// or permission to retire it. Retirement independently authenticates custody.
type ProxyRetirementOrigin struct {
	OriginCommandID identity.CommandID
	FlowID          identity.PreAuthTransactionID
}

// ProxyRetirementDiscoveryPage lists matching originals in Origins.
// Continue with NextAfterFlowID even if Origins is empty: this trusted cursor
// can refer to a nonmatching row. An empty cursor ends this traversal, not
// the cascade: reads do not pin a snapshot or rule out late custody writers.
type ProxyRetirementDiscoveryPage struct {
	Origins         []ProxyRetirementOrigin
	Scanned         uint16
	NextAfterFlowID identity.PreAuthTransactionID
}

// ListDisabledProviderOrigins discovers exact production origins in one tenant
// after authenticating a retained disable. It makes no provider calls or writes.
func (s *ProxyForwardService) ListDisabledProviderOrigins(ctx context.Context, authority *ProxyRetirementAuthority, r ProxyRetirementDiscoveryRequest) (ProxyRetirementDiscoveryPage, error) {
	if s == nil || s.pool == nil || s.providerAuthority == nil {
		return ProxyRetirementDiscoveryPage{}, identity.ForbiddenError{}
	}
	c := s.config
	read := proxyRetirementDiscovery{
		pool: s.pool, envelopes: s.envelopes, timeout: c.MaximumDuration, production: c.ProductionDeployment,
		schema: c.Schema, kind: kernel.OAuthProxyRetireProduction,
		statement: productionRetirementDiscoverySQL(rpQuotedSchema(c.Schema) + ".proxy_transactions"),
	}
	return read.page(ctx, authority, r)
}

// ListDisabledProviderOrigins discovers exact origins in the configured
// preview tenant. Its audit authorization and local custody read are separate;
// it does not create sessions, change either database, or acknowledge a cascade.
func (s *ProxyPreviewService) ListDisabledProviderOrigins(ctx context.Context, authority *ProxyRetirementAuthority, r ProxyRetirementDiscoveryRequest) (ProxyRetirementDiscoveryPage, error) {
	if s == nil || s.signin == nil || s.signin.start == nil || s.authority == nil || r.Disable.Key.TenantID != s.config.TenantID {
		return ProxyRetirementDiscoveryPage{}, identity.ForbiddenError{}
	}
	start := s.signin.start
	read := proxyRetirementDiscovery{
		pool: start.pool, envelopes: start.envelopes, timeout: start.config.MaximumDuration,
		production: s.config.ProductionDeployment, preview: s.config.Target.Deployment,
		schema: start.config.Schema, kind: kernel.OAuthProxyRetirePreview,
		statement: previewRetirementDiscoverySQL(rpQuotedSchema(start.config.Schema) + ".proxy_preview_bindings"),
	}
	return read.page(ctx, authority, r)
}

type proxyRetirementDiscovery struct {
	pool       *database.Pool
	envelopes  *envelope.Service
	timeout    time.Duration
	production string
	preview    string
	schema     string
	kind       kernel.OAuthProxyRetirementKind
	statement  string
}

type proxyRetirementDiscoveryRow struct {
	flow, version, production, provider, callbackURI, profile string
	origin, callback, digest, binding                         []byte
	stateKey                                                  int64
	issued, expires                                           time.Time
}

func validateProxyRetirementDiscoveryRequest(r ProxyRetirementDiscoveryRequest) error {
	if r.ScanLimit == 0 || r.ScanLimit > proxyRetirementDiscoveryMaxScan {
		return identity.InvalidInputError{Field: "oauth_proxy_retirement_scan_limit"}
	}
	if r.AfterFlowID != "" {
		if _, err := identity.ParsePreAuthTransactionID(string(r.AfterFlowID)); err != nil {
			return identity.InvalidInputError{Field: "oauth_proxy_retirement_cursor"}
		}
	}
	return nil
}

func (d proxyRetirementDiscovery) page(ctx context.Context, authority *ProxyRetirementAuthority, r ProxyRetirementDiscoveryRequest) (ProxyRetirementDiscoveryPage, error) {
	if ctx == nil || !authority.selected() || d.pool == nil || d.pool.Raw() == nil || d.envelopes == nil {
		return ProxyRetirementDiscoveryPage{}, identity.ForbiddenError{}
	}
	if err := validateProxyRetirementDiscoveryRequest(r); err != nil {
		return ProxyRetirementDiscoveryPage{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	if err := authority.authenticate(ctx, d.pool, d.schema, d.kind, r.Disable); err != nil {
		return ProxyRetirementDiscoveryPage{}, err
	}

	n := int(r.ScanLimit)
	rows, err := d.readRows(ctx, r, n+1)
	defer func() {
		for i := range rows {
			clear(rows[i].binding)
		}
	}()
	if err != nil {
		return ProxyRetirementDiscoveryPage{}, providerAuthorityFailure(ctx)
	}

	scanned := min(n, len(rows))
	page := ProxyRetirementDiscoveryPage{Scanned: uint16(scanned)}
	for i := 0; i < scanned; i++ {
		row := &rows[i]
		flow, err := identity.ParsePreAuthTransactionID(row.flow)
		if err != nil {
			return ProxyRetirementDiscoveryPage{}, providerAuthorityFailure(ctx)
		}
		if i == n-1 && len(rows) > n {
			page.NextAfterFlowID = flow
		}
		origin, match, err := d.match(ctx, r.Disable, flow, row)
		if err != nil {
			return ProxyRetirementDiscoveryPage{}, providerAuthorityFailure(ctx)
		}
		if match {
			page.Origins = append(page.Origins, origin)
		}
	}
	if err := ctx.Err(); err != nil {
		return ProxyRetirementDiscoveryPage{}, err
	}
	return page, nil
}

// Do not filter provider, epoch or version in SQL; doing so could scan all
// remaining keys before the LIMIT. The lookahead consumes one additional row,
// never another decryption. These queries select no bearer custody columns.
func productionRetirementDiscoverySQL(table string) string {
	return `SELECT transaction_id,version::text,origin_command_id,callback_command_id,
 production_deployment,provider_id,production_callback_uri,configuration_version::text,
 state_key_version,state_lookup_digest,issued_at,expires_at,CASE WHEN version IN (1,2) THEN binding_ciphertext END
 FROM ` + table + ` WHERE tenant_id=$1 AND transaction_id>$2 ORDER BY transaction_id LIMIT $3`
}

func previewRetirementDiscoverySQL(table string) string {
	return `SELECT flow_id,version::text,origin_command_id,callback_command_id,issued_at,expires_at,
 CASE WHEN version IN (1,2) THEN binding_ciphertext END
 FROM ` + table + ` WHERE tenant_id=$1 AND flow_id>$2 ORDER BY flow_id LIMIT $3`
}

func (d proxyRetirementDiscovery) readRows(ctx context.Context, r ProxyRetirementDiscoveryRequest, limit int) ([]proxyRetirementDiscoveryRow, error) {
	rows, err := d.pool.Raw().Query(ctx, d.statement, string(r.Disable.Key.TenantID), string(r.AfterFlowID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	data := make([]proxyRetirementDiscoveryRow, 0, limit)
	for rows.Next() {
		data = append(data, proxyRetirementDiscoveryRow{})
		if err := data[len(data)-1].scan(rows, d.preview != ""); err != nil {
			return data, err
		}
	}
	return data, rows.Err()
}

func (r *proxyRetirementDiscoveryRow) scan(rows pgx.Rows, preview bool) error {
	if preview {
		return rows.Scan(&r.flow, &r.version, &r.origin, &r.callback, &r.issued, &r.expires, &r.binding)
	}
	return rows.Scan(&r.flow, &r.version, &r.origin, &r.callback, &r.production, &r.provider, &r.callbackURI,
		&r.profile, &r.stateKey, &r.digest, &r.issued, &r.expires, &r.binding)
}

func (d proxyRetirementDiscovery) match(ctx context.Context, disable ProviderAuthorityChange, flow identity.PreAuthTransactionID, row *proxyRetirementDiscoveryRow) (ProxyRetirementOrigin, bool, error) {
	switch row.version {
	case "3":
		return ProxyRetirementOrigin{}, false, nil
	case "1", "2":
	default:
		return ProxyRetirementOrigin{}, false, identity.UnavailableError{}
	}
	if d.preview == "" && (row.production != d.production || row.provider != disable.Key.ProviderID) {
		return ProxyRetirementOrigin{}, false, nil
	}
	origin := identity.CommandID(base64.RawURLEncoding.EncodeToString(row.origin))
	callback := identity.CommandID(base64.RawURLEncoding.EncodeToString(row.callback))
	target := ProxyRetirementOrigin{OriginCommandID: origin, FlowID: flow}
	if d.preview != "" {
		locator := proxyPreviewBindingLocator{
			Tenant: disable.Key.TenantID, Flow: flow, OriginCommand: origin, CallbackCommand: callback,
			IssuedAt: row.issued.UTC(), ExpiresAt: row.expires.UTC(),
		}
		stored, _, err := openProxyPreviewBinding(ctx, d.envelopes, locator, row.binding)
		if err != nil {
			return ProxyRetirementOrigin{}, false, err
		}
		return target, stored.Evidence.ProductionDeployment == d.production && stored.Evidence.PreviewDeployment == d.preview &&
			proxyProviderDisableCoversOriginal(disable, stored.Evidence), nil
	}
	profile, err := strconv.ParseUint(row.profile, 10, 64)
	if err != nil || row.stateKey < 1 || row.stateKey > math.MaxUint32 || len(row.digest) != 32 {
		return ProxyRetirementOrigin{}, false, identity.UnavailableError{}
	}
	locator := proxyBindingLocator{
		Tenant: disable.Key.TenantID, Transaction: flow, OriginCommand: origin, CallbackCommand: callback,
		Production: row.production, Provider: row.provider, CallbackURI: row.callbackURI, ProviderVersion: profile,
		StateKeyVersion: uint32(row.stateKey), LookupDigest: [32]byte(row.digest), IssuedAt: row.issued.UTC(), ExpiresAt: row.expires.UTC(),
	}
	stored, err := openProxyOriginalBinding(ctx, d.envelopes, locator, row.binding)
	if err != nil {
		return ProxyRetirementOrigin{}, false, err
	}
	return target, proxyProviderDisableCoversOriginal(disable, stored.Evidence), nil
}
