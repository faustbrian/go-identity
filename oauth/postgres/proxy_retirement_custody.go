package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type proxyCustodyErasure struct {
	statement string
	args      []any
	binding   []byte
}

type proxyCustodyRetirementState uint8

const (
	proxyCustodyReadyToRetire proxyCustodyRetirementState = iota + 1
	proxyCustodyAlreadyRetired
)

func (m proxyCustodyErasure) erase(ctx context.Context, w kernel.Work, scope kernel.OAuthProxyOriginRetirementScope) error {
	source, err := base64.RawURLEncoding.Strict().DecodeString(string(scope.SourceCommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, m.statement, append(m.args, source, strconv.FormatUint(scope.SourceVersion, 10))...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyRetirementPhase) authenticateCustody(ctx context.Context, w kernel.Work, scope kernel.OAuthProxyOriginRetirementScope, state proxyCustodyRetirementState) (proxyCustodyErasure, error) {
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(scope.OriginCommandID))
	if err != nil {
		return proxyCustodyErasure{}, identity.ForbiddenError{}
	}
	if p.kind == kernel.OAuthProxyRetireProduction {
		return p.authenticateProductionCustody(ctx, w, scope, origin, state)
	}
	if p.kind == kernel.OAuthProxyRetirePreview {
		return p.authenticatePreviewCustody(ctx, w, scope, origin, state)
	}
	return proxyCustodyErasure{}, identity.ForbiddenError{}
}

func productionRetirementQuery(table string) string {
	return `SELECT ` + productionRetirementColumns + ` FROM ` + table + `
 WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND production_deployment=$4 AND provider_id=$5 AND version IN (1,2)`
}

func productionRetiredCustodyQuery(table string) string {
	// Filter deployment/provider after the point lookup so a mismatch cannot
	// induce a scan of that deployment's provider index instead of the PK.
	return `WITH original AS MATERIALIZED (
 SELECT production_deployment,provider_id,` + productionRetirementColumns + ` FROM ` + table + `
 WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3
 AND version=3 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL
 AND handoff_ciphertext IS NULL AND ` + proxyRetiredProvenance + `
) SELECT ` + productionRetirementColumns + ` FROM original WHERE production_deployment=$4 AND provider_id=$5`
}

const productionRetirementColumns = `callback_command_id,production_callback_uri,configuration_version::text,state_key_version,state_lookup_digest,
 issued_at,expires_at,binding_ciphertext`

func productionRetirementMutation(table string) string {
	return `UPDATE ` + table + ` SET version=3,state_proof_ciphertext=NULL,pkce_ciphertext=NULL,handoff_ciphertext=NULL,
 retirement_source_command_id=$14,retirement_source_version=$15::numeric,retired_at=clock_timestamp()
 WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND production_deployment=$4 AND provider_id=$5
 AND callback_command_id=$6 AND production_callback_uri=$7 AND configuration_version=$8::numeric AND state_key_version=$9
 AND state_lookup_digest=$10 AND issued_at=$11 AND expires_at=$12 AND binding_ciphertext=$13 AND version IN (1,2)`
}

func (p *proxyRetirementPhase) authenticateProductionCustody(ctx context.Context, w kernel.Work, scope kernel.OAuthProxyOriginRetirementScope, origin []byte, state proxyCustodyRetirementState) (proxyCustodyErasure, error) {
	table := rpQuotedSchema(p.schema) + `.proxy_transactions`
	provider := p.request.Disable.Key.ProviderID
	args := []any{string(scope.TenantID), string(scope.FlowID), origin, p.production, provider}
	var callback, digest, binding []byte
	var callbackURI, profile string
	var stateKey int64
	var issued, expires time.Time
	statement := productionRetirementQuery(table)
	if state == proxyCustodyAlreadyRetired {
		statement = productionRetiredCustodyQuery(table)
	}
	err := readRetirementCustody(ctx, w, statement, args,
		&callback, &callbackURI, &profile, &stateKey, &digest, &issued, &expires, &binding)
	if err != nil {
		return proxyCustodyErasure{}, err
	}
	version, versionErr := strconv.ParseUint(profile, 10, 64)
	if versionErr != nil || stateKey < 1 || stateKey > 4294967295 || len(digest) != 32 {
		clear(binding)
		return proxyCustodyErasure{}, identity.ForbiddenError{}
	}
	locator := proxyBindingLocator{Tenant: scope.TenantID, Transaction: scope.FlowID, OriginCommand: scope.OriginCommandID,
		CallbackCommand: identity.CommandID(base64.RawURLEncoding.EncodeToString(callback)), Production: p.production, Provider: provider,
		CallbackURI: callbackURI, ProviderVersion: version, StateKeyVersion: uint32(stateKey), LookupDigest: [32]byte(digest), IssuedAt: issued.UTC(), ExpiresAt: expires.UTC()}
	stored, err := openProxyOriginalBinding(ctx, p.envelopes, locator, binding)
	if err != nil || !proxyProviderDisableCoversOriginal(p.request.Disable, stored.Evidence) {
		clear(binding)
		return proxyCustodyErasure{}, providerRetirementCustodyDenial(ctx)
	}
	if state == proxyCustodyAlreadyRetired {
		return proxyCustodyErasure{binding: binding}, nil
	}
	args = append(args, callback, callbackURI, profile, stateKey, digest, issued.UTC(), expires.UTC(), binding)
	return proxyCustodyErasure{statement: productionRetirementMutation(table), args: args, binding: binding}, nil
}

func previewRetirementQuery(table string) string {
	return previewRetirementLookup(table) + ` AND version IN (1,2)`
}

func previewRetiredCustodyQuery(table string) string {
	return previewRetirementLookup(table) + ` AND version=3 AND proof_ciphertext IS NULL AND ` + proxyRetiredProvenance
}

func previewRetirementLookup(table string) string {
	return `SELECT callback_command_id,issued_at,expires_at,binding_ciphertext FROM ` + table + `
 WHERE tenant_id=$1 AND flow_id=$2 AND origin_command_id=$3`
}

func previewRetirementMutation(table string) string {
	return `UPDATE ` + table + ` SET version=3,proof_ciphertext=NULL,
 retirement_source_command_id=$8,retirement_source_version=$9::numeric,retired_at=clock_timestamp()
 WHERE tenant_id=$1 AND flow_id=$2 AND origin_command_id=$3 AND callback_command_id=$4
 AND issued_at=$5 AND expires_at=$6 AND binding_ciphertext=$7 AND version IN (1,2)`
}

func (p *proxyRetirementPhase) authenticatePreviewCustody(ctx context.Context, w kernel.Work, scope kernel.OAuthProxyOriginRetirementScope, origin []byte, state proxyCustodyRetirementState) (proxyCustodyErasure, error) {
	table := rpQuotedSchema(p.schema) + `.proxy_preview_bindings`
	args := []any{string(scope.TenantID), string(scope.FlowID), origin}
	var callback, binding []byte
	var issued, expires time.Time
	statement := previewRetirementQuery(table)
	if state == proxyCustodyAlreadyRetired {
		statement = previewRetiredCustodyQuery(table)
	}
	if err := readRetirementCustody(ctx, w, statement, args, &callback, &issued, &expires, &binding); err != nil {
		return proxyCustodyErasure{}, err
	}
	locator := proxyPreviewBindingLocator{Tenant: scope.TenantID, Flow: scope.FlowID, OriginCommand: scope.OriginCommandID,
		CallbackCommand: identity.CommandID(base64.RawURLEncoding.EncodeToString(callback)), IssuedAt: issued.UTC(), ExpiresAt: expires.UTC()}
	stored, _, err := openProxyPreviewBinding(ctx, p.envelopes, locator, binding)
	if err != nil || stored.Evidence.ProductionDeployment != p.production || stored.Evidence.PreviewDeployment != p.preview ||
		!proxyProviderDisableCoversOriginal(p.request.Disable, stored.Evidence) {
		clear(binding)
		return proxyCustodyErasure{}, providerRetirementCustodyDenial(ctx)
	}
	if state == proxyCustodyAlreadyRetired {
		return proxyCustodyErasure{binding: binding}, nil
	}
	args = append(args, callback, issued.UTC(), expires.UTC(), binding)
	return proxyCustodyErasure{statement: previewRetirementMutation(table), args: args, binding: binding}, nil
}

// There is one exact primary-key lookup. Neither role reads bearer columns or
// uses expiry as proof that an original grant is absent.
func readRetirementCustody(ctx context.Context, w kernel.Work, statement string, args []any, dest ...any) error {
	rows, err := w.Query(ctx, statement, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	if err := rows.Scan(dest...); err != nil {
		return err
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	return rows.Err()
}

func providerRetirementCustodyDenial(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.ForbiddenError{}
}
