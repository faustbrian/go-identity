package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ProxyDisablePairAcknowledgement records cleanup for the selected production
// and preview pair only. It does not complete a provider cascade or report an
// external provider outcome.
type ProxyDisablePairAcknowledgement struct {
	TenantID                                identity.TenantID
	CascadeID                               identity.CascadeID
	Generation                              uint64
	SourceCommandID                         identity.CommandID
	ProductionDeployment, PreviewDeployment string
	Consumer                                ProviderDisableConsumer
	AcknowledgedAt                          time.Time
}

// ProxyDisablePairOperator borrows the matching singleton proxy composition
// and the existing provider disable owner. It owns no pools and mounts no HTTP
// route. Deployments with additional or historical custody origins must not
// interpret this selected-pair result as whole-consumer completion.
type ProxyDisablePairOperator struct {
	operator       *ProviderAuthorityOperator
	primary        *ProviderAuthority
	key            ProviderAuthorityKey
	scope          proxyDisablePairScope
	productionPool *database.Pool
	previewPool    *database.Pool
}

type proxyDisablePairScope struct {
	productionSchema, previewSchema         string
	productionDeployment, previewDeployment string
}

// NewProxyDisablePairOperator selects the matching live production and preview
// services and their shared provider-primary reader. Deployment names must
// continue to identify the same custody owners while an admission can be
// recovered. Install ProxyDisablePairMigrationSource before using this operator.
func NewProxyDisablePairOperator(operator *ProviderAuthorityOperator, production *ProxyStartService, preview *ProxyPreviewService) (*ProxyDisablePairOperator, error) {
	if operator == nil || operator.authority == nil || operator.authority.pool == nil ||
		production == nil || production.forward == nil || production.admission == nil ||
		preview == nil || preview.signin == nil || preview.signin.start == nil {
		return nil, invalidProxyDisablePair()
	}
	forward, start := production.forward, preview.signin.start
	primary := forward.providerAuthority
	if primary == nil || preview.authority != primary || primary.cascadeTable != operator.authority.cascadeTable ||
		!sameProxyDisablePairDatabase(primary.pool, operator.authority.pool) ||
		forward.pool == nil || start.pool == nil || forward.pool.Raw() == nil || start.pool.Raw() == nil ||
		sameProxyDisablePairDatabase(forward.pool, start.pool) {
		return nil, invalidProxyDisablePair()
	}
	if production.previewTenant != preview.config.TenantID || production.previewTarget != preview.config.Target ||
		forward.config.ProductionDeployment != preview.config.ProductionDeployment {
		return nil, invalidProxyDisablePair()
	}
	key := ProviderAuthorityKey{TenantID: production.previewTenant, ProviderID: production.profile.ID}
	previewProfile, registered := start.profiles[key.ProviderID]
	if !validProviderAuthorityKey(key) || !registered || previewProfile.Version != production.profile.Version ||
		previewProfile.Issuer != production.profile.Issuer || previewProfile.ClientID != production.profile.ClientID {
		return nil, invalidProxyDisablePair()
	}
	return &ProxyDisablePairOperator{
		operator: operator, primary: primary, key: key, productionPool: forward.pool, previewPool: start.pool,
		scope: proxyDisablePairScope{productionSchema: forward.config.Schema, previewSchema: start.config.Schema,
			productionDeployment: forward.config.ProductionDeployment, previewDeployment: preview.config.Target.Deployment},
	}, nil
}

func sameProxyDisablePairDatabase(a, b *database.Pool) bool {
	if a == nil || b == nil || a.Raw() == nil || b.Raw() == nil {
		return false
	}
	if a.Raw() == b.Raw() {
		return true
	}
	ac, bc := a.Raw().Config().ConnConfig, b.Raw().Config().ConnConfig
	return ac.Host == bc.Host && ac.Port == bc.Port && ac.Database == bc.Database
}

func invalidProxyDisablePair() error {
	return identity.InvalidInputError{Field: "oauth_proxy_disable_pair"}
}

// ApplyDisableCascade freezes the configured pair within the original disable
// transaction, including the existing audit and outbox. An exact retry requires
// the stored pair; a legacy admission cannot gain a pair retroactively.
func (p *ProxyDisablePairOperator) ApplyDisableCascade(ctx context.Context, change ProviderAuthorityChange, window time.Duration) (ProviderDisableAdmission, error) {
	if p == nil || p.operator == nil || ctx == nil || change.Key != p.key {
		return ProviderDisableAdmission{}, identity.ForbiddenError{}
	}
	return p.operator.applyDisableCascade(ctx, change, window, &p.scope)
}

// Acknowledge records the selected proxy consumer only after both actual local
// databases have an activated fence, sufficient cutoff and durable exhausted
// checkpoint for this exact admission. An absent/incomplete checkpoint returns
// conflict, without writing. After completion, retry returns the same persisted
// acknowledgement; it never repeats local cleanup or changes the cascade status.
func (p *ProxyDisablePairOperator) Acknowledge(ctx context.Context, source ProxyCustodyFenceSealRequest) (ProxyDisablePairAcknowledgement, error) {
	if p == nil || p.operator == nil || ctx == nil || source.TenantID != p.key.TenantID {
		return ProxyDisablePairAcknowledgement{}, identity.ForbiddenError{}
	}
	if err := validateProxyCustodyFenceSealRequest(source); err != nil {
		return ProxyDisablePairAcknowledgement{}, err
	}
	owner := p.operator.authority
	ctx, stop := context.WithTimeout(ctx, owner.timeout)
	defer stop()
	reader := ProxyCustodyFenceOperator{primary: p.primary, config: ProxyCustodyFenceOperatorConfig{ActorID: p.operator.actor}}
	admission, err := reader.authoritativeDisable(ctx, source)
	if err != nil {
		return ProxyDisablePairAcknowledgement{}, err
	}
	if admission.Disable.Key != p.key {
		return ProxyDisablePairAcknowledgement{}, identity.ForbiddenError{}
	}
	pool := owner.pool.Raw()
	at, err := readProxyDisablePair(ctx, pool, owner.proxyPairsTable, admission, p.scope)
	if err != nil {
		return ProxyDisablePairAcknowledgement{}, err
	}
	if at.IsZero() {
		if err := requireProxyDisablePairOrigin(ctx, p.productionPool, admission, kernel.OAuthProxyRetireProduction,
			p.scope.productionSchema, p.scope.productionDeployment); err != nil {
			return ProxyDisablePairAcknowledgement{}, err
		}
		if err := requireProxyDisablePairOrigin(ctx, p.previewPool, admission, kernel.OAuthProxyRetirePreview,
			p.scope.previewSchema, p.scope.previewDeployment); err != nil {
			return ProxyDisablePairAcknowledgement{}, err
		}
		at, err = confirmProxyDisablePair(ctx, pool, owner.proxyPairsTable, admission, p.scope)
		if err != nil {
			return ProxyDisablePairAcknowledgement{}, err
		}
	}
	return ProxyDisablePairAcknowledgement{
		TenantID: source.TenantID, CascadeID: source.CascadeID, Generation: source.Generation, SourceCommandID: source.SourceCommandID,
		ProductionDeployment: p.scope.productionDeployment, PreviewDeployment: p.scope.previewDeployment,
		Consumer: ProviderDisableConsumer{ID: providerDisableProxyConsumerID, ContractVersion: 1}, AcknowledgedAt: at,
	}, nil
}

func requireProxyDisablePairOrigin(ctx context.Context, pool *database.Pool, admission ProviderDisableAdmission,
	kind kernel.OAuthProxyRetirementKind, schema, deployment string) error {
	custody, fence, role := proxyCustodyFenceStorage(kind)
	namespace := rpQuotedSchema(schema)
	check := ProxyCustodyFenceOperator{config: ProxyCustodyFenceOperatorConfig{Schema: schema},
		custody: custody, fence: namespace + "." + fence, gate: "enforce_proxy_" + role + "_write_fence"}
	if err := check.requireLocalCutoff(ctx, pool, admission.Disable); err != nil {
		return err
	}
	store := proxyRetirementDrainStore{pool: pool.Raw(), table: namespace + ".proxy_retirement_drains",
		key: proxyRetirementDrainKey{source: admission, kind: kind, deployment: deployment}}
	state, err := store.read(ctx)
	if err != nil {
		return err
	}
	if !state.exhausted {
		return identity.ConflictError{}
	}
	return nil
}
