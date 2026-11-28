package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// OAuthProxyMaintenanceConfiguration borrows the trusted provider operator and
// the two local roles permitted to advance custody fences. Each fence pool
// must target the same database as its corresponding configured custody owner.
// Pools and operator remain caller-owned.
type OAuthProxyMaintenanceConfiguration struct {
	Operator                              *oauthpg.ProviderAuthorityOperator
	ActorID                               identity.ActorID
	ProductionFencePool, PreviewFencePool *database.Pool
	MaximumDuration                       time.Duration
}

// OAuthProxyMaintenance operates on one selected Reference proxy pair. It
// mounts no endpoint and keeps no journal apart from the native owners.
type OAuthProxyMaintenance struct {
	state                         *storeState
	pair                          *oauthpg.ProxyDisablePairOperator
	production                    *oauthpg.ProxyForwardService
	preview                       *oauthpg.ProxyPreviewService
	productionFence, previewFence *oauthpg.ProxyCustodyFenceOperator
}

func invalidOAuthProxyMaintenance() error {
	return identity.InvalidInputError{Field: "reference_oauth_proxy_maintenance"}
}

// NewOAuthProxyMaintenance borrows the two explicitly selected fenced owners
// and the matching operator. No database work runs during construction. Call
// only against the expanded histories; sealing also requires active fences.
func (f FeatureSet) NewOAuthProxyMaintenance(production *OAuthProxyProduction, c OAuthProxyMaintenanceConfiguration) (*OAuthProxyMaintenance, error) {
	if f.state == nil || !f.state.proxyMaintenance.valid() || f.state.features == nil || production == nil ||
		production.maintenanceSchema == "" || production.providerAuthority == nil || c.Operator == nil {
		return nil, invalidOAuthProxyMaintenance()
	}
	preview := f.state.features.oauthProxyPreview
	if preview == nil || preview.owner == nil || f.state.features.socialOAuth == nil ||
		sameProxyDatabase(production.pool, f.state.pool) || !matchingProxyProduction(preview, production) ||
		!validProxyFencePool(c.ProductionFencePool, production.pool) || !validProxyFencePool(c.PreviewFencePool, f.state.pool) {
		return nil, invalidOAuthProxyMaintenance()
	}
	pair, err := oauthpg.NewProxyDisablePairOperator(c.Operator, production.start, preview.owner)
	if err != nil {
		return nil, err
	}
	scope := oauthpg.ProxyCustodyFenceOperatorConfig{Schema: production.maintenanceSchema, Kind: kernel.OAuthProxyRetireProduction,
		TenantID: production.tenant, ActorID: c.ActorID, MaximumDuration: c.MaximumDuration}
	productionFence, err := oauthpg.NewProxyCustodyFenceOperator(c.ProductionFencePool, production.providerAuthority, scope)
	if err != nil {
		return nil, err
	}
	scope.Schema, scope.Kind = f.state.features.socialOAuth.schema, kernel.OAuthProxyRetirePreview
	previewFence, err := oauthpg.NewProxyCustodyFenceOperator(c.PreviewFencePool, production.providerAuthority, scope)
	if err != nil {
		return nil, err
	}
	return &OAuthProxyMaintenance{state: f.state, pair: pair, production: production.forward, preview: preview.owner,
		productionFence: productionFence, previewFence: previewFence}, nil
}

func validProxyFencePool(fence, custody *database.Pool) bool {
	return fence != nil && fence.Raw() != nil && custody != nil && custody.Raw() != nil && sameProxyDatabase(fence, custody)
}

func (m *OAuthProxyMaintenance) enter(ctx context.Context) (context.Context, func(), error) {
	if m == nil || m.state == nil || ctx == nil {
		return nil, nil, identity.ForbiddenError{}
	}
	return m.state.enterFeature(ctx, true)
}

// ApplyDisableCascade admits the exact disable and freezes the pair in the
// provider owner's existing audit/outbox transaction.
func (m *OAuthProxyMaintenance) ApplyDisableCascade(ctx context.Context, change oauthpg.ProviderAuthorityChange, window time.Duration) (oauthpg.ProviderDisableAdmission, error) {
	work, done, err := m.enter(ctx)
	if err != nil {
		return oauthpg.ProviderDisableAdmission{}, err
	}
	defer done()
	return m.pair.ApplyDisableCascade(work, change, window)
}

// Seal advances the two local cutoffs for the exact admission. The two
// databases do not share a transaction; retry the same selector if one fails.
func (m *OAuthProxyMaintenance) Seal(ctx context.Context, source oauthpg.ProxyCustodyFenceSealRequest) error {
	work, done, err := m.enter(ctx)
	if err != nil {
		return err
	}
	defer done()
	if _, err := m.pair.CheckAdmission(work, source); err != nil {
		return err
	}
	if _, err := m.productionFence.SealAdmittedProviderDisable(work, source); err != nil {
		return err
	}
	_, err = m.previewFence.SealAdmittedProviderDisable(work, source)
	return err
}

// StepProduction resumes the exact local production drain for this admission.
func (m *OAuthProxyMaintenance) StepProduction(ctx context.Context, source oauthpg.ProxyCustodyFenceSealRequest, limit uint16) (oauthpg.ProxyRetirementDrainProgress, error) {
	work, done, err := m.enter(ctx)
	if err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	defer done()
	if _, err := m.pair.CheckAdmission(work, source); err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	authority, err := oauthpg.NewSealedProxyRetirementAuthority(m.productionFence, source)
	if err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	drain, err := oauthpg.NewProductionProxyRetirementDrain(m.production, authority)
	if err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	return drain.Step(work, limit)
}

// StepPreview resumes the exact local preview drain for this admission.
func (m *OAuthProxyMaintenance) StepPreview(ctx context.Context, source oauthpg.ProxyCustodyFenceSealRequest, limit uint16) (oauthpg.ProxyRetirementDrainProgress, error) {
	work, done, err := m.enter(ctx)
	if err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	defer done()
	if _, err := m.pair.CheckAdmission(work, source); err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	authority, err := oauthpg.NewSealedProxyRetirementAuthority(m.previewFence, source)
	if err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	drain, err := oauthpg.NewPreviewProxyRetirementDrain(m.preview, authority)
	if err != nil {
		return oauthpg.ProxyRetirementDrainProgress{}, err
	}
	return drain.Step(work, limit)
}

// Acknowledge confirms only the selected pair's proxy cleanup, never the
// global provider cascade or the external provider outcome.
func (m *OAuthProxyMaintenance) Acknowledge(ctx context.Context, source oauthpg.ProxyCustodyFenceSealRequest) (oauthpg.ProxyDisablePairAcknowledgement, error) {
	work, done, err := m.enter(ctx)
	if err != nil {
		return oauthpg.ProxyDisablePairAcknowledgement{}, err
	}
	defer done()
	return m.pair.Acknowledge(work, source)
}

func (OAuthProxyMaintenanceConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.OAuthProxyMaintenanceConfiguration(redacted)")
}

func (OAuthProxyMaintenanceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (OAuthProxyMaintenanceConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

func (*OAuthProxyMaintenance) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.OAuthProxyMaintenance(redacted)")
}
