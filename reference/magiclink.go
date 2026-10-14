package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	magichttp "github.com/faustbrian/go-identity/http/magiclink"
	"github.com/faustbrian/go-identity/magiclink"
)

// MagicLinkRequestService combines the public native workflow and frozen
// normalization consumed by selected HTTP. Normalization confers no authority.
type MagicLinkRequestService interface {
	magiclink.RequestService
	magichttp.RequestService
}

// MagicLinkConsumeService combines native consumption/recovery and authenticated
// original rate-source lookup. No source metadata may be exposed to a client.
type MagicLinkConsumeService interface {
	magiclink.ConsumptionService
	magichttp.ConsumeService
}

// MagicLinkRequest returns the selected native owner without IO or startup.
// Calls retain graph initialization, bounded lifetime and tenant admission;
// normalization is a state-neutral parser and has no caller-selected tenant.
// Retained handles deny after Close, including recovery and normalization.
func (f FeatureSet) MagicLinkRequest() (MagicLinkRequestService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_magic_link"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.magicRequest == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicRequest{state: s}, nil
}

// MagicLinkConsume returns explicit consumption only when independently
// selected. Obtaining a handle enables neither a route nor session issuance.
// Every call retains current graph startup/tenant/shutdown guards.
func (f FeatureSet) MagicLinkConsume() (MagicLinkConsumeService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_magic_link_consume"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.magicConsume == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicConsume{state: s}, nil
}

type composedMagicRequest struct{ state *storeState }
type composedMagicConsume struct{ state *storeState }

func (f composedMagicRequest) Request(ctx context.Context, r magiclink.RequestRequest) (magiclink.RequestResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return magiclink.RequestResult{}, err
	}
	defer done()
	return f.state.features.magicRequest.Request(w, r)
}
func (f composedMagicRequest) RequestRateSource(ctx context.Context, input email.AddressInput) (string, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return "", err
	}
	defer done()
	return f.state.features.magicRequest.RequestRateSource(w, input)
}
func (f composedMagicRequest) RecoverRequest(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (magiclink.RequestResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return magiclink.RequestResult{}, err
	}
	defer done()
	return f.state.features.magicRequest.RecoverRequest(w, q, caller)
}
func (f composedMagicConsume) Consume(ctx context.Context, r magiclink.ConsumeRequest) (magiclink.ConsumeResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return magiclink.ConsumeResult{}, err
	}
	defer done()
	return f.state.features.magicConsume.Consume(w, r)
}
func (f composedMagicConsume) ConsumeRateSource(ctx context.Context, r magiclink.ConsumeRequest) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return f.state.features.magicConsume.ConsumeRateSource(w, r)
}
func (f composedMagicConsume) RecoverConsume(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (magiclink.ConsumeResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return magiclink.ConsumeResult{}, err
	}
	defer done()
	return f.state.features.magicConsume.RecoverConsume(w, q, caller)
}

var _ MagicLinkRequestService = composedMagicRequest{}
var _ MagicLinkConsumeService = composedMagicConsume{}
