package reference

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// APIKeyService exposes the selected native management and atomic verification
// owner behind this graph's startup, tenant and shutdown guards. It owns no pool
// or separate journal. Independent calls are concurrent-safe; recovery remains
// original status observation, not execution or secret reconstruction.
type APIKeyService struct{ state *storeState }

// APIKeys returns the independently selected native owner without IO or HTTP
// activation. Handles may be retained before initialization; calls cannot run
// before readiness or after graph closure.
func (f FeatureSet) APIKeys() (*APIKeyService, error) {
	if f.state == nil {
		return nil, identity.InvalidInputError{Field: "reference_api_key"}
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.apiKey == nil {
		return nil, identity.UnavailableError{}
	}
	return &APIKeyService{state: s}, nil
}

func (a *APIKeyService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, func(), *apiKeyState, error) {
	if a == nil || a.state == nil {
		return nil, nil, nil, identity.UnavailableError{}
	}
	w, done, err := (composedPasswordReset{state: a.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	if a.state.features.apiKey == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, done, a.state.features.apiKey, nil
}

// Create retains original keyed self-owned native issuance and reveal custody.
func (a *APIKeyService) Create(ctx context.Context, r apikey.CreateRequest) (apikey.IssuanceResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return apikey.IssuanceResult{}, err
	}
	defer done()
	return n.native.Create(w, r)
}

// CreateOrganization retains genuine current human management independently
// of the explicitly selected organization credential owner. It shares this
// graph's admission, lifetime and native original reveal-once custody.
func (a *APIKeyService) CreateOrganization(ctx context.Context, r apikey.OrganizationCreateRequest) (apikey.IssuanceResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return apikey.IssuanceResult{}, err
	}
	defer done()
	return n.native.CreateOrganization(w, r)
}

// RecoverOrganization observes only the exact original command under current
// member authority. Retain its target even when an unknown create has no key
// row; status recovery neither executes work nor reconstructs key plaintext.
func (a *APIKeyService) RecoverOrganization(ctx context.Context, id apikey.OrganizationID, r apikey.RecoveryRequest) (identity.CommandResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return n.native.RecoverOrganization(w, id, r)
}

// Import retains the selected native digest-only workflow, current source and
// owner authorization, and original outcome recovery. It never issues a key.
func (a *APIKeyService) Import(ctx context.Context, r apikey.ImportRequest) (identity.CommandResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return n.native.Import(w, r)
}

// Rotate retains zero-overlap native successor issuance without widening grants.
func (a *APIKeyService) Rotate(ctx context.Context, r apikey.Rotation) (apikey.IssuanceResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return apikey.IssuanceResult{}, err
	}
	defer done()
	return n.native.Rotate(w, r)
}

// Revoke retains native terminal tombstones and exact original-key effects.
func (a *APIKeyService) Revoke(ctx context.Context, r apikey.Revocation) (identity.CommandResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return n.native.Revoke(w, r)
}

// Recover observes the exact original command under current native authority.
func (a *APIKeyService) Recover(ctx context.Context, r apikey.RecoveryRequest) (identity.CommandResult, error) {
	w, done, n, err := a.enter(ctx, r.Authentication.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return n.native.Recover(w, r)
}

// VerifyAndConsume retains native atomic current-authority verification and
// narrowing, including persisted denial. It never issues a browser session.
func (a *APIKeyService) VerifyAndConsume(ctx context.Context, r apikey.AtomicVerificationRequest) (apikey.AtomicVerificationResult, error) {
	w, done, n, err := a.enter(ctx, r.TenantID)
	if err != nil {
		return apikey.AtomicVerificationResult{}, err
	}
	defer done()
	return n.native.VerifyAndConsume(w, r)
}

// ReconcileVerifyAndConsume observes one exact original verification attempt.
// It preserves original authority deadlines and does not execute missing work.
func (a *APIKeyService) ReconcileVerifyAndConsume(ctx context.Context, r apikey.VerificationReconcileQuery) (apikey.AtomicVerificationResult, error) {
	w, done, n, err := a.enter(ctx, r.TenantID)
	if err != nil {
		return apikey.AtomicVerificationResult{}, err
	}
	defer done()
	return n.native.ReconcileVerifyAndConsume(w, r)
}
func (APIKeyService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.APIKeyService(redacted)")
}
func (APIKeyService) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
func (APIKeyService) MarshalText() ([]byte, error) { return nil, apikey.ErrDisclosure }

var _ apikey.Service = (*APIKeyService)(nil)
var _ apikey.OrganizationService = (*APIKeyService)(nil)
var _ apikey.LegacyImporter = (*APIKeyService)(nil)
