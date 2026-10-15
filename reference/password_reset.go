package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// PasswordReset returns the public request/completion/recovery owner only when
// selected in this sealed graph. Obtaining a handle performs no IO or startup.
// Every retained call checks initialization, tenant ownership and the bounded
// graph lifetime. Close permanently denies further operations, including replay.
func (f FeatureSet) PasswordReset() (password.ResetService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_password_reset"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.reset == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPasswordReset{state: s}, nil
}

type composedPasswordReset struct{ state *storeState }

// PasswordResetInspection returns the selected read-only reset owner without
// IO. It preserves the same initialized tenant/graph lifetime as PasswordReset;
// callers gain neither a proof reservation nor permission for later completion.
func (f FeatureSet) PasswordResetInspection() (password.ResetInspectionService, error) {
	owner, err := f.PasswordReset()
	if err != nil {
		return nil, err
	}
	return owner.(composedPasswordReset), nil
}

func (f composedPasswordReset) ResetInspect(ctx context.Context, r password.ResetInspectRequest) (password.ResetInspectResult, error) {
	w, done, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return password.ResetInspectResult{}, err
	}
	defer done()
	return f.state.features.reset.ResetInspect(w, r)
}

func (f composedPasswordReset) ResetInspectionRateSource(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	w, done, err := f.enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return "", "", "", 0, err
	}
	defer done()
	return f.state.features.reset.ResetInspectionRateSource(w, proof, caller)
}

func (f composedPasswordReset) enter(ctx context.Context, tenant identity.TenantID) (context.Context, func(), error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return nil, nil, err
	}
	if f.state.tenants[string(tenant)] == nil {
		done()
		return nil, nil, identity.UnavailableError{}
	}
	return w, done, nil
}

func (f composedPasswordReset) ResetRequest(ctx context.Context, r password.ResetRequestRequest) (password.ResetRequestResult, error) {
	w, done, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return password.ResetRequestResult{}, err
	}
	defer done()
	return f.state.features.reset.ResetRequest(w, r)
}

func (f composedPasswordReset) ResetComplete(ctx context.Context, r password.ResetCompleteRequest) (password.ResetCompleteResult, error) {
	w, done, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return password.ResetCompleteResult{}, err
	}
	defer done()
	return f.state.features.reset.ResetComplete(w, r)
}

func (f composedPasswordReset) RecoverResetRequest(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.ResetRequestResult, error) {
	w, done, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return password.ResetRequestResult{}, err
	}
	defer done()
	return f.state.features.reset.RecoverResetRequest(w, q, caller)
}

func (f composedPasswordReset) RecoverResetComplete(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.ResetCompleteResult, error) {
	w, done, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return password.ResetCompleteResult{}, err
	}
	defer done()
	return f.state.features.reset.RecoverResetComplete(w, q, caller)
}

// Transport admission consumes only native normalization and authenticated
// issuance metadata; it cannot substitute its own subject or factor authority.
func (f composedPasswordReset) ResetRequestRateSource(ctx context.Context, input identifier.Input) (string, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return "", err
	}
	defer done()
	return f.state.features.reset.ResetRequestRateSource(w, input)
}

func (f composedPasswordReset) ResetCompletionRateSource(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error) {
	w, done, err := f.enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return "", "", "", 0, err
	}
	defer done()
	return f.state.features.reset.ResetCompletionRateSource(w, proof, caller)
}

var _ password.ResetService = composedPasswordReset{}
