package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
)

// ImpersonationService exposes the selected primary native owner without
// transferring its dependencies or extending it beyond the graph lifetime.
type ImpersonationService struct{ state *storeState }

// Impersonation returns the opt-in native grant and child-use owner.
func (f FeatureSet) Impersonation() (*ImpersonationService, error) {
	if f.state == nil {
		return nil, identity.UnavailableError{}
	}
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if f.state.closed || f.state.features == nil || !f.state.features.composed || f.state.features.impersonation == nil {
		return nil, identity.UnavailableError{}
	}
	return &ImpersonationService{state: f.state}, nil
}

func (s *ImpersonationService) enter(ctx context.Context) (context.Context, func(), *impersonationpg.Service, error) {
	if s == nil || s.state == nil {
		return nil, nil, nil, identity.UnavailableError{}
	}
	w, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return nil, nil, nil, err
	}
	return w, done, s.state.features.impersonation.native, nil
}

// PrepareRequest prepares a pending grant without creating authority.
func (s *ImpersonationService) PrepareRequest(ctx context.Context, input impersonationpg.RequestInput) (impersonationpg.PreparedCommand, error) {
	w, done, native, err := s.enter(ctx)
	if err != nil {
		return impersonationpg.PreparedCommand{}, err
	}
	defer done()
	return native.PrepareRequest(w, input)
}

// PrepareApproval prepares an independent administrator's exact grant decision.
func (s *ImpersonationService) PrepareApproval(ctx context.Context, input impersonationpg.ApproveInput) (impersonationpg.PreparedCommand, error) {
	w, done, native, err := s.enter(ctx)
	if err != nil {
		return impersonationpg.PreparedCommand{}, err
	}
	defer done()
	return native.PrepareApproval(w, input)
}

// PrepareDenial prepares an independent administrator's terminal decision
// when the native denial profile is selected. It does not write the grant.
func (s *ImpersonationService) PrepareDenial(ctx context.Context, input impersonationpg.DenyInput) (impersonationpg.PreparedCommand, error) {
	w, done, native, err := s.enter(ctx)
	if err != nil {
		return impersonationpg.PreparedCommand{}, err
	}
	defer done()
	return native.PrepareDenial(w, input)
}

// Execute commits the native request, approval, or selected denial.
func (s *ImpersonationService) Execute(ctx context.Context, input impersonationpg.PreparedCommand) (identity.CommandResult, error) {
	w, done, native, err := s.enter(ctx)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return native.Execute(w, input)
}

// Recover reconciles an exact original request, approval, or denial with current
// administrator authentication. It cannot mint or transfer credentials.
func (s *ImpersonationService) Recover(ctx context.Context, auth impersonationpg.Authentication, binding identity.CommandBinding) (identity.CommandResult, error) {
	switch binding.OperationID {
	case "identity.impersonation.request", "identity.impersonation.approve", "identity.impersonation.deny":
	default:
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	w, done, native, err := s.enter(ctx)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return native.Recover(w, auth, binding)
}

// ValidateUse checks a child credential's exact approved application permission
// against the live primary. This cannot authenticate an ordinary session.
func (s *ImpersonationService) ValidateUse(ctx context.Context, input impersonationpg.UseInput) (impersonationpg.UseResult, error) {
	w, done, native, err := s.enter(ctx)
	if err != nil {
		return impersonationpg.UseResult{}, err
	}
	defer done()
	return native.ValidateUse(w, input)
}
