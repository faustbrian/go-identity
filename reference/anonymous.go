package reference

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	"github.com/faustbrian/go-identity/session"
)

// AnonymousService retains this graph's actual native guest workflows. It owns
// no resources; independent calls are concurrency-safe and preserve tenant,
// initialization, shutdown and original native deadlines. Zero denies. Recovery
// reconciles original commands only, never reexecutes or redelivers credentials.
// Unsupported operations remain unavailable even if a sibling was selected.
type AnonymousService struct{ state *storeState }

// Anonymous returns selected native guest operations without enabling HTTP or
// performing IO. The retained handle cannot outlive the graph's active lifetime.
func (f FeatureSet) Anonymous() (*AnonymousService, error) {
	if f.state == nil {
		return nil, identity.InvalidInputError{Field: "reference_anonymous"}
	}
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if f.state.closed || f.state.features == nil || !f.state.features.composed || f.state.features.anonymous == nil {
		return nil, identity.UnavailableError{}
	}
	return &AnonymousService{state: f.state}, nil
}

// AnonymousPreAuth returns the selected native anonymous-flow issuer without
// enabling HTTP or changing OTP/password initiation. Preparation, issuance and
// metadata-only recovery retain graph initialization, tenant and shutdown guards.
func (f FeatureSet) AnonymousPreAuth() (PreAuthService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_anonymous_preauth"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.anonymous == nil || s.features.anonymous.preauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: s, issuer: s.features.anonymous.preauth}, nil
}

func (f *AnonymousService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, func(), *anonymousState, error) {
	if f == nil || f.state == nil {
		return nil, nil, nil, identity.UnavailableError{}
	}
	bounded, done, err := (composedPasswordReset{state: f.state}).enter(ctx, tenant)
	if err != nil {
		return nil, nil, nil, err
	}
	a := f.state.features.anonymous
	if a == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return bounded, done, a, nil
}

// Signin executes the selected actual keyed guest-creation workflow once.
func (f *AnonymousService) Signin(ctx context.Context, r anonymous.SigninRequest) (anonymous.SigninResult, error) {
	w, done, a, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return anonymous.SigninResult{}, err
	}
	defer done()
	if a.signin == nil {
		return anonymous.SigninResult{}, identity.UnavailableError{}
	}
	return a.signin.Signin(w, r)
}

// RecoverSignin authenticates original flow possession for metadata-only query.
func (f *AnonymousService) RecoverSignin(ctx context.Context, r anonymous.SigninRecoveryRequest) (anonymous.SigninResult, error) {
	q, _, err := r.Recovery.Bindings()
	if err != nil {
		return anonymous.SigninResult{}, err
	}
	w, done, a, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return anonymous.SigninResult{}, err
	}
	defer done()
	if a.signin == nil {
		return anonymous.SigninResult{}, identity.UnavailableError{}
	}
	return a.signin.RecoverSignin(w, r)
}

// Get recognizes explicitly unprivileged guest custody, never a verified user.
func (f *AnonymousService) Get(ctx context.Context, r session.GetRequest) (session.AnonymousGetResult, error) {
	w, done, a, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return session.AnonymousGetResult{}, err
	}
	defer done()
	if a.reader == nil {
		return session.AnonymousGetResult{}, identity.UnavailableError{}
	}
	return a.reader.Get(w, r)
}

// Delete executes selected native self-disposal with required atomic effects.
func (f *AnonymousService) Delete(ctx context.Context, r anonymous.DeletionRequest) (anonymous.DeletionResult, error) {
	w, done, a, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return anonymous.DeletionResult{}, err
	}
	defer done()
	if a.deletion == nil {
		return anonymous.DeletionResult{}, identity.UnavailableError{}
	}
	return a.deletion.Delete(w, r)
}

// RecoverDeletion queries retained original possession, not new active admission.
func (f *AnonymousService) RecoverDeletion(ctx context.Context, r anonymous.DeletionRecoveryRequest) (anonymous.DeletionResult, error) {
	w, done, a, err := f.enter(ctx, r.Recovery.TenantID)
	if err != nil {
		return anonymous.DeletionResult{}, err
	}
	defer done()
	if a.deletion == nil {
		return anonymous.DeletionResult{}, identity.UnavailableError{}
	}
	return a.deletion.RecoverDeletion(w, r)
}

// Upgrade delegates to the native two-command, one-use protected transition.
func (f *AnonymousService) Upgrade(ctx context.Context, r anonymous.UpgradeRequest) (anonymous.UpgradeResult, error) {
	w, done, a, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return anonymous.UpgradeResult{}, err
	}
	defer done()
	if a.upgrade == nil {
		return anonymous.UpgradeResult{}, identity.UnavailableError{}
	}
	return a.upgrade.Upgrade(w, r)
}

// RecoverUpgrade retains both original command scopes without credential reveal.
func (f *AnonymousService) RecoverUpgrade(ctx context.Context, r anonymous.UpgradeRecoveryRequest) (anonymous.UpgradeResult, error) {
	w, done, a, err := f.enter(ctx, r.Recovery.TenantID)
	if err != nil {
		return anonymous.UpgradeResult{}, err
	}
	defer done()
	if a.upgrade == nil {
		return anonymous.UpgradeResult{}, identity.UnavailableError{}
	}
	return a.upgrade.RecoverUpgrade(w, r)
}

// CleanupExpired executes explicitly selected, tenant-bound maintenance under
// its configured service actor. It enables no HTTP route or background job.
// Individual items retain the native original-command recovery contract.
func (f *AnonymousService) CleanupExpired(ctx context.Context, r anonymouspg.CleanupRequest) (anonymouspg.CleanupResult, error) {
	w, done, a, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return anonymouspg.CleanupResult{}, err
	}
	defer done()
	if a.cleanup == nil {
		return anonymouspg.CleanupResult{}, identity.UnavailableError{}
	}
	return a.cleanup.CleanupExpired(w, r)
}

// RecoverCleanup reconciles an original service-owned cleanup command without
// requiring an expired guest credential or repeating its disposal.
func (f *AnonymousService) RecoverCleanup(ctx context.Context, q identity.RecoveryQuery) (anonymouspg.CleanupItem, error) {
	w, done, a, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return anonymouspg.CleanupItem{}, err
	}
	defer done()
	if a.cleanup == nil {
		return anonymouspg.CleanupItem{}, identity.UnavailableError{}
	}
	return a.cleanup.RecoverCleanup(w, q)
}

// Format hides retained graph resources and custody for every formatting verb.
func (*AnonymousService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.AnonymousService(redacted)")
}

// MarshalJSON rejects implicit export of borrowed graph custody.
func (*AnonymousService) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// MarshalText rejects implicit text/map-key export of borrowed graph custody.
func (*AnonymousService) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }
