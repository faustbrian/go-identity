package reference

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	oauth "github.com/faustbrian/go-oauth-server"
)

// OAuthWorkloadService is the selected native workload interface behind the
// sealed graph's initialization, cancellation and shutdown boundary. Copies
// share one lifetime and are safe for concurrent calls. It owns no pool or
// goroutine. Requests retain native OAuth ownership, credential-custody and
// trusted transport-attribution obligations; input mutation during a call is
// forbidden. Successful credentials belong to the caller, never to a logger.
// Zero is invalid. Retained handles permanently deny after StoreSet.Close.
type OAuthWorkloadService struct{ state *storeState }

// OAuthWorkloads returns the selected native handle without enabling HTTP or
// performing IO. It can be retained before Initialize, but its operations deny
// until initialization succeeds. Unselected, uncomposed and closed graphs deny.
func (f FeatureSet) OAuthWorkloads() (OAuthWorkloadService, error) {
	s := f.state
	if s == nil {
		return OAuthWorkloadService{}, identity.InvalidInputError{Field: "reference_oauth_workload"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.oauthWorkload == nil || s.features.oauthWorkload.native == nil {
		return OAuthWorkloadService{}, identity.UnavailableError{}
	}
	return OAuthWorkloadService{state: s}, nil
}

// Token invokes the existing configured workload issuer. Earlier caller
// deadlines win, Close cancels the call, and native committed/unknown outcomes
// remain unchanged. Errors are not proof that a previously attempted command
// rolled back; consume only the native result's declared outcome.
func (o OAuthWorkloadService) Token(ctx context.Context, r oauth.TokenRequest) (oauth.TokenResult, error) {
	w, done, err := o.state.enterFeature(ctx, true)
	if err != nil {
		return oauth.TokenResult{}, err
	}
	defer done()
	return o.state.features.oauthWorkload.native.Token(w, r)
}

// Introspect performs the native owning-client primary read within this graph's
// lifetime. It returns no cacheable authority or renewed freshness evidence.
func (o OAuthWorkloadService) Introspect(ctx context.Context, r oauth.IntrospectRequest) (oauth.IntrospectResult, error) {
	w, done, err := o.state.enterFeature(ctx, true)
	if err != nil {
		return oauth.IntrospectResult{}, err
	}
	defer done()
	return o.state.features.oauthWorkload.native.Introspect(w, r)
}

// Revoke retains the native client's authorization, atomic effects, unknown-
// outcome and indistinguishable unknown-token semantics, bounded by shutdown.
func (o OAuthWorkloadService) Revoke(ctx context.Context, r oauth.RevokeRequest) (oauth.RevokeResult, error) {
	w, done, err := o.state.enterFeature(ctx, true)
	if err != nil {
		return oauth.RevokeResult{}, err
	}
	defer done()
	return o.state.features.oauthWorkload.native.Revoke(w, r)
}

// Format redacts graph internals and correlated deployment custody.
func (OAuthWorkloadService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.OAuthWorkloadService(redacted)"))
}

// MarshalJSON rejects implicit runtime-custody export.
func (OAuthWorkloadService) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText rejects implicit runtime-custody export.
func (OAuthWorkloadService) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
