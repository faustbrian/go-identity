package oauthproxy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

type callbackCommandFunc func(context.Context, CallbackLookup, CallbackGeneration) error

func (f callbackCommandFunc) ExecuteOAuthProxyForward(ctx context.Context, lookup CallbackLookup, generate CallbackGeneration) error {
	return f(ctx, lookup, generate)
}

func TestProductionCommandCallbackDoesNotRegenerate(t *testing.T) {
	fixture := newCallbackFixture(t)
	var runs int
	store := callbackCommandFunc(func(ctx context.Context, lookup CallbackLookup, generate CallbackGeneration) error {
		runs++
		if lookup.StateDigest != fixture.store.original.Binding.StateDigest || lookup.ProviderID != "oidc" || lookup.ProviderDenied {
			t.Fatal("command owner did not receive original selection")
		}
		if runs > 1 {
			return ErrOriginalUnavailable
		}
		fixture.store.reserved = 1 // This fixture models the acknowledged native lease.
		prepared, err := generate(ctx, fixture.store.original)
		if !errors.Is(err, CallbackReconcile) || prepared.Disposition() != CallbackNeedsReconciliation || len(prepared.Envelope()) != 0 {
			t.Fatalf("ambiguous exchange became a terminal output: %v", err)
		}
		repeated, err := generate(ctx, fixture.store.original)
		if !errors.Is(err, CallbackReconcile) || len(repeated.Envelope()) != 0 {
			t.Fatal("same generation could call external work twice")
		}
		return errors.New("private native diagnostic")
	})
	callback, err := newProductionCommandCallback(ProductionCallbackConfig{
		ProductionDeployment: "production-a", Codec: fixture.codec, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
	}, fixture.provider, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := callback.Handle(t.Context(), fixture.route, fixture.query)
	if !errors.Is(err, CallbackReconcile) || strings.Contains(err.Error(), "private") || len(result.Envelope()) != 0 || fixture.provider.attempts != 1 {
		t.Fatalf("ambiguous native command produced output or leaked diagnostics: %v", err)
	}
	result, err = callback.Handle(t.Context(), fixture.route, fixture.query)
	if !errors.Is(err, CallbackDenied) || len(result.Envelope()) != 0 || fixture.provider.attempts != 1 {
		t.Fatalf("terminal replay regenerated provider work: %v", err)
	}
}

func TestProductionCommandCallbackDoesNotTreatEmptyCommitAsFreshHandoff(t *testing.T) {
	fixture := newCallbackFixture(t)
	callback, err := newProductionCommandCallback(ProductionCallbackConfig{
		ProductionDeployment: "production-a", Codec: fixture.codec, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
	}, fixture.provider, callbackCommandFunc(func(context.Context, CallbackLookup, CallbackGeneration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	result, err := callback.Handle(t.Context(), fixture.route, fixture.query)
	if !errors.Is(err, CallbackReconcile) || len(result.Envelope()) != 0 || fixture.provider.attempts != 0 {
		t.Fatal("missing fresh generation created a handoff", err)
	}
}

func TestProductionCommandCallbackDenialValidatesExactDirectoryTenant(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tenant      identity.TenantID
		disposition CallbackDisposition
		want        CallbackError
	}{
		{"uppercase directory ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV", CallbackRejected, CallbackDenied},
		{"empty tenant", "", CallbackNeedsReconciliation, CallbackReconcile},
		{"tenant with space", "tenant a", CallbackNeedsReconciliation, CallbackReconcile},
		{"tenant with control", "tenant\x7f", CallbackNeedsReconciliation, CallbackReconcile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			fixture.store.original.Binding.TenantID = tc.tenant
			fixture.query = strings.Replace(fixture.query, "code=local-code", "error=access_denied", 1)
			fixture.store.original.Verifier = oauth.PKCEVerifier{}
			fixture.store.original.Nonce = ""
			var generated bool
			callback, err := newProductionCommandCallback(ProductionCallbackConfig{
				ProductionDeployment: "production-a", Codec: fixture.codec, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
			}, fixture.provider, callbackCommandFunc(func(ctx context.Context, lookup CallbackLookup, generate CallbackGeneration) error {
				if !lookup.ProviderDenied || lookup.StateDigest != fixture.store.original.Binding.StateDigest {
					t.Fatal("command did not select the original provider denial")
				}
				generated = true
				prepared, generationErr := generate(ctx, fixture.store.original)
				if prepared.Disposition() != tc.disposition || len(prepared.Envelope()) != 0 {
					t.Fatalf("denial prepared disposition %v, want %v, or released an envelope", prepared.Disposition(), tc.disposition)
				}
				if tc.disposition == CallbackRejected && generationErr != nil {
					t.Fatalf("valid original denial was not acknowledged: %v", generationErr)
				}
				if tc.disposition == CallbackNeedsReconciliation && !errors.Is(generationErr, CallbackReconcile) {
					t.Fatalf("invalid tenant was not left for reconciliation: %v", generationErr)
				}
				return generationErr
			}))
			if err != nil {
				t.Fatal(err)
			}
			result, err := callback.Handle(t.Context(), fixture.route, fixture.query)
			if !generated || !errors.Is(err, tc.want) || result.Destination() != "" || len(result.Envelope()) != 0 || fixture.provider.attempts != 0 {
				t.Fatalf("denial returned an unexpected outcome or performed provider work: %v", err)
			}
		})
	}
}

type cancellationCallbackProvider struct {
	profile         oauth.ProviderProfile
	cancelCaller    func()
	sawCancellation bool
}

func (p *cancellationCallbackProvider) Profile() oauth.ProviderProfile { return p.profile }
func (p *cancellationCallbackProvider) Exchange(ctx context.Context, _ identity.OAuthCallbackInput, _ oauth.PKCEVerifier, _ string) (oauth.ProviderIdentity, error) {
	p.cancelCaller()
	select {
	case <-ctx.Done():
		p.sawCancellation = true
	case <-time.After(200 * time.Millisecond):
	}
	return oauth.ProviderIdentity{}, errors.New("unresolved in-flight provider request")
}

func TestProductionCommandCallbackKeepsCallerCancellationDuringDetachedGeneration(t *testing.T) {
	fixture := newCallbackFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	provider := &cancellationCallbackProvider{profile: fixture.provider.profile, cancelCaller: cancel}
	callback, err := newProductionCommandCallback(ProductionCallbackConfig{
		ProductionDeployment: "production-a", Codec: fixture.codec, Clock: fixture.clock, Targets: []PreviewTarget{fixture.target},
	}, provider, callbackCommandFunc(func(command context.Context, _ CallbackLookup, generate CallbackGeneration) error {
		prepared, err := generate(context.WithoutCancel(command), fixture.store.original)
		if !errors.Is(err, CallbackReconcile) || prepared.Disposition() != CallbackNeedsReconciliation || len(prepared.Envelope()) != 0 {
			t.Fatal("cancelled generation became a terminal handoff", err)
		}
		return err
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := callback.Handle(ctx, fixture.route, fixture.query)
	if !provider.sawCancellation || !errors.Is(err, CallbackReconcile) || len(result.Envelope()) != 0 {
		t.Fatal("detached native settlement context dropped caller cancellation", err)
	}
}
