package postgres

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func refreshOutputTestBinding(t *testing.T, f *refreshEnvelopeFixture) identity.CommandBinding {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	operation := providerRefreshOperation()
	return identity.CommandBinding{CommandID: id, TenantID: f.current.Binding.TenantID, UserID: f.current.Binding.UserID,
		ActorID: identity.ActorID(f.current.Binding.UserID), ActorKind: authorization.SubjectUser, RecordID: string(f.current.Binding.AccountID),
		OperationID: operation.OperationID, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion,
		PolicyID: "test-policy", PolicyVersion: 1, CorrelationID: string(id)}
}

func TestRetainedProviderRefreshGenerationRestoresWithoutAnotherRequest(t *testing.T) {
	f := newRefreshEnvelopeFixture(t)
	ctx := context.Background()
	binding := refreshOutputTestBinding(t, f)
	const generation = 4
	wire, err := f.service.generateProviderRefreshOutput(ctx, binding, f.current, f.refresh, generation)
	if err != nil || len(wire) == 0 || len(f.seen) != 1 {
		t.Fatalf("original generation did not retain one provider response: %v", err)
	}
	defer clear(wire)
	for range 2 {
		out, err := f.service.openProviderRefreshOutput(ctx, binding, f.current, generation, wire)
		if err != nil || out.Rejected || out.Successor == nil || out.Successor.Version != 2 || len(out.Successor.Ciphertext) == 0 || len(f.seen) != 1 {
			t.Fatalf("original result was missing or repeated provider work: %v", err)
		}
	}
	if _, err := f.service.openProviderRefreshOutput(ctx, binding, f.current, generation+1, wire); err == nil {
		t.Fatal("another journal generation adopted original output")
	}
	modified := f.current
	modified.Binding.SocialLinkVersion++
	if _, err := f.service.openProviderRefreshOutput(ctx, binding, modified, generation, wire); err == nil {
		t.Fatal("different predecessor adopted the original refresh")
	}
	otherID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	binding.CommandID = otherID
	if _, err := f.service.openProviderRefreshOutput(ctx, binding, f.current, generation, wire); err == nil {
		t.Fatal("another command obtained original provider result")
	}
}

func TestProviderRefreshGenerationDoesNotConvertAnAmbiguousSendIntoRejection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		response map[string]any
		rejected bool
	}{
		{"unusable grant", http.StatusBadRequest, map[string]any{"error": "invalid_grant"}, true},
		{"unconfirmed provider", http.StatusServiceUnavailable, map[string]any{"error": "invalid_grant"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshEnvelopeFixture(t)
			f.status, f.response = tc.status, tc.response
			ctx := context.Background()
			binding := refreshOutputTestBinding(t, f)
			wire, err := f.service.generateProviderRefreshOutput(ctx, binding, f.current, f.refresh, 1)
			defer clear(wire)
			if len(f.seen) != 1 {
				t.Fatalf("expected one upstream attempt, got %d", len(f.seen))
			}
			if !tc.rejected {
				var providerError *oauth.Error
				if len(wire) != 0 || !errors.As(err, &providerError) || providerError.Kind() != oauth.Unknown {
					t.Fatalf("ambiguous result incorrectly produced a terminal disposition: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal("definitive rejection was not retained", err)
			}
			out, err := f.service.openProviderRefreshOutput(ctx, binding, f.current, 1, wire)
			if err != nil || !out.Rejected || out.Successor != nil || len(f.seen) != 1 {
				t.Fatalf("definitive grant rejection changed during restoration: %v", err)
			}
		})
	}
}
