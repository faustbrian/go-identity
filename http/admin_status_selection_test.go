package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestCanonicalAdminUserStatusSelectsStoredSynchronizer(t *testing.T) {
	stored := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	canonical := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionOriginAndToken, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}
	for _, operation := range []struct{ id, path string }{
		{"identity.admin.user-ban", "/v1/admin/user-ban"},
		{"identity.admin.user-unban", "/v1/admin/user-unban"},
	} {
		for _, profile := range []struct {
			name string
			csrf identityhttp.CSRFPolicy
		}{
			{"stored", stored},
			{"canonical", canonical},
		} {
			t.Run(operation.id+"/"+profile.name, func(t *testing.T) {
				op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
					Owner: "identity", OperationID: operation.id,
					Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
					CSRF:    profile.csrf, MaximumSerializedBytes: 16384,
				})
				if err != nil {
					t.Fatal("administrator user-status synchronizer rejected", err)
				}
				feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity", Operations: []identityhttp.OperationDescriptor{op}})
				if err != nil {
					t.Fatal("administrator user-status feature rejected", err)
				}
				selected, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(selected) != 1 {
					t.Fatal("administrator user-status selection failed", err)
				}
				got := selected[0]
				if got.Route.Method != http.MethodPost || got.Route.Path != operation.path || got.Record.OperationID != operation.id || got.Record.Idempotency != "keyed" || got.Record.RatePolicy != "rate.admin" || got.Record.HandlerOwner != "identity" || len(got.Record.Owners) != 1 || got.Record.Owners[0] != "identity" || got.Route.CSRF != profile.csrf || got.Record.CSRFOrigin != profile.csrf {
					t.Fatal("selection changed canonical user-status custody", got.Record)
				}
				for _, change := range []struct {
					name   string
					mutate func(*identityhttp.OperationDescriptor)
				}{
					{"method", func(op *identityhttp.OperationDescriptor) {
						op.Record.Method, op.Route.Method = http.MethodGet, http.MethodGet
					}},
					{"path", func(op *identityhttp.OperationDescriptor) {
						op.Record.Path, op.Route.Path = "/v1/admin/other", "/v1/admin/other"
					}},
					{"idempotency", func(op *identityhttp.OperationDescriptor) { op.Record.Idempotency = "repeat" }},
					{"rate", func(op *identityhttp.OperationDescriptor) {
						op.Record.RatePolicy, op.Route.RatePolicy = "rate.safe", "rate.safe"
					}},
					{"handler-owner", func(op *identityhttp.OperationDescriptor) { op.Record.HandlerOwner = "identity/session" }},
					{"authorization", func(op *identityhttp.OperationDescriptor) {
						op.Record.Authorization.Policy, op.Route.Authorization.Policy = "none", "none"
					}},
				} {
					t.Run(change.name, func(t *testing.T) {
						changed := feature.Operations()[0]
						change.mutate(&changed)
						if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity", Operations: []identityhttp.OperationDescriptor{changed}}); err == nil {
							t.Fatal("changed canonical user-status custody accepted")
						}
					})
				}
			})
		}
	}
}

func TestCanonicalAdminUserStatusRejectsWeakerStoredSynchronizer(t *testing.T) {
	stored := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	for _, operation := range []string{"identity.admin.user-ban", "identity.admin.user-unban"} {
		for _, profile := range []struct {
			name string
			csrf identityhttp.CSRFPolicy
		}{
			{"none", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}},
			{"origin-only", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}},
			{"missing-header", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, RefererFallback: identityhttp.RefererFallbackDeny}},
			{"other-header", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "Other-Token", RefererFallback: identityhttp.RefererFallbackDeny}},
			{"independent-age", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}},
			{"referer-fallback", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS}},
			{"pre-auth-union", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFVariantOriginSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}},
		} {
			t.Run(operation+"/"+profile.name, func(t *testing.T) {
				config := identityhttp.CanonicalOperationConfig{Owner: "identity", OperationID: operation, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: profile.csrf, MaximumSerializedBytes: 16384}
				if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
					t.Fatal("weaker user-status synchronizer accepted")
				}
			})
		}
		config := identityhttp.CanonicalOperationConfig{Owner: "identity/session", OperationID: operation, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: stored, MaximumSerializedBytes: 16384}
		if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
			t.Fatal("wrong accountable user-status owner accepted")
		}
	}
	for _, operation := range []struct{ id, owner string }{
		{"identity.admin.user-delete", "identity"},
		{"identity.admin.user-password-set", "identity/password"},
		{"identity.admin.user-role-set", "authorization"},
	} {
		t.Run(operation.id, func(t *testing.T) {
			config := identityhttp.CanonicalOperationConfig{Owner: identityhttp.ModuleID(operation.owner), OperationID: operation.id, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: stored, MaximumSerializedBytes: 16384}
			if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
				t.Fatal("user-status stored synchronizer exception broadened to unrelated administration")
			}
		})
	}
}
