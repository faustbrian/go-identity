package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestCanonicalAdminSessionRevokeSelectsStoredSynchronizer(t *testing.T) {
	for _, operation := range []struct{ id, path, otherPath string }{
		{"identity.admin.session-revoke", "/v1/admin/session-revoke", "/v1/admin/session-revoke-all"},
		{"identity.admin.session-revoke-all", "/v1/admin/session-revoke-all", "/v1/admin/session-revoke"},
	} {
		t.Run(operation.id, func(t *testing.T) {
			testCanonicalAdminSessionRevokeSelectsSynchronizer(t, operation.id, operation.path, operation.otherPath)
		})
	}
}

func testCanonicalAdminSessionRevokeSelectsSynchronizer(t *testing.T, operationID, path, otherPath string) {
	t.Helper()
	for _, profile := range []struct {
		name string
		csrf identityhttp.CSRFPolicy
	}{
		{"stored", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}},
		{"canonical", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionOriginAndToken, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
				Owner: "identity/session", OperationID: operationID,
				Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				CSRF:    profile.csrf, MaximumSerializedBytes: 16384,
			})
			if err != nil {
				t.Fatal("administrator session-revoke synchronizer rejected", err)
			}
			feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{op}})
			if err != nil {
				t.Fatal("administrator session-revoke feature rejected", err)
			}
			selected, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil || len(selected) != 1 {
				t.Fatal("administrator session-revoke selection failed", err)
			}
			got := selected[0]
			if got.Record.OperationID != operationID || got.Record.OpenAPIOperationID != operationID {
				t.Fatal("selection changed canonical operation identity", got.Record)
			}
			if got.Route.Method != http.MethodPost || got.Route.Path != path || got.Record.Method != got.Route.Method || got.Record.Path != got.Route.Path {
				t.Fatal("selection changed canonical session-revoke route", got.Route)
			}
			if got.Record.Idempotency != "repeat" || got.Record.RatePolicy != "rate.admin" || got.Route.RatePolicy != "rate.admin" {
				t.Fatal("selection changed canonical repeat or administrative rate contract", got.Record)
			}
			if got.Record.HandlerOwner != "identity/session" || len(got.Record.Owners) != 1 || got.Record.Owners[0] != "identity/session" {
				t.Fatal("selection changed canonical session owner", got.Record)
			}
			if got.Route.CSRF != profile.csrf || got.Record.CSRFOrigin != profile.csrf {
				t.Fatal("selection changed selected synchronizer", got.Record.CSRFOrigin)
			}
			for _, change := range []struct {
				name   string
				mutate func(*identityhttp.OperationDescriptor)
			}{
				{"method", func(op *identityhttp.OperationDescriptor) {
					op.Record.Method, op.Route.Method = http.MethodGet, http.MethodGet
				}},
				{"path", func(op *identityhttp.OperationDescriptor) {
					op.Record.Path, op.Route.Path = otherPath, otherPath
				}},
				{"idempotency-key", func(op *identityhttp.OperationDescriptor) { op.Record.Idempotency = "keyed" }},
				{"rate", func(op *identityhttp.OperationDescriptor) {
					op.Record.RatePolicy, op.Route.RatePolicy = "rate.safe", "rate.safe"
				}},
				{"handler-owner", func(op *identityhttp.OperationDescriptor) { op.Record.HandlerOwner = "identity" }},
				{"accountable-owner", func(op *identityhttp.OperationDescriptor) { op.Record.Owners = []identityhttp.ModuleID{"identity"} }},
				{"authorization", func(op *identityhttp.OperationDescriptor) {
					op.Record.Authorization.Policy, op.Route.Authorization.Policy = "none", "none"
				}},
			} {
				t.Run(change.name, func(t *testing.T) {
					changed := feature.Operations()[0]
					change.mutate(&changed)
					if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{changed}}); err == nil {
						t.Fatal("changed canonical session-revoke custody accepted")
					}
				})
			}
		})
	}
}

func TestCanonicalAdminSessionRevokeRejectsWeakerStoredSynchronizer(t *testing.T) {
	for _, operationID := range []string{"identity.admin.session-revoke", "identity.admin.session-revoke-all"} {
		t.Run(operationID, func(t *testing.T) {
			testCanonicalAdminSessionRevokeRejectsWeakerSynchronizer(t, operationID)
		})
	}
}

func testCanonicalAdminSessionRevokeRejectsWeakerSynchronizer(t *testing.T, operationID string) {
	t.Helper()
	for _, profile := range []struct {
		name string
		csrf identityhttp.CSRFPolicy
	}{
		{"none", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}},
		{"origin-only", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}},
		{"missing-header", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, RefererFallback: identityhttp.RefererFallbackDeny}},
		{"other-header", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "Other-Token", RefererFallback: identityhttp.RefererFallbackDeny}},
		{"different-header-case", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "x-csrf-token", RefererFallback: identityhttp.RefererFallbackDeny}},
		{"independent-age", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}},
		{"referer-fallback", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS}},
		{"pre-auth-union", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFVariantOriginSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			config := identityhttp.CanonicalOperationConfig{
				Owner: "identity/session", OperationID: operationID,
				Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				CSRF:    profile.csrf, MaximumSerializedBytes: 16384,
			}
			if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
				t.Fatal("weaker administrator session-revoke synchronizer accepted")
			}
		})
	}
}

func TestCanonicalAdminSessionRevokeStoredSynchronizerDoesNotBroadenAdministration(t *testing.T) {
	stored := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	for _, operation := range []struct {
		name, id string
		owner    identityhttp.ModuleID
	}{
		{"session-list", "identity.admin.session-list", "identity/session"},
		{"user-delete", "identity.admin.user-delete", "identity"},
		{"wrong-single-owner", "identity.admin.session-revoke", "identity"},
		{"wrong-all-owner", "identity.admin.session-revoke-all", "identity"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			config := identityhttp.CanonicalOperationConfig{
				Owner: operation.owner, OperationID: operation.id,
				Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				CSRF:    stored, MaximumSerializedBytes: 16384,
			}
			if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
				t.Fatal("administrator session-revoke stored synchronizer exception broadened", operation.id)
			}
		})
	}
}
