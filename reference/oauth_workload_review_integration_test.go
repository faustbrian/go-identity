//go:build integration

package reference_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	oauth "github.com/faustbrian/go-oauth-server"
	password "github.com/faustbrian/go-password/v2"
)

func TestReferenceOAuthWorkloadRejectsConflictingHTTPTenants(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c, deps, policies, wire := referenceWorkloadConfiguration(t, f.config, "https://127.0.0.1")
	deps.PostgreSQL = f.pool
	const otherTenant identity.TenantID = "other-tenant"
	c.DurableAdmission.Tenants = append(c.DurableAdmission.Tenants, string(otherTenant))
	c.OAuthWorkload.BootstrapTenantIDs = append(c.OAuthWorkload.BootstrapTenantIDs, otherTenant)
	workload, err := oauth.NewWorkload(otherTenant, "oauth-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	otherClient := c.OAuthWorkload.Protocol.Clients[0]
	otherClient.ID += "-other"
	otherClient.Workload = workload
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	verifier, err := oauth.NewClientSecretVerifier(otherClient.ID, otherClient.Version, secret)
	if err != nil {
		t.Fatal(err)
	}
	c.OAuthWorkload.Protocol.Clients = append(c.OAuthWorkload.Protocol.Clients, otherClient)
	c.OAuthWorkload.Protocol.ClientSecrets = append(c.OAuthWorkload.Protocol.ClientSecrets, verifier)
	compose := func(input reference.StoreConfiguration) reference.FeatureSet {
		t.Helper()
		stores, err := reference.ComposeStores(input, deps)
		if err != nil {
			t.Fatal("valid native multi-tenant configuration", err)
		}
		t.Cleanup(func() {
			bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := stores.Close(bounded); err != nil {
				t.Error(err)
			}
		})
		providers, err := reference.ComposeProviders(stores)
		if err != nil {
			t.Fatal(err)
		}
		workers, err := reference.ComposeWorkers(stores, providers)
		if err != nil {
			t.Fatal(err)
		}
		features, err := reference.ComposeFeatures(stores, providers, workers)
		if err != nil {
			t.Fatal(err)
		}
		return features
	}
	selected := compose(c)
	config := referenceWorkloadServerConfig(policies)
	if _, err := reference.NewServer(config, deps, selected); err == nil {
		t.Error("HTTP tenant admission disagreed with configured workload authority")
	}
	config.HTTP.Network.PublicHosts = []string{"127.0.0.1"}
	config.HTTP.Network.TenantHosts = nil
	if _, err := reference.NewServer(config, deps, selected); err == nil {
		t.Error("public-only host bypassed required Reference tenant admission")
	}
	nativeOnly := c
	nativeOnly.HTTPOAuthWorkload, nativeOnly.HTTPRate = nil, nil
	if _, err := reference.NewServer(referenceWorkloadServerConfig(policies), deps, compose(nativeOnly)); err != nil {
		t.Fatal("native-only composition lost independently bound workload tenants", err)
	}
}

func TestReferenceOAuthWorkloadRejectsAuditSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c, deps, _, _ := referenceWorkloadConfiguration(t, f.config, "https://login.example")
	deps.PostgreSQL = f.pool
	c.OAuthWorkload.Schema = "audit"
	stores, err := reference.ComposeStores(c, deps)
	if err == nil {
		_ = stores.Close(ctx)
		t.Fatal("OAuth accepted the mandatory audit owner's namespace")
	}
}

func TestReferenceOAuthWorkloadRejectsInvalidCoordinator(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c, deps, _, _ := referenceWorkloadConfiguration(t, f.config, "https://login.example")
	deps.PostgreSQL = f.pool
	c.OAuthWorkload.Coordinator.LeaseDuration = 0
	stores, err := reference.ComposeStores(c, deps)
	if err == nil {
		_ = stores.Close(ctx)
		t.Fatal("Reference accepted an unusable native coordinator")
	}
}

func TestReferenceOAuthWorkloadRejectsUnmanagedSchemaBeforeWrites(t *testing.T) {
	for _, unrelated := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "unrelated-object"}[unrelated], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			f := newLiveStoresProfile(t, ctx, false, true)
			c, deps, _, _ := referenceWorkloadConfiguration(t, f.config, "https://login.example")
			deps.PostgreSQL = f.pool
			stores, err := reference.ComposeStores(c, deps)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := stores.Close(bounded); err != nil {
					t.Error(err)
				}
			}()
			if _, err := f.pool.Raw().Exec(ctx, "CREATE SCHEMA oauth_store"); err != nil {
				t.Fatal(err)
			}
			if unrelated {
				if _, err := f.pool.Raw().Exec(ctx, "CREATE TABLE oauth_store.external_marker(value integer)"); err != nil {
					t.Fatal(err)
				}
			}
			status, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"oauth-server/postgres"}})
			if err != nil || len(status.Statuses) != 1 || status.Statuses[0].Compatibility != reference.MigrationIncompatible {
				t.Fatal("unmanaged schema was not incompatible before writes", err)
			}
			modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "oauth-server/postgres"}
			if _, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules}); err == nil {
				t.Fatal("unmanaged schema produced an executable plan")
			}
			var untouched bool
			if err := f.pool.Raw().QueryRow(ctx, `SELECT to_regnamespace('identity') IS NULL AND to_regnamespace('audit') IS NULL AND to_regclass('public.outbox_messages') IS NULL`).Scan(&untouched); err != nil || !untouched {
				t.Fatal("preflight rejection changed another owner", err)
			}
		})
	}
}
