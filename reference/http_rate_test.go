package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func httpRateFixture() HTTPRateConfiguration {
	return HTTPRateConfiguration{Namespace: "reference-http", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
}

func TestReferenceHTTPRateOwnsSelectedNativeHistory(t *testing.T) {
	ctx := t.Context()
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}}}
	legacy, err := s.migrationCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.state.httpRate = &httpRateState{}
	selected, err := s.migrationCatalog(ctx)
	if err != nil || len(selected) != len(legacy)+1 {
		t.Fatal("selected native history missing", err)
	}
	owned := selected[len(selected)-1]
	native := ratepg.SchemaMigration()
	if owned.namespace != "identity_http_rate" || len(owned.history) != 1 || owned.owners[1] != "rate-limit/postgres" || owned.history[0].UpSQL() != native.Up || owned.history[0].DownSQL() != native.Down {
		t.Fatal("native SQL or independent ownership replaced")
	}
	plan, err := migrations.PlanUp(owned.history, nil)
	if err != nil || len(plan.Steps()) != 1 {
		t.Fatal("native history cannot install", err)
	}
	for i := range legacy[0].history {
		if legacy[0].history[i] != selected[0].history[i] {
			t.Fatal("shared applied prefix changed")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.migrationCatalog(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled discovery exported catalog")
	}
}

func TestReferenceHTTPRateValidatesBeforeResourcesAndRetainsOneOwner(t *testing.T) {
	pool, err := database.Connect(t.Context(), database.Config{DSN: "host=127.0.0.1 port=1 user=postgres dbname=identity_test sslmode=disable search_path=public", StartupPolicy: database.StartupLazy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	for _, mutate := range []func(*HTTPRateConfiguration){
		func(c *HTTPRateConfiguration) { c.IdentifierKey = [32]byte{} },
		func(c *HTTPRateConfiguration) { c.Namespace = "" },
		func(c *HTTPRateConfiguration) { c.Timeout = 0 },
		func(c *HTTPRateConfiguration) { c.MaximumDuration = 3 * time.Second },
		func(c *HTTPRateConfiguration) { c.LockTimeout = time.Second },
		func(c *HTTPRateConfiguration) { c.RollbackTimeout = 0 },
		func(c *HTTPRateConfiguration) { c.Timeout = 1500 * time.Millisecond },
		func(c *HTTPRateConfiguration) { c.LockTimeout = time.Microsecond },
		func(c *HTTPRateConfiguration) { c.RollbackTimeout = time.Second },
	} {
		c := httpRateFixture()
		mutate(&c)
		if owner, err := composeHTTPRate(&c, pool); err == nil || owner != nil {
			t.Fatal("invalid native composition escaped")
		}
	}
	c := httpRateFixture()
	owner, err := composeHTTPRate(&c, pool)
	if err != nil || owner == nil || !owner.limiter.Configured() {
		t.Fatal("pure native construction required unavailable database", err)
	}
	c.Namespace, c.IdentifierKey = "mutated", [32]byte{}
	if !owner.limiter.Configured() {
		t.Fatal("configuration not frozen")
	}
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "login.example", TenantID: "tenant"}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "https://login.example/flow", nil)
	request.RequestURI = "/flow"
	request.RemoteAddr = "127.0.0.1:1234"
	facts, err := network.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	// Closed owner denial is independent of backend/network availability.
	lifetime, cancel := context.WithCancel(context.Background())
	drained := make(chan struct{})
	close(drained)
	stores := StoreSet{state: &storeState{pool: pool, lifetime: lifetime, cancel: cancel, drained: drained, httpRate: owner}}
	// This unit isolates terminal admission even if another native owner cannot
	// finish cleanup. The synthetic graph has no velocity custody, so its owner
	// reports the exact missing-custody error rather than successful shutdown.
	if err := stores.Close(t.Context()); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("synthetic velocity cleanup classification", err)
	}
	if owner.limiter.Configured() {
		t.Fatal("closed native limiter retained admission")
	}
	if _, err := owner.limiter.AdmitOriginalFlow(t.Context(), facts); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("closed admission reached backend", err)
	}
	if err := stores.Close(t.Context()); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("repeated graph shutdown", err)
	}
	if absent, err := composeHTTPRate(nil, nil); err != nil || absent != nil {
		t.Fatal("disabled rate selected resources")
	}
}

func TestReferenceHTTPRateRejectsAmbiguousSchemaAndSecretSerialization(t *testing.T) {
	c := httpRateFixture()
	pool, err := database.Connect(t.Context(), database.Config{DSN: "host=127.0.0.1 port=1 user=postgres dbname=identity_test sslmode=disable", StartupPolicy: database.StartupLazy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if owner, err := composeHTTPRate(&c, pool); err == nil || owner != nil {
		t.Fatal("ambiguous native schema accepted")
	}
	if owner, err := composeHTTPRate(&c, nil); err == nil || owner != nil {
		t.Fatal("missing caller resource accepted")
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("deployment secret serialized")
	}
	if _, err := c.MarshalText(); err == nil {
		t.Fatal("deployment secret serialized as text")
	}
	if fmt.Sprintf("%+v", c) != "reference.HTTPRateConfiguration(redacted)" {
		t.Fatal("deployment formatting not redacted")
	}
}
