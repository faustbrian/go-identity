//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

func installProxyProviderEpochAuthority(t *testing.T, f proxyStartIntegration) (*ProviderAuthority, *ProviderAuthorityOperator) {
	t.Helper()
	schema := f.forward.config.Schema
	history, err := (ProviderAuthorityMigrationSource{Schema: schema, Version: 42}).Load(f.ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load shared provider authority into the native Start schema", err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install authority beside the real native proxy tables", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}

	// A separate reader pool cannot wait on a connection held by the native
	// callback transaction; both pools still use the same fixture primary.
	readPool, err := database.Connect(f.ctx, database.Config{
		DSN: f.pool.Raw().Config().ConnString(), MaxConns: 2,
		Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
			return nil
		},
	})
	if err != nil {
		t.Fatal("open independent provider authority reader", err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := readPool.Close(ctx); err != nil {
			t.Error("close independent provider authority reader", err)
		}
	})
	authority, err := NewProviderAuthority(readPool, schema, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	operatorAuthority, err := NewProviderAuthority(f.pool, schema, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := NewProviderAuthorityOperator(operatorAuthority, oneTapStartActor)
	if err != nil {
		t.Fatal(err)
	}
	return authority, operator
}

func TestProxyProviderEpochStartAndForwardUseLiveAuthority(t *testing.T) {
	f := newProxyStartIntegration(t)
	authority, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = authority
	missing, err := f.start.Start(f.ctx, f.request)
	_, authorized := missing.Authorization()
	_, bound := missing.Binding()
	if err == nil || authorized || bound {
		t.Fatal("an unregistered provider returned native authorization or original binding", err)
	}
	var originals, commands, grants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM onetap_oauth.proxy_transactions),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM public.capability_identity_one_use)`).Scan(&originals, &commands, &grants); err != nil || originals != 0 || commands != 0 || grants != 0 {
		t.Fatal("unregistered provider created original command or grant custody", originals, commands, grants, err)
	}

	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	const initialEpoch = uint64(41)
	configure := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 0, Next: ProviderAuthorityState{Version: initialEpoch, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, configure); err != nil || state != configure.Next {
		t.Fatal("configure the original live provider epoch", state, err)
	}
	request := freshProxyProviderEpochRequest(t, f.request)
	original, lookup := startProxyProviderEpochOriginal(t, f, request, initialEpoch)

	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: initialEpoch, Next: ProviderAuthorityState{Version: initialEpoch + 1, ProfileVersion: f.provider.Version, Enabled: false},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, disable); err != nil || state != disable.Next {
		t.Fatal("commit provider disable before callback generation", state, err)
	}
	calls := 0
	refusedGeneration := func(_ context.Context, _ oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
		calls++
		return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
	}
	assertOriginalRefused := func() {
		t.Helper()
		if err := f.forward.ExecuteOAuthProxyForward(f.ctx, lookup, refusedGeneration); err == nil || calls != 0 {
			t.Fatal("invalidated original reached generation or acknowledged a returned handoff", calls, err)
		}
		originID, err := base64.RawURLEncoding.DecodeString(string(original.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var noHandoff bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT handoff_ciphertext IS NULL
 FROM onetap_oauth.proxy_transactions WHERE origin_command_id=$1`, originID).Scan(&noHandoff); err != nil || !noHandoff {
			t.Fatal("invalidated original acquired a stored handoff", err)
		}
	}
	assertOriginalRefused()

	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: initialEpoch + 1, Next: ProviderAuthorityState{Version: initialEpoch + 2, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, reenable); err != nil || state != reenable.Next {
		t.Fatal("re-enable the same profile under a strictly newer epoch", state, err)
	}
	assertOriginalRefused()

	freshRequest := freshProxyProviderEpochRequest(t, request)
	fresh, freshLookup := startProxyProviderEpochOriginal(t, f, freshRequest, initialEpoch+2)
	if fresh.CommandID == original.CommandID || fresh.TransactionID == original.TransactionID {
		t.Fatal("fresh authorization reused the original command or transaction")
	}
	freshCalls := 0
	err = f.forward.ExecuteOAuthProxyForward(f.ctx, freshLookup, func(ctx context.Context, selected oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
		freshCalls++
		if ctx.Err() != nil || selected.Binding.ProviderAuthorityEpoch != initialEpoch+2 || selected.Binding.ProviderVersion != f.provider.Version ||
			selected.Binding.CommandID != fresh.CommandID || selected.Binding.TransactionID != fresh.TransactionID || selected.Verifier.Challenge() == "" {
			t.Error("fresh generation did not receive its exact live-epoch original and PKCE custody")
		}
		return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
	})
	if !errors.Is(err, oauthproxy.CallbackReconcile) || freshCalls != 1 {
		t.Fatal("fresh authorization at the newer epoch could not reach native generation", freshCalls, err)
	}
}

func TestProxyProviderEpochDisableAfterReservationKeepsVerifierClosed(t *testing.T) {
	f := newProxyStartIntegration(t)
	authority, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = authority
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	register := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 41, ProfileVersion: f.provider.Version, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(f.ctx, register); err != nil {
		t.Fatal("register the live provider", err)
	}
	_, lookup := startProxyProviderEpochOriginal(t, f, f.request, 41)
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 41, Next: ProviderAuthorityState{Version: 42, ProfileVersion: f.provider.Version}, CommandID: providerAuthorityCommand(t)}
	trace := &proxyForwardAuthorityCommitTrace{invalidate: func(ctx context.Context) error {
		_, err := operator.Apply(ctx, disable)
		return err
	}}
	traced, err := database.Connect(f.ctx, database.Config{
		DSN: f.pool.Raw().Config().ConnString(), MaxConns: 2,
		Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
			c.ConnConfig.Tracer = trace
			return nil
		},
	})
	if err != nil {
		t.Fatal("open fixture-owned callback runtime pool", err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := traced.Close(ctx); err != nil {
			t.Error("close fixture-owned callback runtime pool", err)
		}
	})
	directory, err := kernel.NewRepository(traced, kernel.Config{MaximumDuration: f.forward.config.MaximumDuration})
	if err != nil {
		t.Fatal("open traced directory reader", err)
	}
	forward := *f.forward
	forward.pool, forward.directory = traced, directory
	calls := 0
	err = forward.ExecuteOAuthProxyForward(f.ctx, lookup, func(context.Context, oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
		calls++
		return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
	})
	if !errors.Is(err, oauthproxy.CallbackReconcile) || calls != 0 {
		t.Errorf("disable after acknowledged reservation reached generation: calls=%d: %v", calls, err)
	}
	trace.mu.Lock()
	markers, commits, invalidations, traceErr := trace.markers, trace.commits, trace.invalidations, trace.err
	trace.mu.Unlock()
	if markers != 1 || commits != 1 || invalidations != 1 || traceErr != nil {
		t.Fatalf("disable did not commit at the exact generation acknowledgement: marked=%d committed=%d invalidated=%d: %v", markers, commits, invalidations, traceErr)
	}
	var pending bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version=1 AND handoff_ciphertext IS NULL FROM onetap_oauth.proxy_transactions`).Scan(&pending); err != nil || !pending {
		t.Fatal("reconciliation did not retain the unforwarded original", err)
	}
}

func freshProxyProviderEpochRequest(t *testing.T, request oauthproxy.InitiationRequest) oauthproxy.InitiationRequest {
	t.Helper()
	var err error
	request.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request.TransactionID, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func startProxyProviderEpochOriginal(t *testing.T, f proxyStartIntegration, request oauthproxy.InitiationRequest, epoch uint64) (oauth.ProxyOIDCEvidenceBinding, oauthproxy.CallbackLookup) {
	t.Helper()
	result, err := f.start.Start(f.ctx, request)
	if err != nil {
		t.Fatal("native Start for the selected live provider epoch", err)
	}
	authorization, authorized := result.Authorization()
	binding, bound := result.Binding()
	if !authorized || !bound || binding.ProviderAuthorityEpoch != epoch || binding.ProviderVersion != f.provider.Version ||
		binding.ProviderAuthorityEpoch == binding.ProviderVersion || binding.CommandID != request.CommandID || binding.TransactionID != request.TransactionID {
		t.Fatal("native Start did not expose the independent live epoch and exact original binding")
	}
	providerURL, err := url.Parse(authorization.URL())
	if err != nil {
		t.Fatal(err)
	}
	state := providerURL.Query().Get("state")
	stateDigest := sha256.Sum256([]byte(state))
	if state == "" || stateDigest != binding.StateDigest {
		t.Fatal("native authorization state did not identify its returned original")
	}
	return binding, oauthproxy.CallbackLookup{
		StateDigest: stateDigest, ProductionDeployment: binding.ProductionDeployment, ProductionCallback: f.provider.RedirectURI,
		ProviderID: f.provider.ID, ProviderVersion: f.provider.Version, Issuer: f.provider.Issuer, ClientID: f.provider.ClientID,
	}
}
