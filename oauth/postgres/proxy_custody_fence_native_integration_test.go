//go:build integration

package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

func TestProxyCustodyFenceNativeStartActivationAndDeniedEpoch(t *testing.T) {
	f := newProxyStartIntegration(t)
	authority, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = authority
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	proxyCustodyFenceSetAuthority(t, f.ctx, operator, key, f.provider.Version, 0, 41, true)
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceMigrationSource{
		Schema: f.forward.config.Schema, Version: 90, Kind: kernel.OAuthProxyRetireProduction,
	})

	legacy := *f.start
	legacyBinding, legacyLookup := startProxyProviderEpochOriginal(t, f, f.request, 41)
	var legacyUnprojected bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT fence_provider_id IS NULL AND fence_provider_epoch IS NULL
FROM onetap_oauth.proxy_transactions WHERE transaction_id=$1`, string(legacyBinding.TransactionID)).Scan(&legacyUnprojected); err != nil || !legacyUnprojected {
		t.Fatal("expansion did not preserve the unselected native writer", err)
	}
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceActivationSource{
		Schema: f.forward.config.Schema, Version: 92, Kind: kernel.OAuthProxyRetireProduction,
	})

	beforeCustody, beforeGrants := proxyCustodyFenceCounts(t, f.ctx, f.pool, "proxy_transactions")
	late := freshProxyProviderEpochRequest(t, f.request)
	result, err := legacy.Start(f.ctx, late)
	proxyCustodyFenceNoStartOutput(t, result, err)
	proxyCustodyFenceAssertCounts(t, f.ctx, f.pool, "proxy_transactions", beforeCustody, beforeGrants)

	// Existing fixture inputs are intentionally private after construction. Copy
	// the real native service and opt only its writer into the new SQL contract.
	selected := *f.start
	selected.custodyFence = true
	f.start = &selected
	current, _ := startProxyProviderEpochOriginal(t, f, freshProxyProviderEpochRequest(t, f.request), 41)
	proxyCustodyFenceAssertProjection(t, f.ctx, f.pool, "proxy_transactions", "transaction_id", string(current.TransactionID), current)

	calls := 0
	err = f.forward.ExecuteOAuthProxyForward(f.ctx, legacyLookup, func(context.Context, oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
		calls++
		return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
	})
	if !errors.Is(err, oauthproxy.CallbackReconcile) || calls != 1 {
		t.Fatal("activation made an existing unprojected original unreadable to native callback generation", calls, err)
	}

	observed, err := authority.Current(f.ctx, key)
	if err != nil || !observed.Enabled || observed.Version != 41 {
		t.Fatal("local write fence test lost its independent enabled shared authority", observed, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO onetap_oauth.proxy_production_write_fences(tenant_id,provider_id,denied_through)
VALUES($1,$2,$3::numeric)`, string(key.TenantID), key.ProviderID, strconv.FormatUint(observed.Version, 10)); err != nil {
		t.Fatal("install a local fence without disabling shared provider authority", err)
	}
	beforeCustody, beforeGrants = proxyCustodyFenceCounts(t, f.ctx, f.pool, "proxy_transactions")
	denied := freshProxyProviderEpochRequest(t, f.request)
	result, err = f.start.Start(f.ctx, denied)
	proxyCustodyFenceNoStartOutput(t, result, err)
	proxyCustodyFenceAssertCounts(t, f.ctx, f.pool, "proxy_transactions", beforeCustody, beforeGrants)
	if current, err := authority.Current(f.ctx, key); err != nil || current != observed {
		t.Fatal("write rejection was not isolated from the still-enabled shared provider authority", current, err)
	}
	proxyPreviewProductionHasNoIdentity(t, f)

	proxyCustodyFenceSetAuthority(t, f.ctx, operator, key, f.provider.Version, 41, 42, false)
	proxyCustodyFenceSetAuthority(t, f.ctx, operator, key, f.provider.Version, 42, 43, true)
	newer, _ := startProxyProviderEpochOriginal(t, f, freshProxyProviderEpochRequest(t, f.request), 43)
	proxyCustodyFenceAssertProjection(t, f.ctx, f.pool, "proxy_transactions", "transaction_id", string(newer.TransactionID), newer)
}

func TestProxyCustodyFenceNativePreviewActivationAndDeniedEpoch(t *testing.T) {
	production := newProxyStartIntegration(t)
	preview := newProxyPreviewSessionFixture(t, production.target, production.start.provider)
	authority, operator := installProxyProviderEpochAuthority(t, production)
	production.forward.providerAuthority = authority
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: production.provider.ID}
	proxyCustodyFenceSetAuthority(t, production.ctx, operator, key, production.provider.Version, 0, 41, true)
	legacy, err := NewProxyPreviewServiceWithProviderAuthority(preview.completion, preview.config, authority)
	if err != nil {
		t.Fatal("construct the unselected native live-authority preview writer", err)
	}
	selected, err := NewProxyPreviewServiceWithCustodyFence(preview.completion, preview.config, authority)
	if err != nil {
		t.Fatal("construct the selected native preview writer from trusted fixture inputs", err)
	}
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceMigrationSource{
		Schema: preview.completion.start.config.Schema, Version: 90, Kind: kernel.OAuthProxyRetirePreview,
	})
	legacyBind := proxyCustodyFencePreviewRequest(t, production, preview, 41)
	if err := legacy.Bind(preview.ctx, legacyBind); err != nil {
		t.Fatal("expansion stopped the unselected native preview writer", err)
	}
	var legacyUnprojected bool
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT fence_provider_id IS NULL AND fence_provider_epoch IS NULL
FROM onetap_oauth.proxy_preview_bindings WHERE flow_id=$1`, string(legacyBind.Binding.TransactionID)).Scan(&legacyUnprojected); err != nil || !legacyUnprojected {
		t.Fatal("legacy native preview unexpectedly required a projected provider", err)
	}
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceActivationSource{
		Schema: preview.completion.start.config.Schema, Version: 92, Kind: kernel.OAuthProxyRetirePreview,
	})

	late := proxyCustodyFencePreviewRequest(t, production, preview, 41)
	beforeCustody, beforeGrants := proxyCustodyFenceCounts(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	if err := legacy.Bind(preview.ctx, late); err == nil {
		t.Fatal("activated preview custody acknowledged an unselected late native writer")
	}
	proxyCustodyFenceAssertCounts(t, preview.ctx, preview.pool, "proxy_preview_bindings", beforeCustody, beforeGrants)
	proxyCustodyFenceAssertBrowserUnconsumed(t, preview, late.Binding.TransactionID)

	current := proxyCustodyFencePreviewRequest(t, production, preview, 41)
	if err := selected.Bind(preview.ctx, current); err != nil {
		t.Fatal("activated preview custody rejected its selected current live writer", err)
	}
	proxyCustodyFenceAssertProjection(t, preview.ctx, preview.pool, "proxy_preview_bindings", "flow_id", string(current.Binding.TransactionID), current.Binding)
	if err := legacy.Bind(preview.ctx, legacyBind); err != nil {
		t.Fatal("activation stopped exact replay of an existing legacy preview binding", err)
	}

	observed, err := authority.Current(production.ctx, key)
	if err != nil || !observed.Enabled || observed.Version != 41 {
		t.Fatal("preview local fence test lost enabled shared authority", observed, err)
	}
	if _, err := preview.pool.Raw().Exec(preview.ctx, `INSERT INTO onetap_oauth.proxy_preview_write_fences(tenant_id,provider_id,denied_through)
VALUES($1,$2,$3::numeric)`, string(key.TenantID), key.ProviderID, strconv.FormatUint(observed.Version, 10)); err != nil {
		t.Fatal("install a preview-local denied epoch", err)
	}
	denied := proxyCustodyFencePreviewRequest(t, production, preview, observed.Version)
	beforeCustody, beforeGrants = proxyCustodyFenceCounts(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	if err := selected.Bind(preview.ctx, denied); err == nil {
		t.Fatal("native preview acknowledged custody at its locally denied epoch")
	}
	proxyCustodyFenceAssertCounts(t, preview.ctx, preview.pool, "proxy_preview_bindings", beforeCustody, beforeGrants)
	proxyCustodyFenceAssertBrowserUnconsumed(t, preview, denied.Binding.TransactionID)
	if current, err := authority.Current(production.ctx, key); err != nil || current != observed {
		t.Fatal("preview write rejection changed the independent shared authority", current, err)
	}

	proxyCustodyFenceSetAuthority(t, production.ctx, operator, key, production.provider.Version, 41, 42, false)
	proxyCustodyFenceSetAuthority(t, production.ctx, operator, key, production.provider.Version, 42, 43, true)
	newer := proxyCustodyFencePreviewRequest(t, production, preview, 43)
	if err := selected.Bind(preview.ctx, newer); err != nil {
		t.Fatal("preview local fence rejected a newer live re-enabled epoch", err)
	}
	proxyCustodyFenceAssertProjection(t, preview.ctx, preview.pool, "proxy_preview_bindings", "flow_id", string(newer.Binding.TransactionID), newer.Binding)
	proxyCustodyFenceAssertBrowserUnconsumed(t, preview, newer.Binding.TransactionID)
}

func proxyCustodyFenceInstall(t *testing.T, ctx context.Context, pool *database.Pool, source migrations.Source) {
	t.Helper()
	history, err := source.Load(ctx)
	if err != nil || len(history) == 0 {
		t.Fatal("load opt-in native custody fence history", err)
	}
	for _, migration := range history {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("install opt-in native custody fence history", migration.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("commit opt-in native custody fence history", err)
		}
	}
}

func proxyCustodyFenceSetAuthority(t *testing.T, ctx context.Context, operator *ProviderAuthorityOperator, key ProviderAuthorityKey, profile, previous, next uint64, enabled bool) {
	t.Helper()
	change := ProviderAuthorityChange{Key: key, ExpectedVersion: previous,
		Next: ProviderAuthorityState{Version: next, ProfileVersion: profile, Enabled: enabled}, CommandID: providerAuthorityCommand(t)}
	if state, err := operator.Apply(ctx, change); err != nil || state != change.Next {
		t.Fatal("advance the independent shared provider authority", state, err)
	}
}

func proxyCustodyFencePreviewRequest(t *testing.T, production proxyStartIntegration, preview proxyPreviewSessionFixture, epoch uint64) ProxyPreviewBindRequest {
	t.Helper()
	flow, cookie := preview.issueBrowser(t, production.request.Remember)
	request := freshProxyProviderEpochRequest(t, production.request)
	request.TransactionID = flow
	binding, _ := startProxyProviderEpochOriginal(t, production, request, epoch)
	return ProxyPreviewBindRequest{Binding: binding, FlowCookie: cookie,
		Origin: production.target.Origin, Network: "192.0.2.19", Device: "original-preview-browser"}
}

func proxyCustodyFenceNoStartOutput(t *testing.T, result ProxyStartResult, err error) {
	t.Helper()
	authorization, authorized := result.Authorization()
	_, bound := result.Binding()
	if err == nil || authorized || bound || authorization.URL() != "" {
		t.Fatal("rejected native custody write released authorization or original binding", err)
	}
}

func proxyCustodyFenceCounts(t *testing.T, ctx context.Context, pool *database.Pool, table string) (int, int) {
	t.Helper()
	var custody, grants int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM onetap_oauth.`+table+`),
(SELECT count(*) FROM public.capability_identity_one_use)`).Scan(&custody, &grants); err != nil {
		t.Fatal("read native custody and grant effects", err)
	}
	return custody, grants
}

func proxyCustodyFenceAssertCounts(t *testing.T, ctx context.Context, pool *database.Pool, table string, wantCustody, wantGrants int) {
	t.Helper()
	custody, grants := proxyCustodyFenceCounts(t, ctx, pool, table)
	if custody != wantCustody || grants != wantGrants {
		t.Fatal("rejected native write leaked custody or an issued grant", custody, grants, wantCustody, wantGrants)
	}
}

func proxyCustodyFenceAssertProjection(t *testing.T, ctx context.Context, pool *database.Pool, table, locator, id string, binding oauth.ProxyOIDCEvidenceBinding) {
	t.Helper()
	var provider, epoch string
	if err := pool.Raw().QueryRow(ctx, `SELECT fence_provider_id,fence_provider_epoch::text
FROM onetap_oauth.`+table+` WHERE tenant_id=$1 AND `+locator+`=$2`, string(binding.TenantID), id).Scan(&provider, &epoch); err != nil ||
		provider != binding.ProviderID || epoch != strconv.FormatUint(binding.ProviderAuthorityEpoch, 10) || binding.ProviderAuthorityEpoch == binding.ProviderVersion {
		t.Fatal("native custody projection did not retain the authenticated provider and independent live epoch", provider, epoch, err)
	}
}

func proxyCustodyFenceAssertBrowserUnconsumed(t *testing.T, preview proxyPreviewSessionFixture, flow identity.PreAuthTransactionID) {
	t.Helper()
	var state string
	var sessions int
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT state,(SELECT count(*) FROM onetap_sessions.sessions)
FROM onetap_sessions.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(oneTapStartTenant), string(flow)).Scan(&state, &sessions); err != nil || state != "issued" || sessions != 0 {
		t.Fatal("native Bind consumed the browser or created session effects", state, sessions, err)
	}
}
