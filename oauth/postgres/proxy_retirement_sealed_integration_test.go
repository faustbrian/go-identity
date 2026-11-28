//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func TestProxySealedRetirementProductionSurvivesSourceAuditRetention(t *testing.T) {
	f := newProxyStartIntegration(t)
	primary, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = primary
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	configure := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 41, ProfileVersion: f.provider.Version, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(f.ctx, configure); err != nil {
		t.Fatal("configure provider before native original", err)
	}
	original, lookup := startProxyProviderEpochOriginal(t, f, f.request, 41)
	proxyRetirementDiscoveryInstall(t, f.ctx, f.pool, f.forward.config.Schema, kernel.OAuthProxyRetireProduction)
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProviderDisableCascadeMigrationSource{Schema: f.forward.config.Schema, Version: 80})
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceMigrationSource{Schema: f.forward.config.Schema, Version: 90, Kind: kernel.OAuthProxyRetireProduction})
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 41, Next: ProviderAuthorityState{Version: 42, ProfileVersion: f.provider.Version}, CommandID: providerAuthorityCommand(t)}
	admitted, err := operator.ApplyDisableCascade(f.ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit exact provider disable through the real primary owner", err)
	}
	reenable := ProviderAuthorityChange{Key: key, ExpectedVersion: 42, Next: ProviderAuthorityState{Version: 43, ProfileVersion: f.provider.Version, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(f.ctx, reenable); err != nil {
		t.Fatal("re-enable the same profile under a newer epoch", err)
	}
	fresh, _ := startProxyProviderEpochOriginal(t, f, freshProxyProviderEpochRequest(t, f.request), 43)
	sealer, err := NewProxyCustodyFenceOperator(f.pool, primary, ProxyCustodyFenceOperatorConfig{
		Schema: f.forward.config.Schema, Kind: kernel.OAuthProxyRetireProduction, TenantID: key.TenantID,
		ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose the separate primary-reader and actual local custody pools", err)
	}
	source := ProxyCustodyFenceSealRequest{TenantID: key.TenantID, SourceCommandID: disable.CommandID, CascadeID: admitted.CascadeID, Generation: admitted.Generation}
	authority, err := NewSealedProxyRetirementAuthority(sealer, source)
	if err != nil {
		t.Fatal("construct sealed-source authority without granting authority before sealing", err)
	}
	request := ProxyOriginRetirementRequest{CommandID: providerAuthorityCommand(t), OriginCommandID: original.CommandID, FlowID: original.TransactionID, Disable: disable}
	snapshot := func() string {
		t.Helper()
		return proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions")
	}
	assertDenied := func(t *testing.T, selected *ProxyRetirementAuthority, change ProviderAuthorityChange) {
		t.Helper()
		before := snapshot()
		page, err := f.forward.ListDisabledProviderOrigins(f.ctx, selected, ProxyRetirementDiscoveryRequest{Disable: change, ScanLimit: 32})
		proxyProviderDisableAssertDenied(t, err)
		if !reflect.DeepEqual(page, ProxyRetirementDiscoveryPage{}) {
			t.Fatal("unsealed or substituted source disclosed local custody")
		}
		attempt := request
		attempt.CommandID, attempt.Disable = providerAuthorityCommand(t), change
		result, err := f.forward.RetireDisabledProviderOrigin(f.ctx, selected, attempt)
		proxyProviderDisableAssertDenied(t, err)
		if !reflect.DeepEqual(result, identity.CommandResult{}) || snapshot() != before {
			t.Fatal("unsealed or substituted source committed local retirement effects")
		}
	}
	assertDenied(t, authority, disable)
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceActivationSource{Schema: f.forward.config.Schema, Version: 92, Kind: kernel.OAuthProxyRetireProduction})
	assertDenied(t, authority, disable)
	seal, err := sealer.SealAdmittedProviderDisable(f.ctx, source)
	if err != nil || seal.DeniedThrough != 41 {
		t.Fatal("persist the exact admitted cutoff on actual production custody", seal, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE onetap_oauth.proxy_transactions DISABLE TRIGGER proxy_custody_write_fence`); err != nil {
		t.Fatal("disable only fixture-owned writer gate", err)
	}
	assertDenied(t, authority, disable)
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE onetap_oauth.proxy_transactions ENABLE TRIGGER proxy_custody_write_fence`); err != nil {
		t.Fatal("restore fixture-owned writer gate", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE onetap_oauth.proxy_production_write_fences SET denied_through=40 WHERE tenant_id=$1 AND provider_id=$2`, oneTapStartTenant, key.ProviderID); err != nil {
		t.Fatal("lower only the fixture-owned local cutoff", err)
	}
	assertDenied(t, authority, disable)
	if _, err := sealer.SealAdmittedProviderDisable(f.ctx, source); err != nil {
		t.Fatal("restore exact authoritative cutoff after failed use", err)
	}

	for _, mutate := range []func(*ProxyCustodyFenceSealRequest){
		func(r *ProxyCustodyFenceSealRequest) { r.SourceCommandID = configure.CommandID },
		func(r *ProxyCustodyFenceSealRequest) { r.CascadeID, _ = identity.NewCascadeID() },
	} {
		forged := source
		mutate(&forged)
		selected, err := NewSealedProxyRetirementAuthority(sealer, forged)
		if err != nil {
			t.Fatal("validly shaped forged selector must be checked against durable source", err)
		}
		assertDenied(t, selected, disable)
	}
	for _, mutate := range []func(*ProviderAuthorityChange){
		func(c *ProviderAuthorityChange) { c.ExpectedVersion-- },
		func(c *ProviderAuthorityChange) { c.Next.Version++ },
		func(c *ProviderAuthorityChange) { c.Next.ProfileVersion++ },
		func(c *ProviderAuthorityChange) { c.CommandID = configure.CommandID },
		func(c *ProviderAuthorityChange) { c.Key.ProviderID = "another-provider" },
	} {
		changed := disable
		mutate(&changed)
		assertDenied(t, authority, changed)
	}

	legacy := proxyRetirementDiscoveryAuthority(t, primary.pool)
	recordID := "oauth-provider-authority:" + string(disable.CommandID)
	var pruned bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT audit.prune_record(record_id,canonical_sha256)
 FROM audit.records WHERE record_id=$1`, recordID).Scan(&pruned); err != nil || !pruned {
		t.Fatal("prune exact source audit using native retention", err)
	}
	var payloads, tombstones int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM audit.records WHERE record_id=$1),
 (SELECT count(*) FROM audit.record_identities WHERE record_id=$1)`, recordID).Scan(&payloads, &tombstones); err != nil || payloads != 0 || tombstones != 1 {
		t.Fatal("retained tombstone did not outlive source audit payload", err)
	}
	assertDenied(t, legacy, disable)
	beforeDiscovery := snapshot()
	page, err := f.forward.ListDisabledProviderOrigins(f.ctx, authority, ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: 32})
	want := []ProxyRetirementOrigin{{OriginCommandID: original.CommandID, FlowID: original.TransactionID}}
	if err != nil || !reflect.DeepEqual(page.Origins, want) || page.Scanned != 2 || page.NextAfterFlowID != "" || snapshot() != beforeDiscovery {
		t.Fatal("sealed retained source did not discover only the exact old native original without writes", page, err)
	}

	const freshSQL = `SELECT jsonb_build_array(
 (SELECT to_jsonb(p) FROM onetap_oauth.proxy_transactions p WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT jsonb_agg(to_jsonb(g)) FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$3))::text`
	var freshBefore string
	if err := f.pool.Raw().QueryRow(f.ctx, freshSQL, oneTapStartTenant, string(fresh.TransactionID), string(fresh.CommandID)).Scan(&freshBefore); err != nil {
		t.Fatal("retain newer-epoch native custody and grant", err)
	}
	result, err := f.forward.RetireDisabledProviderOrigin(f.ctx, authority, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Validate() != nil || result.Binding.CommandID != request.CommandID {
		t.Fatal("sealed admitted source with pruned audit did not commit real retirement", err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(string(disable.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var retired, revoked bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT version=3 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL AND handoff_ciphertext IS NULL
 AND binding_ciphertext IS NOT NULL AND retirement_source_command_id=$3 AND retirement_source_version=42 AND retired_at IS NOT NULL
 FROM onetap_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT count(*)=1 AND bool_and(state='revoked' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$1 AND origin_command_id=$4 AND subject_id=$2 AND purpose='identity.oauth.proxy-forward')`,
		oneTapStartTenant, string(original.TransactionID), raw, string(original.CommandID)).Scan(&retired, &revoked); err != nil || !retired || !revoked {
		t.Fatal("retirement failed to atomically erase old bearer custody and revoke its exact unused grant", err)
	}
	committed := snapshot()
	replay, err := f.forward.RetireDisabledProviderOrigin(f.ctx, authority, request)
	if err != nil || !reflect.DeepEqual(replay, result) || snapshot() != committed {
		t.Fatal("exact sealed retirement replay changed its immutable receipt or effects", err)
	}
	var freshAfter string
	if err := f.pool.Raw().QueryRow(f.ctx, freshSQL, oneTapStartTenant, string(fresh.TransactionID), string(fresh.CommandID)).Scan(&freshAfter); err != nil || freshAfter != freshBefore {
		t.Fatal("historical sealed retirement changed newer-epoch custody or grant", err)
	}
	providerAuthorityAssertState(t, f.ctx, primary, key, reenable.Next)
	var pending, sourceEvent bool
	if err := primary.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT status=$3 FROM onetap_oauth.provider_disable_cascades WHERE tenant_id=$1 AND source_command_id=$2),
 (SELECT count(*)=1 FROM public.outbox_messages WHERE id=$2 AND topic='social_provider.disabled.v1')`,
		oneTapStartTenant, string(disable.CommandID), int16(identity.RevocationPending)).Scan(&pending, &sourceEvent); err != nil || !pending || !sourceEvent {
		t.Fatal("local cleanup acknowledged admission or removed source enqueue", err)
	}
	calls := 0
	err = f.forward.ExecuteOAuthProxyForward(f.ctx, lookup, func(context.Context, oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
		calls++
		return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
	})
	if !errors.Is(err, oauthproxy.ErrOriginalUnavailable) || calls != 0 {
		t.Fatal("sealed cleanup restored the old callback authority after re-enable", calls, err)
	}

	// A previously constructed authority must reread the pending source rather
	// than cache permission, even when its original command has committed.
	if _, err := primary.pool.Raw().Exec(f.ctx, `DELETE FROM onetap_oauth.provider_disable_cascades WHERE tenant_id=$1 AND source_command_id=$2`, oneTapStartTenant, string(disable.CommandID)); err != nil {
		t.Fatal("remove only fixture-owned source admission", err)
	}
	assertDenied(t, authority, disable)
	var missing string
	if err := primary.pool.Raw().QueryRow(f.ctx, `SELECT source_command_id FROM onetap_oauth.provider_disable_cascades WHERE tenant_id=$1 AND source_command_id=$2`, oneTapStartTenant, string(disable.CommandID)).Scan(&missing); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("source disappearance fixture did not remove exact admission", err)
	}
}

func TestProxySealedRetirementPreviewSurvivesSourceAuditRetention(t *testing.T) {
	production, preview, callback, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
	primary := production.forward.providerAuthority
	schema := preview.completion.start.config.Schema
	proxyRetirementDiscoveryInstall(t, preview.ctx, preview.pool, schema, kernel.OAuthProxyRetirePreview)
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProviderDisableCascadeMigrationSource{Schema: production.forward.config.Schema, Version: 80})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: 90, Kind: kernel.OAuthProxyRetirePreview})
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next: ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version}, CommandID: providerAuthorityCommand(t)}
	admitted, err := operator.ApplyDisableCascade(production.ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit preview's disable through designated production primary", err)
	}
	reenable := ProviderAuthorityChange{Key: key, ExpectedVersion: disable.Next.Version,
		Next: ProviderAuthorityState{Version: disable.Next.Version + 1, ProfileVersion: production.provider.Version, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(production.ctx, reenable); err != nil {
		t.Fatal("re-enable provider without restoring old preview authority", err)
	}
	newFlow, cookie := preview.issueBrowser(t, production.request.Remember)
	newStart := production.request
	newStart.CommandID, newStart.TransactionID = providerAuthorityCommand(t), newFlow
	newStart.RequestFingerprint = sha256.Sum256([]byte("sealed-retirement-newer-preview-origin"))
	started, err := production.start.Start(production.ctx, newStart)
	if err != nil {
		t.Fatal("create newer-epoch real native preview origin", err)
	}
	newBinding, ok := started.Binding()
	if !ok || newBinding.ProviderAuthorityEpoch != reenable.Next.Version {
		t.Fatal("new native preview binding lost its newer authority epoch")
	}
	if err := preview.service.Bind(preview.ctx, ProxyPreviewBindRequest{Binding: newBinding, FlowCookie: cookie,
		Origin: production.target.Origin, Network: "192.0.2.21", Device: "sealed-retirement-newer-browser"}); err != nil {
		t.Fatal("bind independent newer origin in real local preview custody", err)
	}
	sealer, err := NewProxyCustodyFenceOperator(preview.pool, primary, ProxyCustodyFenceOperatorConfig{
		Schema: schema, Kind: kernel.OAuthProxyRetirePreview, TenantID: key.TenantID, ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose preview custody separately from designated provider primary", err)
	}
	source := ProxyCustodyFenceSealRequest{TenantID: key.TenantID, SourceCommandID: disable.CommandID, CascadeID: admitted.CascadeID, Generation: admitted.Generation}
	authority, err := NewSealedProxyRetirementAuthority(sealer, source)
	if err != nil {
		t.Fatal("compose native preview sealed authority", err)
	}
	request := ProxyOriginRetirementRequest{CommandID: providerAuthorityCommand(t), OriginCommandID: production.request.CommandID, FlowID: callback.FlowID, Disable: disable}
	before := proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	page, err := preview.service.ListDisabledProviderOrigins(preview.ctx, authority, ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: 32})
	proxyProviderDisableAssertDenied(t, err)
	if !reflect.DeepEqual(page, ProxyRetirementDiscoveryPage{}) {
		t.Fatal("unsealed preview source disclosed original custody")
	}
	refused, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, authority, request)
	proxyProviderDisableAssertDenied(t, err)
	if !reflect.DeepEqual(refused, identity.CommandResult{}) || proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != before {
		t.Fatal("unsealed preview source changed local original or grant")
	}
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: 92, Kind: kernel.OAuthProxyRetirePreview})
	if _, err := sealer.SealAdmittedProviderDisable(preview.ctx, source); err != nil {
		t.Fatal("seal exact admitted source on native preview origin", err)
	}
	var pruned bool
	if err := production.pool.Raw().QueryRow(production.ctx, `SELECT audit.prune_record(record_id,canonical_sha256)
 FROM audit.records WHERE record_id=$1`, "oauth-provider-authority:"+string(disable.CommandID)).Scan(&pruned); err != nil || !pruned {
		t.Fatal("prune fixture's exact production audit payload before preview cleanup", err)
	}
	before = proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	page, err = preview.service.ListDisabledProviderOrigins(preview.ctx, authority, ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: 32})
	want := []ProxyRetirementOrigin{{OriginCommandID: production.request.CommandID, FlowID: callback.FlowID}}
	if err != nil || !reflect.DeepEqual(page.Origins, want) || page.Scanned != 2 || page.NextAfterFlowID != "" || proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != before {
		t.Fatal("preview discovery failed to use sealed admission after source retention", page, err)
	}
	const stableSQL = `SELECT jsonb_build_array(
 (SELECT to_jsonb(b) FROM onetap_oauth.proxy_preview_bindings b WHERE tenant_id=$1 AND flow_id=$2),
 (SELECT jsonb_agg(to_jsonb(g)) FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$3),
 (SELECT jsonb_agg(to_jsonb(b) ORDER BY flow_id) FROM onetap_sessions.preauth_transactions b))::text`
	var newerBefore string
	if err := preview.pool.Raw().QueryRow(preview.ctx, stableSQL, oneTapStartTenant, string(newFlow), string(newStart.CommandID)).Scan(&newerBefore); err != nil {
		t.Fatal("retain newer preview custody, grant and all browser state", err)
	}
	result, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, authority, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Validate() != nil || result.Binding.CommandID != request.CommandID {
		t.Fatal("sealed retained source did not commit native preview retirement", err)
	}
	var erased, revoked bool
	raw, err := base64.RawURLEncoding.Strict().DecodeString(string(disable.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT version=3 AND proof_ciphertext IS NULL AND binding_ciphertext IS NOT NULL AND settled_at IS NULL
 AND retired_at IS NOT NULL AND retirement_source_command_id=$3 AND retirement_source_version=42
 FROM onetap_oauth.proxy_preview_bindings WHERE tenant_id=$1 AND flow_id=$2),
 (SELECT count(*)=1 AND bool_and(state='revoked' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$1 AND origin_command_id=$4 AND subject_id=$2 AND purpose='identity.oauth.callback')`,
		oneTapStartTenant, string(callback.FlowID), raw, string(production.request.CommandID)).Scan(&erased, &revoked); err != nil || !erased || !revoked {
		t.Fatal("native preview retirement did not erase exact proof and revoke unused callback grant", err)
	}
	committed := proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	replay, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, authority, request)
	if err != nil || !reflect.DeepEqual(replay, result) || proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != committed {
		t.Fatal("sealed preview replay repeated effects or changed receipt", err)
	}
	var newerAfter string
	if err := preview.pool.Raw().QueryRow(preview.ctx, stableSQL, oneTapStartTenant, string(newFlow), string(newStart.CommandID)).Scan(&newerAfter); err != nil || newerAfter != newerBefore {
		t.Fatal("old preview cleanup changed newer custody, grant or browser state", err)
	}
	providerAuthorityAssertState(t, production.ctx, primary, key, reenable.Next)
	denied, err := preview.service.Complete(preview.ctx, callback)
	if err == nil || denied.Session.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("sealed cleanup restored invalidated old preview handoff", err)
	}
	proxyPreviewSessionNoDelivery(t, denied)
	var sessions, families, issuances int
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*) FROM onetap_sessions.sessions),
 (SELECT count(*) FROM onetap_sessions.families),
 (SELECT count(*) FROM onetap_sessions.session_issuances)`).Scan(&sessions, &families, &issuances); err != nil || sessions != 0 || families != 0 || issuances != 0 {
		t.Fatal("retirement or rejected old handoff issued preview session state", err)
	}
	if preview.keys.opens.Load() != 0 {
		t.Fatal("cleanup or rejected old handoff opened provider bearer evidence")
	}
}
