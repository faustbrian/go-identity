//go:build integration

package postgres

import (
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"testing"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProxyRetirementPreviewCommitsExactDisableEffects(t *testing.T) {
	production, preview, callback, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
	history, err := (ProxyRetirementMigrationSource{
		Schema: preview.completion.start.config.Schema, Version: 70, Kind: kernel.OAuthProxyRetirePreview,
	}).Load(preview.ctx)
	if err != nil || len(history) != 2 {
		t.Fatal("load both preview retirement migrations", err)
	}
	for _, migration := range history {
		tx, err := preview.pool.Raw().Begin(preview.ctx)
		if err != nil {
			t.Fatal("begin preview retirement migration", err)
		}
		if _, err := tx.Exec(preview.ctx, migration.UpSQL()); err != nil {
			_ = tx.Rollback(preview.ctx)
			t.Fatal("install preview retirement history", err)
		}
		if err := tx.Commit(preview.ctx); err != nil {
			t.Fatal("commit preview retirement migration", err)
		}
	}
	reader, err := auditpg.New(production.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct retained production disable reader", err)
	}
	authority, err := NewProxyRetirementAuthority(reader, oneTapStartActor)
	if err != nil {
		t.Fatal("construct authenticated retirement authority", err)
	}

	var oldGrantID, oldGrantProvenance string
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT capability_id,(to_jsonb(g)-'state')::text
 FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$2
 AND subject_id=$3 AND purpose='identity.oauth.callback' AND state='issued' AND uses=0`,
		oneTapStartTenant, string(production.request.CommandID), string(callback.FlowID)).Scan(&oldGrantID, &oldGrantProvenance); err != nil {
		t.Fatal("read the exact original issued preview grant", err)
	}
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(production.ctx, disable); err != nil || state != disable.Next {
		t.Fatal("commit original provider disable through its production operator", err)
	}
	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: disable.Next.Version,
		Next:      ProviderAuthorityState{Version: disable.Next.Version + 1, ProfileVersion: production.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(production.ctx, reenable); err != nil || state != reenable.Next {
		t.Fatal("re-enable the provider under a distinct authority epoch", err)
	}

	newFlow, newCookie := preview.issueBrowser(t, production.request.Remember)
	newStart := production.request
	newStart.CommandID = providerAuthorityCommand(t)
	newStart.TransactionID = newFlow
	newStart.RequestFingerprint = sha256.Sum256([]byte("newer-preview-origin"))
	started, err := production.start.Start(production.ctx, newStart)
	if err != nil {
		t.Fatal("start a real independent newer-epoch preview origin", err)
	}
	newBinding, ok := started.Binding()
	if !ok || newBinding.ProviderAuthorityEpoch != reenable.Next.Version {
		t.Fatal("new preview origin did not retain the re-enabled epoch")
	}
	if err := preview.service.Bind(preview.ctx, ProxyPreviewBindRequest{
		Binding: newBinding, FlowCookie: newCookie, Origin: production.target.Origin,
		Network: "192.0.2.21", Device: "newer-preview-browser",
	}); err != nil {
		t.Fatal("bind the newer origin through the real preview owner", err)
	}

	snapshot := func(query string, args ...any) string {
		t.Helper()
		var value string
		if err := preview.pool.Raw().QueryRow(preview.ctx, query, args...).Scan(&value); err != nil {
			t.Fatal("snapshot exact preview effects", err)
		}
		return value
	}
	const allCustody = `SELECT jsonb_agg(to_jsonb(b) ORDER BY flow_id)::text FROM onetap_oauth.proxy_preview_bindings b`
	const allGrants = `SELECT jsonb_agg(to_jsonb(g) ORDER BY capability_id)::text FROM public.capability_identity_one_use g`
	const browsers = `SELECT jsonb_agg(to_jsonb(p) ORDER BY flow_id)::text FROM onetap_sessions.preauth_transactions p`
	const stableOriginal = `SELECT (to_jsonb(b)-ARRAY['version','proof_ciphertext','retirement_source_command_id','retirement_source_version','retired_at'])::text
 FROM onetap_oauth.proxy_preview_bindings b WHERE tenant_id=$1 AND flow_id=$2`
	const unrelatedCustody = `SELECT to_jsonb(b)::text FROM onetap_oauth.proxy_preview_bindings b WHERE tenant_id=$1 AND flow_id=$2`
	const unrelatedGrants = `SELECT jsonb_agg(to_jsonb(g) ORDER BY capability_id)::text
 FROM public.capability_identity_one_use g WHERE capability_id<>$1`
	beforeCustody, beforeGrants := snapshot(allCustody), snapshot(allGrants)
	beforeBrowsers := snapshot(browsers)
	original := snapshot(stableOriginal, oneTapStartTenant, string(callback.FlowID))
	newCustody := snapshot(unrelatedCustody, oneTapStartTenant, string(newFlow))
	newGrants := snapshot(unrelatedGrants, oldGrantID)

	request := ProxyOriginRetirementRequest{
		CommandID: providerAuthorityCommand(t), OriginCommandID: production.request.CommandID,
		FlowID: callback.FlowID, Disable: disable,
	}
	assertEffects := func(t *testing.T, command identity.CommandID, wantAudits, wantEvents int) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(command))
		if err != nil {
			t.Fatal(err)
		}
		var audits, events int
		if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*) FROM audit.identity_command_bindings WHERE tenant_id=$1 AND command_id=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2)`,
			oneTapStartTenant, raw).Scan(&audits, &events); err != nil || audits != wantAudits || events != wantEvents {
			t.Fatal("retirement did not retain exactly one audit and lifecycle effect per committed command", audits, events, err)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*ProxyOriginRetirementRequest)
	}{
		{"wrong original", func(r *ProxyOriginRetirementRequest) { r.OriginCommandID = newStart.CommandID }},
		{"wrong provider", func(r *ProxyOriginRetirementRequest) { r.Disable.Key.ProviderID = "another-provider" }},
		{"uncommitted source", func(r *ProxyOriginRetirementRequest) { r.Disable.CommandID = providerAuthorityCommand(t) }},
		{"newer epoch", func(r *ProxyOriginRetirementRequest) { r.Disable = reenable }},
		{"newer original epoch", func(r *ProxyOriginRetirementRequest) {
			r.OriginCommandID, r.FlowID = newStart.CommandID, newFlow
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			changed.CommandID = providerAuthorityCommand(t)
			test.change(&changed)
			result, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, authority, changed)
			if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("substituted original or disable source committed preview retirement", err)
			}
			if snapshot(allCustody) != beforeCustody || snapshot(allGrants) != beforeGrants || snapshot(browsers) != beforeBrowsers {
				t.Fatal("denied retirement changed original or independent preview custody")
			}
			wantAudits := 0
			if test.name == "wrong original" || test.name == "newer original epoch" {
				wantAudits = 1 // Authenticated source reached the protected Work denial.
			}
			assertEffects(t, changed.CommandID, wantAudits, 0)
		})
	}

	result, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, authority, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Validate() != nil ||
		result.Binding.CommandID != request.CommandID || result.Feature == nil ||
		result.Feature.Operation != kernel.OAuthProxyOriginRetirementOperation() {
		t.Fatal("authenticated original disable did not commit preview retirement", err)
	}
	var retired bool
	source, err := base64.RawURLEncoding.DecodeString(string(disable.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT version=3 AND proof_ciphertext IS NULL
 AND binding_ciphertext IS NOT NULL AND settled_at IS NULL AND retirement_source_command_id=$3
 AND retirement_source_version=$4::numeric AND retired_at IS NOT NULL AND retired_at>=issued_at
 FROM onetap_oauth.proxy_preview_bindings WHERE tenant_id=$1 AND flow_id=$2`,
		oneTapStartTenant, string(callback.FlowID), source, disable.Next.Version).Scan(&retired); err != nil || !retired {
		t.Fatal("preview retirement retained proof, lost provenance or fabricated settlement", err)
	}
	var state, grantProvenance string
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT state,(to_jsonb(g)-'state')::text
 FROM public.capability_identity_one_use g WHERE capability_id=$1`, oldGrantID).Scan(&state, &grantProvenance); err != nil || state != "revoked" || grantProvenance != oldGrantProvenance {
		t.Fatal("retirement did not revoke only the exact unused grant while preserving its provenance", err)
	}
	if snapshot(stableOriginal, oneTapStartTenant, string(callback.FlowID)) != original ||
		snapshot(unrelatedCustody, oneTapStartTenant, string(newFlow)) != newCustody ||
		snapshot(unrelatedGrants, oldGrantID) != newGrants || snapshot(browsers) != beforeBrowsers {
		t.Fatal("retirement changed authenticated binding, original browser or newer-epoch custody")
	}
	assertEffects(t, request.CommandID, 1, 1)
	afterCustody, afterGrants := snapshot(allCustody), snapshot(allGrants)
	replay, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, authority, request)
	if err != nil || !reflect.DeepEqual(replay, result) {
		t.Fatal("exact retirement retry did not recover the same immutable committed receipt", err)
	}
	if snapshot(allCustody) != afterCustody || snapshot(allGrants) != afterGrants || snapshot(browsers) != beforeBrowsers {
		t.Fatal("exact retirement replay repeated or changed durable effects")
	}
	assertEffects(t, request.CommandID, 1, 1)
	var sessions, families, issuances int
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*) FROM onetap_sessions.sessions),(SELECT count(*) FROM onetap_sessions.families),
 (SELECT count(*) FROM onetap_sessions.session_issuances)`).Scan(&sessions, &families, &issuances); err != nil || sessions != 0 || families != 0 || issuances != 0 {
		t.Fatal("retirement issued preview session state", err)
	}
	if preview.keys.opens.Load() != 0 {
		t.Fatal("retirement opened provider evidence instead of only authenticating its binding")
	}
	proxyPreviewProductionHasNoIdentity(t, production)
}
