//go:build integration

package postgres

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProxyRetirementDrainProductionResumesCommittedTargetAfterCheckpointFailure(t *testing.T) {
	f := newProxyStartIntegration(t)
	primary, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = primary
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 41, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(f.ctx, configure); err != nil {
		t.Fatal("configure provider before native originals", err)
	}
	firstRequest := f.request
	firstRequest.TransactionID = "AQEBAQEBAQEBAQEBAQEBAQ"
	secondRequest := freshProxyProviderEpochRequest(t, f.request)
	secondRequest.TransactionID = "AwMDAwMDAwMDAwMDAwMDAw"
	first, _ := startProxyProviderEpochOriginal(t, f, firstRequest, 41)
	second, _ := startProxyProviderEpochOriginal(t, f, secondRequest, 41)
	schema := f.forward.config.Schema
	proxyRetirementDiscoveryInstall(t, f.ctx, f.pool, schema, kernel.OAuthProxyRetireProduction)
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProviderDisableCascadeMigrationSource{Schema: schema, Version: 80})
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: 90, Kind: kernel.OAuthProxyRetireProduction})
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyRetirementDrainMigrationSource{Schema: schema, Version: 100})
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 41, Next: ProviderAuthorityState{Version: 42, ProfileVersion: f.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	admitted, err := operator.ApplyDisableCascade(f.ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit exact provider disable through the designated primary", err)
	}
	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 42, Next: ProviderAuthorityState{Version: 43, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(f.ctx, reenable); err != nil {
		t.Fatal("re-enable only the newer provider epoch", err)
	}
	freshRequest := freshProxyProviderEpochRequest(t, f.request)
	freshRequest.TransactionID = "AgICAgICAgICAgICAgICAg"
	fresh, _ := startProxyProviderEpochOriginal(t, f, freshRequest, 43)
	sealer, err := NewProxyCustodyFenceOperator(f.pool, primary, ProxyCustodyFenceOperatorConfig{
		Schema: schema, Kind: kernel.OAuthProxyRetireProduction, TenantID: key.TenantID,
		ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose native custody sealer", err)
	}
	source := ProxyCustodyFenceSealRequest{
		TenantID: key.TenantID, SourceCommandID: disable.CommandID, CascadeID: admitted.CascadeID, Generation: admitted.Generation,
	}
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: 92, Kind: kernel.OAuthProxyRetireProduction})
	if _, err := sealer.SealAdmittedProviderDisable(f.ctx, source); err != nil {
		t.Fatal("seal exact cutoff on actual native custody before draining", err)
	}
	authority, err := NewSealedProxyRetirementAuthority(sealer, source)
	if err != nil {
		t.Fatal("select exact sealed generation", err)
	}
	var pruned bool
	if err := primary.pool.Raw().QueryRow(f.ctx, `SELECT audit.prune_record(record_id,canonical_sha256)
 FROM audit.records WHERE record_id=$1`, "oauth-provider-authority:"+string(disable.CommandID)).Scan(&pruned); err != nil || !pruned {
		t.Fatal("retain only native admission rather than the source audit payload", err)
	}
	drain, err := NewProductionProxyRetirementDrain(f.forward, authority)
	if err != nil {
		t.Fatal("compose native production drain from the selected sealed authority", err)
	}
	const freshSQL = `SELECT jsonb_build_array(
 (SELECT to_jsonb(p) FROM onetap_oauth.proxy_transactions p WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT jsonb_agg(to_jsonb(g)) FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$3))::text`
	var freshBefore string
	if err := f.pool.Raw().QueryRow(f.ctx, freshSQL, oneTapStartTenant, string(fresh.TransactionID), string(fresh.CommandID)).Scan(&freshBefore); err != nil {
		t.Fatal("retain newer native custody and grant", err)
	}
	const failCheckpoint = `CREATE FUNCTION onetap_oauth.fixture_fail_drain_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF NEW.retired > OLD.retired THEN RAISE EXCEPTION 'fixture checkpoint unavailable'; END IF;
 RETURN NEW;
 END $$;
 CREATE TRIGGER fixture_fail_drain_checkpoint BEFORE UPDATE ON onetap_oauth.proxy_retirement_drains
 FOR EACH ROW EXECUTE FUNCTION onetap_oauth.fixture_fail_drain_checkpoint()`
	if _, err := f.pool.Raw().Exec(f.ctx, failCheckpoint); err != nil {
		t.Fatal("inject cursor-checkpoint failure after native retirement commits", err)
	}
	failed, err := drain.Step(f.ctx, 1)
	if err == nil || !reflect.DeepEqual(failed, ProxyRetirementDrainProgress{}) {
		t.Fatal("checkpoint failure did not return an error without claiming progress", failed, err)
	}

	type pendingTarget struct {
		Flow    identity.PreAuthTransactionID `json:"flow"`
		Origin  identity.CommandID            `json:"origin"`
		Command identity.CommandID            `json:"command"`
	}
	var page struct {
		Next    identity.PreAuthTransactionID `json:"next"`
		Targets []pendingTarget               `json:"targets"`
	}
	var pending, checkpoint string
	var retainedSource, retainedProvider, retainedVersion, after string
	var confirmed, retired uint64
	var exhausted bool
	const checkpointSQL = `SELECT to_jsonb(d)::text FROM onetap_oauth.proxy_retirement_drains d WHERE tenant_id=$1 AND cascade_id=$2 AND generation=$3`
	checkpointState := func() string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, checkpointSQL, oneTapStartTenant, string(admitted.CascadeID), admitted.Generation).Scan(&state); err != nil {
			t.Fatal("read the selected durable drain checkpoint", err)
		}
		return state
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT source_command_id,provider_id,source_version::text,after_flow_id,pending_page::text,confirmed,retired,exhausted
 FROM onetap_oauth.proxy_retirement_drains WHERE tenant_id=$1 AND cascade_id=$2 AND generation=$3`,
		oneTapStartTenant, string(admitted.CascadeID), admitted.Generation).
		Scan(&retainedSource, &retainedProvider, &retainedVersion, &after, &pending, &confirmed, &retired, &exhausted); err != nil {
		t.Fatal("read durable page after the failed acknowledgement", err)
	}
	if err := json.Unmarshal([]byte(pending), &page); err != nil {
		t.Fatal("decode native persisted page", err)
	}
	if retainedSource != string(disable.CommandID) || retainedProvider != key.ProviderID || retainedVersion != "42" ||
		after != "" || confirmed != 0 || retired != 0 || exhausted || page.Next != first.TransactionID || len(page.Targets) != 1 {
		t.Fatal("failed checkpoint changed selected source, cursor or unconfirmed page", pending)
	}
	target := page.Targets[0]
	if target.Flow != first.TransactionID || target.Origin != first.CommandID {
		t.Fatal("persisted page did not retain the exact authenticated original")
	}
	if _, err := identity.ParseCommandID(string(target.Command)); err != nil || target.Command == first.CommandID || target.Command == disable.CommandID {
		t.Fatal("page did not persist one independent canonical retirement command", err)
	}
	checkpoint = checkpointState()
	committed := proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions")
	var firstRetired, secondUntouched bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT version=3 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL AND handoff_ciphertext IS NULL
 AND binding_ciphertext IS NOT NULL AND retired_at IS NOT NULL FROM onetap_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT version=1 AND retired_at IS NULL FROM onetap_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$3)`,
		oneTapStartTenant, string(first.TransactionID), string(second.TransactionID)).Scan(&firstRetired, &secondUntouched); err != nil || !firstRetired || !secondUntouched {
		t.Fatal("one failed checkpoint did not leave exactly one native target retired", err)
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(target.Command))
	if err != nil {
		t.Fatal(err)
	}
	sourceCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(disable.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var exactCommittedEffects bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*)=1 FROM identity.commands WHERE command_id=$1 AND state='committed') AND
 (SELECT count(*)=1 FROM audit.identity_command_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 AND bool_and(state='revoked' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$2 AND origin_command_id=$3 AND subject_id=$4 AND purpose='identity.oauth.proxy-forward') AND
 (SELECT retirement_source_command_id=$5 AND retirement_source_version=42
 FROM onetap_oauth.proxy_transactions WHERE tenant_id=$2 AND transaction_id=$4)`,
		command, oneTapStartTenant, string(first.CommandID), string(first.TransactionID), sourceCommand).Scan(&exactCommittedEffects); err != nil || !exactCommittedEffects {
		t.Fatal("unacknowledged target did not retain its one committed command and exact grant revocation", err)
	}
	if _, err := drain.Step(f.ctx, 1); err == nil || checkpointState() != checkpoint || proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != committed {
		t.Fatal("failed retry replaced the pending command, advanced its cursor or duplicated native effects", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fixture_fail_drain_checkpoint ON onetap_oauth.proxy_retirement_drains;
 DROP FUNCTION onetap_oauth.fixture_fail_drain_checkpoint()`); err != nil {
		t.Fatal("remove only fixture-owned checkpoint failure", err)
	}
	restarted, err := NewProductionProxyRetirementDrain(f.forward, authority)
	if err != nil {
		t.Fatal("reconstruct native operator without in-memory target or command state", err)
	}
	progress, err := restarted.Step(f.ctx, 1)
	if err != nil || progress.Retired != 1 || progress.AfterFlowID != first.TransactionID || progress.Remaining != 0 || progress.Exhausted {
		t.Fatal("restart did not acknowledge the saved terminal kernel command", progress, err)
	}
	if proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != committed {
		t.Fatal("terminal command acknowledgement repeated retirement effects")
	}
	progress, err = restarted.Step(f.ctx, 1)
	if err != nil || progress.Retired != 1 || progress.AfterFlowID != fresh.TransactionID || progress.Remaining != 0 || progress.Exhausted {
		t.Fatal("empty filtered page did not advance its scanned cursor without retiring newer custody", progress, err)
	}
	if proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != committed {
		t.Fatal("empty filtered page mutated native effects")
	}
	progress, err = restarted.Step(f.ctx, 1)
	if err != nil || progress.Retired != 2 || progress.Remaining != 0 || !progress.Exhausted {
		t.Fatal("bounded traversal did not retire the second old original and exhaust", progress, err)
	}
	finishedCheckpoint := checkpointState()
	finishedEffects := proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions")
	restarted, err = NewProductionProxyRetirementDrain(f.forward, authority)
	if err != nil {
		t.Fatal(err)
	}
	sticky, err := restarted.Step(f.ctx, 1)
	if err != nil || !reflect.DeepEqual(sticky, progress) || checkpointState() != finishedCheckpoint ||
		proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != finishedEffects {
		t.Fatal("exhaustion did not remain durable and effect-free across restart", sticky, err)
	}
	var freshAfter string
	if err := f.pool.Raw().QueryRow(f.ctx, freshSQL, oneTapStartTenant, string(fresh.TransactionID), string(fresh.CommandID)).Scan(&freshAfter); err != nil || freshAfter != freshBefore {
		t.Fatal("historical drain changed newer-epoch native custody or grant", err)
	}
	var oldRetired, localOnly bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*)=2 AND bool_and(version=3 AND retired_at IS NOT NULL AND state_proof_ciphertext IS NULL
 AND pkce_ciphertext IS NULL AND handoff_ciphertext IS NULL) FROM onetap_oauth.proxy_transactions WHERE transaction_id IN ($1,$2)),
 (SELECT status=$5 FROM onetap_oauth.provider_disable_cascades WHERE tenant_id=$3 AND source_command_id=$4)
 AND (SELECT count(*)=1 FROM public.outbox_messages WHERE id=$4 AND topic='social_provider.disabled.v1')
 AND (SELECT count(*)=2 FROM public.outbox_messages WHERE topic='oauth.proxy.custody_retired.v1')
 AND (SELECT count(*)=0 FROM identity.users) AND (SELECT count(*)=0 FROM identity.accounts)
 AND (SELECT count(*)=0 FROM onetap_sessions.sessions)`,
		string(first.TransactionID), string(second.TransactionID), oneTapStartTenant, string(disable.CommandID), int16(identity.RevocationPending)).Scan(&oldRetired, &localOnly); err != nil || !oldRetired || !localOnly {
		t.Fatal("drain failed to retire only old custody or acknowledged aggregate cascade/session effects", err)
	}
	providerAuthorityAssertState(t, f.ctx, primary, key, reenable.Next)
}

func TestProxyRetirementDrainPreviewUsesItsOwnCustodyAndSealedSource(t *testing.T) {
	production, preview, callback, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
	primary := production.forward.providerAuthority
	schema := preview.completion.start.config.Schema
	secondOld := proxyCustodyFencePreviewRequest(t, production, preview, proxyPreviewAuthorityEpoch)
	if err := preview.service.Bind(preview.ctx, secondOld); err != nil {
		t.Fatal("bind a second genuine old original before provider disable", err)
	}
	proxyRetirementDiscoveryInstall(t, preview.ctx, preview.pool, schema, kernel.OAuthProxyRetirePreview)
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProviderDisableCascadeMigrationSource{Schema: production.forward.config.Schema, Version: 80})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: 90, Kind: kernel.OAuthProxyRetirePreview})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyRetirementDrainMigrationSource{Schema: schema, Version: 100})
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	admitted, err := operator.ApplyDisableCascade(production.ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit preview disable on designated production primary", err)
	}
	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: disable.Next.Version,
		Next:      ProviderAuthorityState{Version: disable.Next.Version + 1, ProfileVersion: production.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(production.ctx, reenable); err != nil {
		t.Fatal("re-enable a distinct epoch before new native preview binding", err)
	}
	newer := proxyCustodyFencePreviewRequest(t, production, preview, reenable.Next.Version)
	if err := preview.service.Bind(preview.ctx, newer); err != nil {
		t.Fatal("bind the newer native origin into preview custody", err)
	}
	sealer, err := NewProxyCustodyFenceOperator(preview.pool, primary, ProxyCustodyFenceOperatorConfig{
		Schema: schema, Kind: kernel.OAuthProxyRetirePreview, TenantID: key.TenantID,
		ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose separate local preview custody and provider primary", err)
	}
	source := ProxyCustodyFenceSealRequest{
		TenantID: key.TenantID, SourceCommandID: disable.CommandID, CascadeID: admitted.CascadeID, Generation: admitted.Generation,
	}
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: 92, Kind: kernel.OAuthProxyRetirePreview})
	if _, err := sealer.SealAdmittedProviderDisable(preview.ctx, source); err != nil {
		t.Fatal("seal actual preview custody against admitted cutoff", err)
	}
	authority, err := NewSealedProxyRetirementAuthority(sealer, source)
	if err != nil {
		t.Fatal(err)
	}
	var pruned bool
	if err := production.pool.Raw().QueryRow(production.ctx, `SELECT audit.prune_record(record_id,canonical_sha256)
 FROM audit.records WHERE record_id=$1`, "oauth-provider-authority:"+string(disable.CommandID)).Scan(&pruned); err != nil || !pruned {
		t.Fatal("prune source audit before the independent preview drain", err)
	}
	productionBefore := proxyRetirementDiscoverySnapshot(t, production.ctx, production.pool, "proxy_transactions")
	const newerSQL = `SELECT jsonb_build_array(
 (SELECT to_jsonb(p) FROM onetap_oauth.proxy_preview_bindings p WHERE tenant_id=$1 AND flow_id=$2),
 (SELECT jsonb_agg(to_jsonb(g)) FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$3),
 (SELECT jsonb_agg(to_jsonb(p) ORDER BY flow_id) FROM onetap_sessions.preauth_transactions p))::text`
	var newerBefore string
	if err := preview.pool.Raw().QueryRow(preview.ctx, newerSQL, oneTapStartTenant, string(newer.Binding.TransactionID), string(newer.Binding.CommandID)).Scan(&newerBefore); err != nil {
		t.Fatal("retain newer preview custody, grant and all browser state", err)
	}
	drain, err := NewPreviewProxyRetirementDrain(preview.service, authority)
	if err != nil {
		t.Fatal("construct preview's native selected local drain", err)
	}
	progress, err := drain.Step(preview.ctx, 32)
	if err != nil || progress.Retired != 1 || progress.Remaining != 1 || progress.Exhausted || progress.AfterFlowID != "" {
		t.Fatal("preview first step did not retain its unfinished two-target page after exactly one retirement", progress, err)
	}
	var oneRetired, partialPage bool
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*)=2 AND count(*) FILTER (WHERE version=3 AND retired_at IS NOT NULL)=1
 AND count(*) FILTER (WHERE version=1 AND retired_at IS NULL)=1 FROM onetap_oauth.proxy_preview_bindings
 WHERE tenant_id=$1 AND flow_id IN ($2,$3)),
 (SELECT confirmed=1 AND retired=1 AND NOT exhausted AND after_flow_id='' AND jsonb_array_length(pending_page->'targets')=2
 FROM onetap_oauth.proxy_retirement_drains WHERE tenant_id=$1 AND cascade_id=$4 AND generation=$5)`,
		oneTapStartTenant, string(callback.FlowID), string(secondOld.Binding.TransactionID), string(admitted.CascadeID), admitted.Generation).
		Scan(&oneRetired, &partialPage); err != nil || !oneRetired || !partialPage {
		t.Fatal("partial preview page did not persist its confirmed index while leaving the second old original untouched", err)
	}
	restarted, err := NewPreviewProxyRetirementDrain(preview.service, authority)
	if err != nil {
		t.Fatal("reconstruct preview drain with its partially confirmed durable page", err)
	}
	progress, err = restarted.Step(preview.ctx, 1)
	if err != nil || progress.Retired != 2 || progress.Remaining != 0 || !progress.Exhausted {
		t.Fatal("preview restart did not finish only the remaining target from its saved page", progress, err)
	}
	sourceCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(disable.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var erased, revoked, selected bool
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*)=2 AND bool_and(version=3 AND proof_ciphertext IS NULL AND binding_ciphertext IS NOT NULL AND settled_at IS NULL
 AND retired_at IS NOT NULL AND retirement_source_command_id=$7 AND retirement_source_version=42)
 FROM onetap_oauth.proxy_preview_bindings WHERE tenant_id=$1 AND flow_id IN ($2,$8)),
 (SELECT count(*)=2 AND bool_and(state='revoked' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$1 AND ((origin_command_id=$3 AND subject_id=$2) OR (origin_command_id=$9 AND subject_id=$8))
 AND purpose='identity.oauth.callback'),
 (SELECT count(*)=1 AND bool_and(exhausted AND retired=2 AND role=2 AND deployment=$6 AND pending_page IS NULL)
 FROM onetap_oauth.proxy_retirement_drains WHERE tenant_id=$1 AND cascade_id=$4 AND generation=$5)`,
		oneTapStartTenant, string(callback.FlowID), string(production.request.CommandID), string(admitted.CascadeID), admitted.Generation, production.target.Deployment,
		sourceCommand, string(secondOld.Binding.TransactionID), string(secondOld.Binding.CommandID)).
		Scan(&erased, &revoked, &selected); err != nil || !erased || !revoked || !selected {
		t.Fatal("preview drain failed exact native proof erasure, callback grant revocation or local role checkpoint", err)
	}
	committed := proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	restarted, err = NewPreviewProxyRetirementDrain(preview.service, authority)
	if err != nil {
		t.Fatal(err)
	}
	sticky, err := restarted.Step(preview.ctx, 1)
	if err != nil || !reflect.DeepEqual(sticky, progress) || proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != committed {
		t.Fatal("preview exhausted restart changed local effects", sticky, err)
	}
	var newerAfter string
	if err := preview.pool.Raw().QueryRow(preview.ctx, newerSQL, oneTapStartTenant, string(newer.Binding.TransactionID), string(newer.Binding.CommandID)).Scan(&newerAfter); err != nil || newerAfter != newerBefore {
		t.Fatal("preview drain changed newer custody, grant or browser state", err)
	}
	if proxyRetirementDiscoverySnapshot(t, production.ctx, production.pool, "proxy_transactions") != productionBefore {
		t.Fatal("preview local drain mutated designated production origin")
	}
	var pending, noSession bool
	if err := production.pool.Raw().QueryRow(production.ctx, `SELECT status=$3 FROM onetap_oauth.provider_disable_cascades
 WHERE tenant_id=$1 AND source_command_id=$2`, oneTapStartTenant, string(disable.CommandID), int16(identity.RevocationPending)).Scan(&pending); err != nil || !pending {
		t.Fatal("preview exhaustion acknowledged aggregate source cascade", err)
	}
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*)=0 FROM onetap_sessions.sessions) AND (SELECT count(*)=0 FROM onetap_sessions.families)
 AND (SELECT count(*)=0 FROM onetap_sessions.session_issuances)
 AND (SELECT count(*)=2 FROM public.outbox_messages WHERE topic='oauth.proxy.custody_retired.v1')`).Scan(&noSession); err != nil || !noSession || preview.keys.opens.Load() != 0 {
		t.Fatal("preview local drain opened bearer evidence, issued sessions or duplicated retirement delivery", err)
	}
}
