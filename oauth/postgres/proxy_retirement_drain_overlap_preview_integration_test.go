//go:build integration

package postgres

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProxyRetirementDrainPreviewAcknowledgesLaterSealedDisableWithoutSuccessEffects(t *testing.T) {
	production, preview, callback, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
	primary := production.forward.providerAuthority
	schema := preview.completion.start.config.Schema
	proxyRetirementDiscoveryInstall(t, preview.ctx, preview.pool, schema, kernel.OAuthProxyRetirePreview)
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProviderDisableCascadeMigrationSource{Schema: production.forward.config.Schema, Version: 80})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: 90, Kind: kernel.OAuthProxyRetirePreview})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyRetirementDrainMigrationSource{Schema: schema, Version: 100})
	firstDisable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	firstAdmission, err := operator.ApplyDisableCascade(production.ctx, firstDisable, time.Hour)
	if err != nil {
		t.Fatal("admit G1 after the fixture's genuine preview Bind", err)
	}
	sealer, err := NewProxyCustodyFenceOperator(preview.pool, primary, ProxyCustodyFenceOperatorConfig{
		Schema: schema, Kind: kernel.OAuthProxyRetirePreview, TenantID: key.TenantID,
		ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose actual preview custody with designated provider primary", err)
	}
	firstSource := ProxyCustodyFenceSealRequest{
		TenantID: key.TenantID, SourceCommandID: firstDisable.CommandID,
		CascadeID: firstAdmission.CascadeID, Generation: firstAdmission.Generation,
	}
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: 92, Kind: kernel.OAuthProxyRetirePreview})
	if _, err := sealer.SealAdmittedProviderDisable(preview.ctx, firstSource); err != nil {
		t.Fatal("seal G1 on the actual preview custody database", err)
	}
	firstAuthority, err := NewSealedProxyRetirementAuthority(sealer, firstSource)
	if err != nil {
		t.Fatal("select the first sealed disable", err)
	}
	found, err := preview.service.ListDisabledProviderOrigins(preview.ctx, firstAuthority, ProxyRetirementDiscoveryRequest{Disable: firstDisable, ScanLimit: 1})
	wantOrigin := ProxyRetirementOrigin{OriginCommandID: production.request.CommandID, FlowID: callback.FlowID}
	if err != nil || !reflect.DeepEqual(found.Origins, []ProxyRetirementOrigin{wantOrigin}) || found.NextAfterFlowID != "" {
		t.Fatal("discover the exact genuinely bound preview origin under G1", found, err)
	}
	page, err := newProxyRetirementDrainPage(found, "")
	if err != nil {
		t.Fatal("assign G1's independent pending retirement command", err)
	}
	store := proxyRetirementDrainStore{
		pool: preview.pool.Raw(), table: rpQuotedSchema(schema) + ".proxy_retirement_drains",
		key: proxyRetirementDrainKey{source: firstAdmission, kind: kernel.OAuthProxyRetirePreview, deployment: production.target.Deployment},
	}
	state := proxyRetirementDrainState{page: page}
	if err := store.save(preview.ctx, &state); err != nil {
		t.Fatal("persist the real G1 page before any competing retirement", err)
	}
	pending, err := store.read(preview.ctx)
	if err != nil || !reflect.DeepEqual(pending, state) || pending.retired != 0 || pending.confirmed != 0 || pending.exhausted {
		t.Fatal("G1 did not retain its exact unconfirmed page and command", err)
	}
	target := pending.page.Targets[0]

	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: firstDisable.Next.Version,
		Next:      ProviderAuthorityState{Version: firstDisable.Next.Version + 1, ProfileVersion: production.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(production.ctx, reenable); err != nil {
		t.Fatal("re-enable before admitting a distinct later disable", err)
	}
	secondDisable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: reenable.Next.Version,
		Next:      ProviderAuthorityState{Version: reenable.Next.Version + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	secondAdmission, err := operator.ApplyDisableCascade(production.ctx, secondDisable, time.Hour)
	if err != nil || secondAdmission.CascadeID == firstAdmission.CascadeID {
		t.Fatal("admit independent G2 through the native provider operator", err)
	}
	secondSource := ProxyCustodyFenceSealRequest{
		TenantID: key.TenantID, SourceCommandID: secondDisable.CommandID,
		CascadeID: secondAdmission.CascadeID, Generation: secondAdmission.Generation,
	}
	if _, err := sealer.SealAdmittedProviderDisable(preview.ctx, secondSource); err != nil {
		t.Fatal("actually seal G2 instead of inferring coverage from its version", err)
	}
	secondAuthority, err := NewSealedProxyRetirementAuthority(sealer, secondSource)
	if err != nil {
		t.Fatal("select the distinct later sealed disable", err)
	}
	latestEnable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: secondDisable.Next.Version,
		Next:      ProviderAuthorityState{Version: secondDisable.Next.Version + 1, ProfileVersion: production.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(production.ctx, latestEnable); err != nil {
		t.Fatal("re-enable beyond both sealed cutoffs for an independent newer binding", err)
	}
	preview.service, err = NewProxyPreviewServiceWithCustodyFence(preview.completion, preview.config, primary)
	if err != nil {
		t.Fatal("select the native preview writer required by activated custody fences", err)
	}
	newer := proxyCustodyFencePreviewRequest(t, production, preview, latestEnable.Next.Version)
	if err := preview.service.Bind(preview.ctx, newer); err != nil {
		t.Fatal("genuinely bind the newer non-covered preview origin", err)
	}
	proxyCustodyFenceAssertProjection(t, preview.ctx, preview.pool, "proxy_preview_bindings", "flow_id", string(newer.Binding.TransactionID), newer.Binding)
	var newerLive bool
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT version=1 AND proof_ciphertext IS NOT NULL AND retired_at IS NULL
 FROM onetap_oauth.proxy_preview_bindings WHERE tenant_id=$1 AND flow_id=$2) AND
 (SELECT count(*)=1 AND bool_and(state='issued' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$1 AND origin_command_id=$3 AND subject_id=$2 AND purpose='identity.oauth.callback')`,
		oneTapStartTenant, string(newer.Binding.TransactionID), string(newer.Binding.CommandID)).Scan(&newerLive); err != nil || !newerLive {
		t.Fatal("newer non-covered origin did not retain real custody and an unused callback grant", err)
	}
	const newerSQL = `SELECT jsonb_build_array(
 (SELECT to_jsonb(p) FROM onetap_oauth.proxy_preview_bindings p WHERE tenant_id=$1 AND flow_id=$2),
 (SELECT jsonb_agg(to_jsonb(g) ORDER BY capability_id) FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$3),
 (SELECT jsonb_agg(to_jsonb(p) ORDER BY flow_id) FROM onetap_sessions.preauth_transactions p))::text`
	var newerBefore string
	if err := preview.pool.Raw().QueryRow(preview.ctx, newerSQL, oneTapStartTenant, string(newer.Binding.TransactionID), string(newer.Binding.CommandID)).Scan(&newerBefore); err != nil {
		t.Fatal("retain newer custody, callback grant and browser state before overlap", err)
	}
	productionBefore := proxyRetirementDiscoverySnapshot(t, production.ctx, production.pool, "proxy_transactions")
	manual := ProxyOriginRetirementRequest{
		CommandID: providerAuthorityCommand(t), OriginCommandID: target.Origin, FlowID: target.Flow, Disable: secondDisable,
	}
	if manual.CommandID == target.Command {
		t.Fatal("G2's trusted manual retirement must not reuse G1's saved command")
	}
	winner, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, secondAuthority, manual)
	if err != nil || winner.Validate() != nil || winner.Outcome != identity.CommitOutcomeCommitted || winner.Binding.CommandID != manual.CommandID {
		t.Fatal("trusted G2 retirement of the exact preview origin did not commit first", winner, err)
	}
	stillPending, err := store.read(preview.ctx)
	if err != nil || !reflect.DeepEqual(stillPending, pending) {
		t.Fatal("G2's winner replaced or acknowledged G1's durable pending command", err)
	}
	drain, err := NewPreviewProxyRetirementDrain(preview.service, firstAuthority)
	if err != nil {
		t.Fatal("reconstruct G1's preview drain from its persisted page", err)
	}
	progress, err := drain.Step(preview.ctx, 1)
	if err != nil || !progress.Exhausted || progress.Retired != 1 || progress.Remaining != 0 || progress.AfterFlowID != "" {
		t.Fatal("G1 did not confirm its covered original after the later sealed G2 retirement", progress, err)
	}
	finished, err := store.read(preview.ctx)
	if err != nil || finished.page != nil || finished.confirmed != 0 || finished.retired != 1 || !finished.exhausted {
		t.Fatal("G1's covered-target confirmation did not durably finish its own page", err)
	}
	decodeCommand := func(command identity.CommandID) []byte {
		t.Helper()
		raw, err := base64.RawURLEncoding.Strict().DecodeString(string(command))
		if err != nil {
			t.Fatal("decode canonical command identity", err)
		}
		return raw
	}
	drainCommand, winnerCommand := decodeCommand(target.Command), decodeCommand(manual.CommandID)
	var journalState, terminalClass string
	var terminal []byte
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT state,terminal_class,result FROM identity.commands WHERE command_id=$1`, drainCommand).
		Scan(&journalState, &terminalClass, &terminal); err != nil {
		t.Fatal("read G1's original command-bound terminal journal", err)
	}
	var recorded identity.CommandResult
	if err := json.Unmarshal(terminal, &recorded); err != nil || recorded.Validate() != nil || journalState != "aborted" || terminalClass != "conflict" ||
		recorded.Outcome != identity.CommitOutcomeNotCommitted || recorded.Binding.CommandID != target.Command ||
		recorded.Binding.TenantID != key.TenantID || recorded.Binding.CorrelationID != string(target.Origin) ||
		recorded.Binding.RecordID != string(target.Flow) || recorded.Binding.AnonymousFlowID != string(target.Flow) ||
		recorded.Binding.OperationID != kernel.OAuthProxyOriginRetirementOperation().OperationID {
		t.Fatal("G1 confirmation did not retain its exact original no-change outcome", err)
	}
	var exactEffects bool
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT
 (SELECT count(*)=1 FROM identity.commands WHERE command_id=$1 AND state='committed') AND
 (SELECT count(*)=1 FROM identity.commands WHERE purpose=$4 AND state='committed') AND
 (SELECT count(*)=1 FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id
 WHERE b.command_id=$1 AND r.outcome=$9) AND
 (SELECT count(*)=1 FROM audit.records WHERE action='identity.oauth.proxy_custody.retire' AND outcome=$9) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 AND bool_and(r.outcome<>$9) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id
 WHERE b.command_id=$2) AND
 (SELECT count(*)=0 FROM public.identity_outbox_bindings WHERE command_id=$2) AND
 (SELECT count(*)=1 FROM public.outbox_messages WHERE topic='oauth.proxy.custody_retired.v1') AND
 (SELECT version=3 AND proof_ciphertext IS NULL AND binding_ciphertext IS NOT NULL AND settled_at IS NULL
 AND retired_at IS NOT NULL AND retirement_source_command_id=$3 AND retirement_source_version=$8::numeric
 FROM onetap_oauth.proxy_preview_bindings WHERE tenant_id=$5 AND flow_id=$6) AND
 (SELECT count(*)=1 AND bool_and(state='revoked' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$5 AND origin_command_id=$7 AND subject_id=$6 AND purpose='identity.oauth.callback')`,
		winnerCommand, drainCommand, decodeCommand(secondDisable.CommandID), kernel.OAuthProxyOriginRetirementOperation().OperationID,
		oneTapStartTenant, string(target.Flow), string(target.Origin), providerAuthorityVersion(secondDisable.Next.Version), int16(audit.OutcomeSucceeded)).Scan(&exactEffects); err != nil || !exactEffects {
		t.Fatal("G1 acknowledgement replaced G2's provenance or added success effects instead of preserving its sole retirement", err)
	}
	stable := proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	drainRequest := ProxyOriginRetirementRequest{CommandID: target.Command, OriginCommandID: target.Origin, FlowID: target.Flow, Disable: firstDisable}
	for range 2 {
		replay, err := preview.service.RetireDisabledProviderOrigin(preview.ctx, firstAuthority, drainRequest)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || !reflect.DeepEqual(replay, recorded) ||
			proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != stable {
			t.Fatal("G1's original no-change journal was not replay-sticky and effect-free", replay, err)
		}
	}
	var replayTerminal []byte
	if err := preview.pool.Raw().QueryRow(preview.ctx, `SELECT result FROM identity.commands WHERE command_id=$1`, drainCommand).Scan(&replayTerminal); err != nil || !bytes.Equal(terminal, replayTerminal) {
		t.Fatal("replay rewrote G1's immutable NotCommitted journal", err)
	}
	restarted, err := NewPreviewProxyRetirementDrain(preview.service, firstAuthority)
	if err != nil {
		t.Fatal("restart the locally exhausted G1 preview drain", err)
	}
	sticky, err := restarted.Step(preview.ctx, 1)
	afterRestart, readErr := store.read(preview.ctx)
	if err != nil || readErr != nil || !reflect.DeepEqual(sticky, progress) || !reflect.DeepEqual(afterRestart, finished) ||
		proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != stable {
		t.Fatal("G1 restart repeated effects or changed its completed overlap checkpoint", sticky, err, readErr)
	}
	var newerAfter string
	if err := preview.pool.Raw().QueryRow(preview.ctx, newerSQL, oneTapStartTenant, string(newer.Binding.TransactionID), string(newer.Binding.CommandID)).Scan(&newerAfter); err != nil || newerAfter != newerBefore {
		t.Fatal("the overlapping disables changed newer preview custody, its grant or browser state", err)
	}
	if proxyRetirementDiscoverySnapshot(t, production.ctx, production.pool, "proxy_transactions") != productionBefore || preview.keys.opens.Load() != 0 {
		t.Fatal("the preview overlap changed production custody or opened provider bearer evidence")
	}
	providerAuthorityAssertState(t, production.ctx, primary, key, latestEnable.Next)
}
