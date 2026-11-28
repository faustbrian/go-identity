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

func TestProxyRetirementDrainProductionAcknowledgesExactCompetingRetirementWithoutSuccessEffects(t *testing.T) {
	f := newProxyStartIntegration(t)
	primary, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = primary
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 41, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(f.ctx, configure); err != nil {
		t.Fatal("configure provider before the native original", err)
	}
	original, _ := startProxyProviderEpochOriginal(t, f, f.request, 41)
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
		t.Fatal("admit the exact provider disable", err)
	}
	sealer, err := NewProxyCustodyFenceOperator(f.pool, primary, ProxyCustodyFenceOperatorConfig{
		Schema: schema, Kind: kernel.OAuthProxyRetireProduction, TenantID: key.TenantID,
		ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose the native custody sealer", err)
	}
	source := ProxyCustodyFenceSealRequest{
		TenantID: key.TenantID, SourceCommandID: disable.CommandID, CascadeID: admitted.CascadeID, Generation: admitted.Generation,
	}
	proxyCustodyFenceInstall(t, f.ctx, f.pool, ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: 92, Kind: kernel.OAuthProxyRetireProduction})
	if _, err := sealer.SealAdmittedProviderDisable(f.ctx, source); err != nil {
		t.Fatal("seal the admitted cutoff on actual production custody", err)
	}
	authority, err := NewSealedProxyRetirementAuthority(sealer, source)
	if err != nil {
		t.Fatal("select the exact sealed authority", err)
	}
	found, err := f.forward.ListDisabledProviderOrigins(f.ctx, authority, ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: 1})
	if err != nil || !reflect.DeepEqual(found.Origins, []ProxyRetirementOrigin{{OriginCommandID: original.CommandID, FlowID: original.TransactionID}}) || found.NextAfterFlowID != "" {
		t.Fatal("discover the one authenticated pending target", found, err)
	}
	page, err := newProxyRetirementDrainPage(found, "")
	if err != nil {
		t.Fatal("assign the pending target's exact drain command", err)
	}
	store := proxyRetirementDrainStore{
		pool: f.pool.Raw(), table: rpQuotedSchema(schema) + ".proxy_retirement_drains",
		key: proxyRetirementDrainKey{source: admitted, kind: kernel.OAuthProxyRetireProduction, deployment: f.forward.config.ProductionDeployment},
	}
	// Pause at the existing durable-page boundary, before any drain retirement.
	// This deterministically orders a real competing command without a test hook.
	state := proxyRetirementDrainState{page: page}
	if err := store.save(f.ctx, &state); err != nil {
		t.Fatal("persist the pending page before the competing retirement", err)
	}
	pending, err := store.read(f.ctx)
	if err != nil || !reflect.DeepEqual(pending, state) || pending.retired != 0 || pending.confirmed != 0 || pending.exhausted {
		t.Fatal("the exact pending command was not durable before the overlap", err)
	}
	target := pending.page.Targets[0]
	manual := ProxyOriginRetirementRequest{
		CommandID: providerAuthorityCommand(t), OriginCommandID: original.CommandID, FlowID: original.TransactionID, Disable: disable,
	}
	if manual.CommandID == target.Command {
		t.Fatal("the competing retirement must have its own command")
	}
	winner, err := f.forward.RetireDisabledProviderOrigin(f.ctx, authority, manual)
	if err != nil || winner.Validate() != nil || winner.Outcome != identity.CommitOutcomeCommitted || winner.Binding.CommandID != manual.CommandID {
		t.Fatal("the separate trusted retirement did not commit first", winner, err)
	}
	stillPending, err := store.read(f.ctx)
	if err != nil || !reflect.DeepEqual(stillPending, pending) {
		t.Fatal("the manual winner acknowledged or replaced the drain's pending command", err)
	}
	drain, err := NewProductionProxyRetirementDrain(f.forward, authority)
	if err != nil {
		t.Fatal("reconstruct the drain from only durable state", err)
	}
	progress, err := drain.Step(f.ctx, 1)
	if err != nil || !progress.Exhausted || progress.Retired != 1 || progress.Remaining != 0 || progress.AfterFlowID != "" {
		t.Fatal("native proof of the exact already-retired target did not acknowledge the saved page", progress, err)
	}
	finished, err := store.read(f.ctx)
	if err != nil || finished.page != nil || finished.confirmed != 0 || finished.retired != 1 || !finished.exhausted {
		t.Fatal("the overlap acknowledgement did not persist local exhaustion", err)
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
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,terminal_class,result FROM identity.commands WHERE command_id=$1`, drainCommand).
		Scan(&journalState, &terminalClass, &terminal); err != nil {
		t.Fatal("read the drain command's own terminal journal", err)
	}
	var recorded identity.CommandResult
	if err := json.Unmarshal(terminal, &recorded); err != nil || recorded.Validate() != nil || journalState != "aborted" || terminalClass != "conflict" ||
		recorded.Outcome != identity.CommitOutcomeNotCommitted || recorded.Binding.CommandID != target.Command ||
		recorded.Binding.CorrelationID != string(target.Origin) || recorded.Binding.RecordID != string(target.Flow) ||
		recorded.Binding.AnonymousFlowID != string(target.Flow) {
		t.Fatal("the drain fabricated a successful retirement instead of retaining its exact no-change outcome", err)
	}
	var exactEffects bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*)=1 FROM identity.commands WHERE command_id=$1 AND state='committed') AND
 (SELECT count(*)=1 FROM identity.commands WHERE purpose=$4 AND state='committed') AND
 (SELECT count(*)=1 FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id
 WHERE b.command_id=$1 AND r.outcome=$8) AND
 (SELECT count(*)=1 FROM audit.records WHERE action='identity.oauth.proxy_custody.retire' AND outcome=$8) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$1) AND
 (SELECT count(*)=1 AND bool_and(r.outcome<>$8) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id
 WHERE b.command_id=$2) AND
 (SELECT count(*)=0 FROM public.identity_outbox_bindings WHERE command_id=$2) AND
 (SELECT count(*)=1 FROM public.outbox_messages WHERE topic='oauth.proxy.custody_retired.v1') AND
 (SELECT version=3 AND retired_at IS NOT NULL AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL
 AND handoff_ciphertext IS NULL AND binding_ciphertext IS NOT NULL AND retirement_source_command_id=$3 AND retirement_source_version=42
 FROM onetap_oauth.proxy_transactions WHERE tenant_id=$5 AND transaction_id=$6) AND
 (SELECT count(*)=1 AND bool_and(state='revoked' AND uses=0) FROM public.capability_identity_one_use
 WHERE tenant_id=$5 AND origin_command_id=$7 AND subject_id=$6 AND purpose='identity.oauth.proxy-forward')`,
		winnerCommand, drainCommand, decodeCommand(disable.CommandID), kernel.OAuthProxyOriginRetirementOperation().OperationID,
		oneTapStartTenant, string(target.Flow), string(target.Origin), int16(audit.OutcomeSucceeded)).Scan(&exactEffects); err != nil || !exactEffects {
		t.Fatal("the manual winner was not the sole committed retirement with the sole success audit/outbox and exact custody cleanup", err)
	}
	stable := proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions")
	drainRequest := ProxyOriginRetirementRequest{CommandID: target.Command, OriginCommandID: target.Origin, FlowID: target.Flow, Disable: disable}
	for range 2 {
		replay, err := f.forward.RetireDisabledProviderOrigin(f.ctx, authority, drainRequest)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || !reflect.DeepEqual(replay, recorded) || proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != stable {
			t.Fatal("the drain command's native no-change terminal was not replay-sticky and effect-free", replay, err)
		}
	}
	var replayTerminal []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT result FROM identity.commands WHERE command_id=$1`, drainCommand).Scan(&replayTerminal); err != nil || !bytes.Equal(terminal, replayTerminal) {
		t.Fatal("replay rewrote the drain's immutable NotCommitted journal", err)
	}
	restarted, err := NewProductionProxyRetirementDrain(f.forward, authority)
	if err != nil {
		t.Fatal("restart the exhausted overlap drain", err)
	}
	sticky, err := restarted.Step(f.ctx, 1)
	afterRestart, readErr := store.read(f.ctx)
	if err != nil || readErr != nil || !reflect.DeepEqual(sticky, progress) || !reflect.DeepEqual(afterRestart, finished) ||
		proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != stable {
		t.Fatal("restart repeated effects or changed the acknowledged overlap checkpoint", sticky, err, readErr)
	}
}
