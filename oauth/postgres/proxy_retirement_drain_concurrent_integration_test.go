//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func TestProxyRetirementDrainProductionAcknowledgesConcurrentExactRetirementWithoutSuccessEffects(t *testing.T) {
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
	state := proxyRetirementDrainState{page: page}
	if err := store.save(f.ctx, &state); err != nil {
		t.Fatal("persist the pending page before either retirement", err)
	}
	pending, err := store.read(f.ctx)
	if err != nil || !reflect.DeepEqual(pending, state) || pending.retired != 0 || pending.confirmed != 0 || pending.exhausted {
		t.Fatal("the exact unconfirmed command was not durable", err)
	}
	target := pending.page.Targets[0]
	manual := ProxyOriginRetirementRequest{
		CommandID: providerAuthorityCommand(t), OriginCommandID: target.Origin, FlowID: target.Flow, Disable: disable,
	}
	if manual.CommandID == target.Command {
		t.Fatal("the trusted competing retirement must have its own command")
	}
	drain, err := NewProductionProxyRetirementDrain(f.forward, authority)
	if err != nil {
		t.Fatal("reconstruct the drain from its durable pending page", err)
	}

	// The native pool has two connections: both must remain available for real
	// retirements. A separate fixture connection owns the gate and observes waits.
	gate, err := pgx.ConnectConfig(f.ctx, f.pool.Raw().Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal("connect the fixture-owned concurrency gate", err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	type retirementResult struct {
		result identity.CommandResult
		err    error
	}
	type drainResult struct {
		progress ProxyRetirementDrainProgress
		err      error
	}
	winnerDone := make(chan retirementResult, 1)
	drainDone := make(chan drainResult, 1)
	winnerStarted, drainStarted, winnerJoined, drainJoined := false, false, false, false
	unlocked := false
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if !unlocked {
			if _, err := gate.Exec(cleanup, `SELECT pg_advisory_unlock(7042042)`); err != nil {
				t.Error("release the fixture gate after failure", err)
			}
		}
		if winnerStarted && !winnerJoined {
			<-winnerDone
		}
		if drainStarted && !drainJoined {
			<-drainDone
		}
		if err := gate.Close(cleanup); err != nil {
			t.Error("close the fixture-owned concurrency gate", err)
		}
	}()
	const holdRetirement = `CREATE FUNCTION onetap_oauth.fixture_hold_retirement_grant() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF OLD.purpose='identity.oauth.proxy-forward' AND OLD.state='issued' AND NEW.state='revoked' THEN
 PERFORM pg_advisory_xact_lock(7042042);
 END IF;
 RETURN NEW;
 END $$;
 CREATE TRIGGER fixture_hold_retirement_grant BEFORE UPDATE ON public.capability_identity_one_use
 FOR EACH ROW EXECUTE FUNCTION onetap_oauth.fixture_hold_retirement_grant()`
	if _, err := gate.Exec(ctx, holdRetirement); err != nil {
		t.Fatal("install the fixture-only grant-update gate", err)
	}
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_lock(7042042)`); err != nil {
		t.Fatal("hold the gate before starting the genuine winner", err)
	}
	winnerStarted = true
	go func() {
		result, err := f.forward.RetireDisabledProviderOrigin(ctx, authority, manual)
		winnerDone <- retirementResult{result: result, err: err}
	}()
	waitCtx, stopWait := context.WithTimeout(ctx, 2*time.Second)
	defer stopWait()
	var winnerPID int32
	for winnerPID == 0 {
		if err := gate.QueryRow(waitCtx, `SELECT COALESCE((SELECT pid FROM pg_stat_activity
 WHERE datname=current_database() AND $1::integer=ANY(pg_blocking_pids(pid))
 AND query LIKE '%public.capability_identity_one_use%' AND query LIKE '%FOR UPDATE%' LIMIT 1),0)`,
			int64(gate.PgConn().PID())).Scan(&winnerPID); err != nil {
			t.Fatal("the genuine winner did not reach the gated native grant update", err)
		}
	}
	pendingPage, err := json.Marshal(pending.page)
	if err != nil {
		t.Fatal("marshal the saved native drain page", err)
	}
	var activeCustody, unchangedPage bool
	if err := gate.QueryRow(waitCtx, `SELECT
 (SELECT version IN (1,2) AND retired_at IS NULL FROM onetap_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT pending_page=$3::jsonb AND confirmed=0 AND retired=0 AND NOT exhausted
 FROM onetap_oauth.proxy_retirement_drains WHERE tenant_id=$1 AND cascade_id=$4 AND generation=$5)`,
		oneTapStartTenant, string(target.Flow), pendingPage, string(admitted.CascadeID), admitted.Generation).
		Scan(&activeCustody, &unchangedPage); err != nil || !activeCustody || !unchangedPage {
		t.Fatal("the held winner changed visible custody or acknowledged the saved drain page", err)
	}
	drainStarted = true
	go func() {
		progress, err := drain.Step(ctx, 1)
		drainDone <- drainResult{progress: progress, err: err}
	}()
	var observedWaits string
	for {
		select {
		case returned := <-drainDone:
			drainJoined = true
			t.Fatalf("drain returned before its coordinator tenant-lock wait: progress=%+v error_type=%T; observed_waits=%s", returned.progress, returned.err, observedWaits)
		default:
		}
		var blocked bool
		if err := gate.QueryRow(waitCtx, `WITH backends AS MATERIALIZED (
 SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers,
 CASE WHEN query='SELECT pg_advisory_xact_lock($1)' THEN 'coordinator-tenant-lock'
 WHEN query LIKE '%public.capability_identity_one_use%' THEN 'native-grant'
 WHEN query LIKE '%proxy_transactions%' THEN 'native-custody'
 WHEN query LIKE '%identity.commands%' THEN 'command-journal'
 WHEN query LIKE '%proxy_retirement_drains%' THEN 'drain-checkpoint'
 ELSE 'other' END AS stage
 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
 ) SELECT EXISTS(SELECT FROM backends WHERE $1::integer=ANY(blockers) AND stage='coordinator-tenant-lock'),
 COALESCE((SELECT jsonb_agg(to_jsonb(backends) ORDER BY pid)::text FROM backends),'[]')`, int64(winnerPID)).
			Scan(&blocked, &observedWaits); err != nil {
			stats := f.pool.Raw().Stat()
			t.Fatalf("drain did not wait on the genuine winner's coordinator tenant lock: %v; native_pool_acquired=%d total=%d; observed_waits=%s", err, stats.AcquiredConns(), stats.TotalConns(), observedWaits)
		}
		if blocked {
			break
		}
	}
	// configureKernelWork serializes same-tenant Work before Apply. Preserve
	// that safety boundary: the drain can inspect custody only after the genuine
	// winner commits, rather than synthesizing an unreachable custody CAS race.
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_unlock(7042042)`); err != nil {
		t.Fatal("release the winner after observing the drain's coordinator tenant-lock wait", err)
	}
	unlocked = true
	winner := <-winnerDone
	winnerJoined = true
	if winner.err != nil || winner.result.Validate() != nil || winner.result.Outcome != identity.CommitOutcomeCommitted || winner.result.Binding.CommandID != manual.CommandID {
		t.Fatal("the distinct trusted retirement did not commit", winner.result, winner.err)
	}
	completed := <-drainDone
	drainJoined = true
	progress := completed.progress
	if completed.err != nil || !progress.Exhausted || progress.Retired != 1 || progress.Remaining != 0 || progress.AfterFlowID != "" {
		t.Fatal("one native drain step did not acknowledge the exact concurrent retirement", progress, completed.err)
	}
	finished, err := store.read(f.ctx)
	if err != nil || finished.page != nil || finished.confirmed != 0 || finished.retired != 1 || !finished.exhausted {
		t.Fatal("the concurrent acknowledgement did not durably exhaust its saved page", err)
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
		t.Fatal("read the saved drain command's own terminal journal", err)
	}
	var recorded identity.CommandResult
	if err := json.Unmarshal(terminal, &recorded); err != nil || recorded.Validate() != nil || journalState != "aborted" || terminalClass != "conflict" ||
		recorded.Outcome != identity.CommitOutcomeNotCommitted || recorded.Binding.CommandID != target.Command ||
		recorded.Binding.CorrelationID != string(target.Origin) || recorded.Binding.RecordID != string(target.Flow) ||
		recorded.Binding.AnonymousFlowID != string(target.Flow) {
		t.Fatal("the waiting drain fabricated success instead of preserving its exact NotCommitted result", err)
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
		t.Fatal("the manual winner was not the sole success with exact custody cleanup and no duplicate effects", err)
	}
	stable := proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions")
	drainRequest := ProxyOriginRetirementRequest{CommandID: target.Command, OriginCommandID: target.Origin, FlowID: target.Flow, Disable: disable}
	for range 2 {
		replay, err := f.forward.RetireDisabledProviderOrigin(f.ctx, authority, drainRequest)
		var detail kernel.TypedFeatureFailureError
		if !errors.As(err, &detail) || detail.Code != kernel.FeatureFailureOAuthProxyAlreadyRetired || !reflect.DeepEqual(replay, recorded) ||
			proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != stable {
			t.Fatal("the exact waiting command's no-change terminal was not replay-sticky and effect-free", replay, err)
		}
	}
	var replayTerminal []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT result FROM identity.commands WHERE command_id=$1`, drainCommand).Scan(&replayTerminal); err != nil || !bytes.Equal(terminal, replayTerminal) {
		t.Fatal("replay rewrote the immutable NotCommitted drain journal", err)
	}
}
