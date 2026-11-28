//go:build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestProxyDisablePairAcknowledgesOnlyBothActualExhaustedCustodyOrigins(t *testing.T) {
	for _, firstRole := range []string{"production", "preview"} {
		t.Run(firstRole+"_finishes_first", func(t *testing.T) {
			production, preview, provider, key := newProxyDisablePairIntegration(t)
			pair, err := NewProxyDisablePairOperator(provider, production.start, preview.service)
			if err != nil {
				t.Fatal("select the matching native pair and its actual custody owners", err)
			}
			disable := ProviderAuthorityChange{
				Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
				Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
				CommandID: providerAuthorityCommand(t),
			}
			admission, err := pair.ApplyDisableCascade(production.ctx, disable, time.Hour)
			if err != nil || admission.Disable != disable || admission.Status != identity.RevocationPending {
				t.Fatal("admit the exact native-pair provider disable", admission, err)
			}
			source := proxyDisablePairSource(admission)
			checked, err := pair.CheckAdmission(production.ctx, source)
			if err != nil || !reflect.DeepEqual(checked, admission) {
				t.Fatal("the operator could not prove the paired admission before sealing or draining", err)
			}
			sourceBefore := proxyDisablePairSourceSnapshot(t, production, admission)
			assertDeniedWithoutEffects := func(request ProxyCustodyFenceSealRequest) {
				t.Helper()
				beforeProduction := proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions")
				beforePreview := proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
				got, err := pair.Acknowledge(production.ctx, request)
				if err == nil || !reflect.DeepEqual(got, ProxyDisablePairAcknowledgement{}) {
					t.Fatal("unproven pair completion disclosed a usable acknowledgement", got, err)
				}
				if proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions") != beforeProduction ||
					proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview ||
					proxyDisablePairSourceSnapshot(t, production, admission) != sourceBefore {
					t.Fatal("rejected acknowledgement changed custody, checkpoints, source or other consumers")
				}
			}
			assertDeniedWithoutEffects(source)

			productionAuthority := proxyDisablePairSeal(t, production, preview, source, kernel.OAuthProxyRetireProduction)
			assertDeniedWithoutEffects(source)
			previewAuthority := proxyDisablePairSeal(t, production, preview, source, kernel.OAuthProxyRetirePreview)
			assertDeniedWithoutEffects(source)
			productionDrain, err := NewProductionProxyRetirementDrain(production.forward, productionAuthority)
			if err != nil {
				t.Fatal("compose the public drain over actual production custody", err)
			}
			previewDrain, err := NewPreviewProxyRetirementDrain(preview.service, previewAuthority)
			if err != nil {
				t.Fatal("compose the public drain over actual preview custody", err)
			}
			first, second := productionDrain, previewDrain
			if firstRole == "preview" {
				first, second = previewDrain, productionDrain
			}
			proxyDisablePairExhaust(t, production.ctx, first, 2)
			assertDeniedWithoutEffects(source)
			partial, err := second.Step(production.ctx, 1)
			if err != nil || partial.Exhausted || partial.Retired != 1 {
				t.Fatal("second actual origin did not retain an incomplete bounded traversal", partial, err)
			}
			assertDeniedWithoutEffects(source)
			proxyDisablePairExhaust(t, production.ctx, second, 2)

			for _, test := range []struct {
				name   string
				change func(*ProxyCustodyFenceSealRequest)
			}{
				{"wrong generation", func(r *ProxyCustodyFenceSealRequest) { r.Generation++ }},
				{"wrong tenant", func(r *ProxyCustodyFenceSealRequest) { r.TenantID = "AAAAAAAAAAAAAAAAAAAAAg" }},
				{"wrong source command", func(r *ProxyCustodyFenceSealRequest) { r.SourceCommandID = providerAuthorityCommand(t) }},
				{"wrong cascade", func(r *ProxyCustodyFenceSealRequest) {
					id, err := identity.NewCascadeID()
					if err != nil {
						t.Fatal(err)
					}
					r.CascadeID = id
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					request := source
					test.change(&request)
					assertDeniedWithoutEffects(request)
				})
			}
			beforeProduction := proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions")
			beforePreview := proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
			var acknowledgement ProxyDisablePairAcknowledgement
			if firstRole == "production" {
				other, err := NewProxyDisablePairOperator(provider, production.start, preview.service)
				if err != nil {
					t.Fatal("compose the second concurrent exact pair owner", err)
				}
				type outcome struct {
					ack ProxyDisablePairAcknowledgement
					err error
				}
				start, results := make(chan struct{}), make(chan outcome, 2)
				for _, owner := range []*ProxyDisablePairOperator{pair, other} {
					go func(owner *ProxyDisablePairOperator) {
						<-start
						ack, err := owner.Acknowledge(production.ctx, source)
						results <- outcome{ack: ack, err: err}
					}(owner)
				}
				close(start)
				first, second := <-results, <-results
				if first.err != nil || second.err != nil || !reflect.DeepEqual(first.ack, second.ack) {
					t.Fatal("concurrent exact acknowledgements did not converge on one durable result", first, second)
				}
				acknowledgement = first.ack
			} else {
				acknowledgement, err = pair.Acknowledge(production.ctx, source)
			}
			if err != nil || acknowledgement.TenantID != source.TenantID || acknowledgement.SourceCommandID != source.SourceCommandID ||
				acknowledgement.CascadeID != source.CascadeID || acknowledgement.Generation != source.Generation ||
				acknowledgement.ProductionDeployment != production.forward.config.ProductionDeployment ||
				acknowledgement.PreviewDeployment != preview.config.Target.Deployment ||
				acknowledgement.Consumer != (ProviderDisableConsumer{ID: "identity/oauth/proxy", ContractVersion: 1}) ||
				acknowledgement.AcknowledgedAt.IsZero() {
				t.Fatal("both actual drains did not produce the exact pair-only consumer acknowledgement", acknowledgement, err)
			}
			var oneDurableAcknowledgement bool
			if err := production.pool.Raw().QueryRow(production.ctx, `SELECT count(*)=1 AND bool_and(acknowledged_at=$3)
 FROM onetap_oauth.provider_disable_proxy_pairs WHERE tenant_id=$1 AND source_command_id=$2`,
				string(source.TenantID), string(source.SourceCommandID), acknowledgement.AcknowledgedAt).Scan(&oneDurableAcknowledgement); err != nil || !oneDurableAcknowledgement {
				t.Fatal("pair acknowledgement did not retain exactly one durable completion timestamp", err)
			}
			for range 2 {
				restarted, err := NewProxyDisablePairOperator(provider, production.start, preview.service)
				if err != nil {
					t.Fatal("reconstruct the selected pair without process-local acknowledgement state", err)
				}
				replayed, err := restarted.Acknowledge(production.ctx, source)
				if err != nil || !reflect.DeepEqual(replayed, acknowledgement) {
					t.Fatal("acknowledgement replay changed its exact pair, generation or durable timestamp", replayed, err)
				}
				repeated, err := restarted.ApplyDisableCascade(production.ctx, disable, time.Hour)
				if err != nil || !reflect.DeepEqual(repeated, admission) {
					t.Fatal("pair admission replay changed its exact historical admission", repeated, err)
				}
			}
			if proxyDisablePairSourceSnapshot(t, production, admission) != sourceBefore ||
				proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions") != beforeProduction ||
				proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview {
				t.Fatal("pair acknowledgement or replay changed the pending cascade, other consumers or native retirement effects")
			}
			if preview.keys.opens.Load() != 0 {
				t.Fatal("native-pair cleanup opened provider bearer evidence")
			}
			proxyPreviewProductionHasNoIdentity(t, production)
			providerAuthorityAssertState(t, production.ctx, production.forward.providerAuthority, key, disable.Next)
		})
	}
}

func TestProxyDisablePairOutboxFailureRollsBackEveryAdmissionEffectAndExactRetryCommits(t *testing.T) {
	production, preview, provider, key := newProxyDisablePairIntegration(t)
	pair, err := NewProxyDisablePairOperator(provider, production.start, preview.service)
	if err != nil {
		t.Fatal("select matching native pair before admission fault", err)
	}
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	configured, err := production.forward.providerAuthority.Current(production.ctx, key)
	if err != nil || !configured.Enabled || configured.Version != disable.ExpectedVersion {
		t.Fatal("retain exact enabled predecessor before admission fault", configured, err)
	}
	beforeProduction := proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions")
	beforePreview := proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	wrongPrimary, err := NewProviderAuthority(preview.pool, production.forward.config.Schema, time.Second)
	if err != nil {
		t.Fatal("compose a same-schema authority pointing at the other actual fixture database", err)
	}
	wrongProvider, err := NewProviderAuthorityOperator(wrongPrimary, oneTapStartActor)
	if err != nil {
		t.Fatal("compose the wrong-database provider operator without invoking it", err)
	}
	if got, err := NewProxyDisablePairOperator(wrongProvider, production.start, preview.service); err == nil || got != nil {
		t.Fatal("same-schema operator on the other actual database selected a usable pair", err)
	}
	if proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions") != beforeProduction ||
		proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview {
		t.Fatal("rejected cross-database operator composition mutated a native owner")
	}
	if _, err := production.pool.Raw().Exec(production.ctx, `CREATE SEQUENCE onetap_oauth.proxy_pair_outbox_failure;
 CREATE FUNCTION onetap_oauth.reject_proxy_pair_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM onetap_oauth.provider_disable_proxy_pairs WHERE source_command_id=NEW.id)
 OR NOT EXISTS (SELECT 1 FROM audit.records WHERE record_id='oauth-provider-authority:' || NEW.id)
 OR NOT EXISTS (SELECT 1 FROM public.outbox_messages WHERE id=NEW.id) THEN
 RAISE EXCEPTION 'fixture fault did not follow pair, audit and outbox writes';
 END IF;
 PERFORM nextval('onetap_oauth.proxy_pair_outbox_failure');
 RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='fixture paired disable outbox failure'; END $$;
 CREATE TRIGGER proxy_pair_outbox_failure AFTER INSERT ON public.outbox_messages
 FOR EACH ROW WHEN (NEW.topic='social_provider.disabled.v1')
 EXECUTE FUNCTION onetap_oauth.reject_proxy_pair_outbox()`); err != nil {
		t.Fatal("install fixture-owned failure after the pair, audit and actual outbox writes", err)
	}
	assertAdmissionEffects := func(want int) {
		t.Helper()
		var cascades, pairs, records, retainedIdentities, events int
		if err := production.pool.Raw().QueryRow(production.ctx, `SELECT
 (SELECT count(*) FROM onetap_oauth.provider_disable_cascades WHERE tenant_id=$1 AND source_command_id=$2),
 (SELECT count(*) FROM onetap_oauth.provider_disable_proxy_pairs WHERE tenant_id=$1 AND source_command_id=$2),
 (SELECT count(*) FROM audit.records WHERE record_id='oauth-provider-authority:' || $2),
 (SELECT count(*) FROM audit.record_identities WHERE record_id='oauth-provider-authority:' || $2),
 (SELECT count(*) FROM public.outbox_messages WHERE id=$2 AND topic='social_provider.disabled.v1')`,
			string(key.TenantID), string(disable.CommandID)).Scan(&cascades, &pairs, &records, &retainedIdentities, &events); err != nil ||
			cascades != want || pairs != want || records != want || retainedIdentities != want || events != want {
			t.Fatal("paired disable did not conserve admission, pair, audit identity and outbox effects", cascades, pairs, records, retainedIdentities, events, err)
		}
	}
	failed, err := pair.ApplyDisableCascade(production.ctx, disable, time.Hour)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || !reflect.DeepEqual(failed, ProviderDisableAdmission{}) {
		t.Fatal("failed final outbox write returned a usable paired admission or wrong error", failed, err)
	}
	var fired bool
	if err := production.pool.Raw().QueryRow(production.ctx, `SELECT is_called FROM onetap_oauth.proxy_pair_outbox_failure`).Scan(&fired); err != nil || !fired {
		t.Fatal("failure did not reach the actual outbox after the pair and audit were written", fired, err)
	}
	assertAdmissionEffects(0)
	providerAuthorityAssertState(t, production.ctx, production.forward.providerAuthority, key, configured)
	if proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions") != beforeProduction ||
		proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview {
		t.Fatal("rolled-back paired admission left native custody, audit, outbox or checkpoint effects")
	}
	if _, err := production.pool.Raw().Exec(production.ctx, `DROP TRIGGER proxy_pair_outbox_failure ON public.outbox_messages;
 DROP FUNCTION onetap_oauth.reject_proxy_pair_outbox();
 DROP SEQUENCE onetap_oauth.proxy_pair_outbox_failure`); err != nil {
		t.Fatal("remove only the fixture's injected paired-admission failure", err)
	}
	accepted, err := pair.ApplyDisableCascade(production.ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("exact retry could not commit the rolled-back paired disable", err)
	}
	providerDisableAssertReceipt(t, accepted, disable, time.Hour)
	assertAdmissionEffects(1)
	providerAuthorityAssertState(t, production.ctx, production.forward.providerAuthority, key, disable.Next)
	committed := proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions")
	replayed, err := pair.ApplyDisableCascade(production.ctx, disable, time.Hour)
	if err != nil || !reflect.DeepEqual(replayed, accepted) {
		t.Fatal("post-rollback exact admission retry was not sticky", replayed, err)
	}
	assertAdmissionEffects(1)
	if proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions") != committed ||
		proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview {
		t.Fatal("exact retry duplicated source effects or changed preview custody")
	}
}

func TestProxyDisablePairCannotRetrofitUnpairedAdmissionAfterActualDrainsFinish(t *testing.T) {
	production, preview, provider, key := newProxyDisablePairIntegration(t)
	pair, err := NewProxyDisablePairOperator(provider, production.start, preview.service)
	if err != nil {
		t.Fatal("select matching native pair", err)
	}
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	admission, err := provider.ApplyDisableCascade(production.ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit a real legacy disable without selecting its native pair", err)
	}
	source := proxyDisablePairSource(admission)
	if checked, err := pair.CheckAdmission(production.ctx, source); checked.CascadeID != "" || err == nil {
		t.Fatal("an unpaired admission could enter the paired seal/drain workflow", err)
	}
	sourceBefore := proxyDisablePairSourceSnapshot(t, production, admission)
	productionAuthority := proxyDisablePairSeal(t, production, preview, source, kernel.OAuthProxyRetireProduction)
	previewAuthority := proxyDisablePairSeal(t, production, preview, source, kernel.OAuthProxyRetirePreview)
	productionDrain, err := NewProductionProxyRetirementDrain(production.forward, productionAuthority)
	if err != nil {
		t.Fatal("select actual production drain for unpaired admission", err)
	}
	previewDrain, err := NewPreviewProxyRetirementDrain(preview.service, previewAuthority)
	if err != nil {
		t.Fatal("select actual preview drain for unpaired admission", err)
	}
	proxyDisablePairExhaust(t, production.ctx, productionDrain, 2)
	proxyDisablePairExhaust(t, preview.ctx, previewDrain, 2)
	beforeProduction := proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions")
	beforePreview := proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	if got, err := pair.ApplyDisableCascade(production.ctx, disable, time.Hour); err == nil || !reflect.DeepEqual(got, ProviderDisableAdmission{}) {
		t.Fatal("selected-pair replay retroactively acquired an unpaired legacy admission", got, err)
	}
	if got, err := pair.Acknowledge(production.ctx, source); err == nil || !reflect.DeepEqual(got, ProxyDisablePairAcknowledgement{}) {
		t.Fatal("even two actual exhausted drains acknowledged a source that never selected this pair", got, err)
	}
	if proxyDisablePairSourceSnapshot(t, production, admission) != sourceBefore ||
		proxyDisablePairCustodySnapshot(t, production.ctx, production.pool, "proxy_transactions") != beforeProduction ||
		proxyDisablePairCustodySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview {
		t.Fatal("denied legacy pairing changed its source or already-completed native cleanup")
	}
}

func newProxyDisablePairIntegration(t *testing.T) (proxyStartIntegration, proxyPreviewSessionFixture, *ProviderAuthorityOperator, ProviderAuthorityKey) {
	t.Helper()
	production, preview, _, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
	productionSchema := production.forward.config.Schema
	previewSchema := preview.completion.start.config.Schema
	proxyRetirementDiscoveryInstall(t, production.ctx, production.pool, productionSchema, kernel.OAuthProxyRetireProduction)
	proxyRetirementDiscoveryInstall(t, preview.ctx, preview.pool, previewSchema, kernel.OAuthProxyRetirePreview)
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProviderDisableCascadeMigrationSource{Schema: productionSchema, Version: 80})
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProxyDisablePairMigrationSource{Schema: productionSchema, Version: 81})
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProxyCustodyWriteFenceMigrationSource{Schema: productionSchema, Version: 90, Kind: kernel.OAuthProxyRetireProduction})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceMigrationSource{Schema: previewSchema, Version: 90, Kind: kernel.OAuthProxyRetirePreview})
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProxyRetirementDrainMigrationSource{Schema: productionSchema, Version: 100})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyRetirementDrainMigrationSource{Schema: previewSchema, Version: 100})

	selected := *production.start
	selected.custodyFence = true
	production.start = &selected
	var err error
	preview.service, err = NewProxyPreviewServiceWithCustodyFence(preview.completion, preview.config, production.forward.providerAuthority)
	if err != nil {
		t.Fatal("select the actual native preview custody writer", err)
	}
	proxyCustodyFenceInstall(t, production.ctx, production.pool, ProxyCustodyWriteFenceActivationSource{Schema: productionSchema, Version: 92, Kind: kernel.OAuthProxyRetireProduction})
	proxyCustodyFenceInstall(t, preview.ctx, preview.pool, ProxyCustodyWriteFenceActivationSource{Schema: previewSchema, Version: 92, Kind: kernel.OAuthProxyRetirePreview})
	additional := proxyCustodyFencePreviewRequest(t, production, preview, proxyPreviewAuthorityEpoch)
	if err := preview.service.Bind(preview.ctx, additional); err != nil {
		t.Fatal("create a second genuine native original so exhaustion requires more than one target", err)
	}
	return production, preview, operator, key
}

func proxyDisablePairSource(admission ProviderDisableAdmission) ProxyCustodyFenceSealRequest {
	return ProxyCustodyFenceSealRequest{TenantID: admission.Disable.Key.TenantID, SourceCommandID: admission.Disable.CommandID,
		CascadeID: admission.CascadeID, Generation: admission.Generation}
}

func proxyDisablePairSeal(t *testing.T, production proxyStartIntegration, preview proxyPreviewSessionFixture,
	source ProxyCustodyFenceSealRequest, kind kernel.OAuthProxyRetirementKind) *ProxyRetirementAuthority {
	t.Helper()
	pool, schema := production.pool, production.forward.config.Schema
	if kind == kernel.OAuthProxyRetirePreview {
		pool, schema = preview.pool, preview.completion.start.config.Schema
	}
	sealer, err := NewProxyCustodyFenceOperator(pool, production.forward.providerAuthority, ProxyCustodyFenceOperatorConfig{
		Schema: schema, Kind: kind, TenantID: source.TenantID, ActorID: oneTapStartActor, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("compose the fence operator over the selected actual custody database", err)
	}
	if _, err := sealer.SealAdmittedProviderDisable(production.ctx, source); err != nil {
		t.Fatal("seal the actual activated custody database against the exact admitted source", err)
	}
	authority, err := NewSealedProxyRetirementAuthority(sealer, source)
	if err != nil {
		t.Fatal("select exact local sealed retirement authority", err)
	}
	return authority
}

func proxyDisablePairExhaust(t *testing.T, ctx context.Context, drain *ProxyRetirementDrain, wantRetired uint64) {
	t.Helper()
	for range 8 {
		progress, err := drain.Step(ctx, 1)
		if err != nil {
			t.Fatal("advance the actual custody owner's public bounded drain", err)
		}
		if progress.Exhausted {
			if progress.Retired != wantRetired || progress.Remaining != 0 {
				t.Fatal("actual exhausted drain did not confirm every native original", progress)
			}
			return
		}
	}
	t.Fatal("two-original fixture did not reach durable exhaustion within its bounded traversal")
}

func proxyDisablePairSourceSnapshot(t *testing.T, production proxyStartIntegration, admission ProviderDisableAdmission) string {
	t.Helper()
	var snapshot string
	var pending bool
	query := `SELECT to_jsonb(c)::text,status=$3 FROM ` + rpQuotedSchema(production.forward.config.Schema) + `.provider_disable_cascades c
 WHERE tenant_id=$1 AND source_command_id=$2`
	if err := production.pool.Raw().QueryRow(production.ctx, query, string(admission.Disable.Key.TenantID),
		string(admission.Disable.CommandID), int16(identity.RevocationPending)).Scan(&snapshot, &pending); err != nil || !pending {
		t.Fatal("pair-local completion changed the exact source's pending global cascade", err)
	}
	return snapshot
}

func proxyDisablePairCustodySnapshot(t *testing.T, ctx context.Context, pool *database.Pool, table string) string {
	t.Helper()
	var drains string
	if err := pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY to_jsonb(d)::text),'[]'::jsonb)::text
 FROM onetap_oauth.proxy_retirement_drains d`).Scan(&drains); err != nil {
		t.Fatal("snapshot actual role-local drain checkpoints", err)
	}
	return proxyRetirementDiscoverySnapshot(t, ctx, pool, table) + "\n" + drains
}
