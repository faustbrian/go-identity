//go:build integration

package postgres

import (
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"testing"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProxyRetirementProductionCommitsExactDisableEffects(t *testing.T) {
	f := newProxyStartIntegration(t)
	providerAuthority, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = providerAuthority
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 41, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, configure); err != nil || state != configure.Next {
		t.Fatal("configure the selected live provider before native Start", err)
	}
	open, _ := startProxyProviderEpochOriginal(t, f, f.request, 41)
	var originalIssued bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*)=1 AND bool_and(state='issued' AND uses=0
 AND purpose='identity.oauth.proxy-forward' AND subject_id=$3)
 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$2`,
		oneTapStartTenant, string(open.CommandID), string(open.TransactionID)).Scan(&originalIssued); err != nil || !originalIssued {
		t.Fatal("native Start did not commit the selected unused issued grant", err)
	}

	// A known provider denial has its own committed callback history and used
	// grant. Local retirement must erase custody without rewriting that history.
	settledRequest := freshProxyProviderEpochRequest(t, f.request)
	settledStart, err := f.start.Start(f.ctx, settledRequest)
	if err != nil {
		t.Fatal("start the independently settled original", err)
	}
	settled, ok := settledStart.Binding()
	authorization, authorized := settledStart.Authorization()
	if !ok || !authorized || settled.ProviderAuthorityEpoch != 41 {
		t.Fatal("settled original did not use the selected live provider epoch")
	}
	providerURL, err := url.Parse(authorization.URL())
	if err != nil {
		t.Fatal(err)
	}
	denial := url.Values{"state": {providerURL.Query().Get("state")}, "error": {"access_denied"}, "iss": {f.provider.Issuer}}.Encode()
	callback, err := f.callback.Handle(f.ctx, f.provider.RedirectURI, denial)
	if !errors.Is(err, oauthproxy.CallbackDenied) || callback.Destination() != "" || len(callback.Envelope()) != 0 {
		t.Fatal("commit the real provider-denied callback without a handoff", err)
	}
	var callbackHistory string
	const callbackHistorySQL = `SELECT to_jsonb(c)::text FROM identity.commands c
 JOIN onetap_oauth.proxy_transactions p ON p.callback_command_id=c.command_id
 WHERE p.tenant_id=$1 AND p.transaction_id=$2 AND c.state='committed'`
	if err := f.pool.Raw().QueryRow(f.ctx, callbackHistorySQL, string(settled.TenantID), string(settled.TransactionID)).Scan(&callbackHistory); err != nil {
		t.Fatal("retain the independent committed callback history", err)
	}

	history, err := (ProxyRetirementMigrationSource{
		Schema: f.forward.config.Schema, Version: 60, Kind: kernel.OAuthProxyRetireProduction,
	}).Load(f.ctx)
	if err != nil || len(history) != 2 {
		t.Fatal("load both production retirement migration steps", err)
	}
	for _, migration := range history {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal("begin the separate retirement migration step", err)
		}
		if _, err := tx.Exec(f.ctx, migration.UpSQL()); err != nil {
			_ = tx.Rollback(f.ctx)
			t.Fatal("apply retirement migration to populated native custody", err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal("commit the retirement migration step", err)
		}
	}
	reader, err := auditpg.New(providerAuthority.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("borrow the separate retained audit reader", err)
	}
	retirementAuthority, err := NewProxyRetirementAuthority(reader, oneTapStartActor)
	if err != nil {
		t.Fatal("compose the actual operator-authenticated retirement authority", err)
	}
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 41, Next: ProviderAuthorityState{Version: 42, ProfileVersion: f.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, disable); err != nil || state != disable.Next {
		t.Fatal("commit the exact historical provider disable", err)
	}
	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 42, Next: ProviderAuthorityState{Version: 43, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, reenable); err != nil || state != reenable.Next {
		t.Fatal("re-enable a distinct epoch without replacing the retained disable", err)
	}
	fresh, _ := startProxyProviderEpochOriginal(t, f, freshProxyProviderEpochRequest(t, f.request), 43)

	// Compare all custody, grant, audit and delivery effects, not just a
	// returned denial. A rejected candidate must not partially retire anything.
	snapshot := func() string {
		t.Helper()
		var state string
		const query = `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(p) ORDER BY transaction_id) FROM onetap_oauth.proxy_transactions p),
 (SELECT jsonb_agg(to_jsonb(g) ORDER BY origin_command_id) FROM public.capability_identity_one_use g),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY record_id) FROM audit.records a WHERE outcome=1),
 (SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM public.outbox_messages o))::text`
		if err := f.pool.Raw().QueryRow(f.ctx, query).Scan(&state); err != nil {
			t.Fatal("snapshot actual retirement effects", err)
		}
		return state
	}
	request := ProxyOriginRetirementRequest{
		CommandID: providerAuthorityCommand(t), OriginCommandID: open.CommandID, FlowID: open.TransactionID, Disable: disable,
	}
	before := snapshot()
	for _, test := range []struct {
		name   string
		change func(*ProxyOriginRetirementRequest)
	}{
		{"wrong provider", func(r *ProxyOriginRetirementRequest) { r.Disable.Key.ProviderID = "another-provider" }},
		{"wrong source command", func(r *ProxyOriginRetirementRequest) { r.Disable.CommandID = configure.CommandID }},
		{"wrong prior epoch", func(r *ProxyOriginRetirementRequest) { r.Disable.ExpectedVersion = 40 }},
		{"wrong disable epoch", func(r *ProxyOriginRetirementRequest) { r.Disable.Next.Version = 44 }},
		{"newer original epoch", func(r *ProxyOriginRetirementRequest) {
			r.OriginCommandID, r.FlowID = fresh.CommandID, fresh.TransactionID
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			candidate.CommandID = providerAuthorityCommand(t)
			test.change(&candidate)
			result, err := f.forward.RetireDisabledProviderOrigin(f.ctx, retirementAuthority, candidate)
			if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("unmatched disable or newer original acquired committed retirement")
			}
			if snapshot() != before {
				t.Fatal("denied retirement changed custody, grants, audit or lifecycle delivery")
			}
		})
	}

	const rejectLocalRetirementOutbox = `ALTER TABLE public.outbox_messages ADD CONSTRAINT fixture_reject_proxy_retirement
 CHECK (topic <> 'oauth.proxy.custody_retired.v1') NOT VALID`
	if _, err := f.pool.Raw().Exec(f.ctx, rejectLocalRetirementOutbox); err != nil {
		t.Fatal("inject the local lifecycle sink failure", err)
	}
	failed := request
	failed.CommandID = providerAuthorityCommand(t)
	failedResult, failedErr := f.forward.RetireDisabledProviderOrigin(f.ctx, retirementAuthority, failed)
	if failedErr == nil || failedResult.Outcome == identity.CommitOutcomeCommitted || snapshot() != before {
		t.Fatal("a failed local lifecycle effect did not roll back grant and custody erasure", failedErr)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT fixture_reject_proxy_retirement`); err != nil {
		t.Fatal("remove the isolated lifecycle failure", err)
	}

	var openBinding, settledBinding, freshRow, freshGrant string
	const originalRow = `SELECT to_jsonb(p)::text FROM onetap_oauth.proxy_transactions p WHERE tenant_id=$1 AND transaction_id=$2`
	const originalBinding = `SELECT (to_jsonb(p)-ARRAY['version','state_proof_ciphertext','pkce_ciphertext',
 'handoff_ciphertext','retirement_source_command_id','retirement_source_version','retired_at'])::text
 FROM onetap_oauth.proxy_transactions p WHERE tenant_id=$1 AND transaction_id=$2`
	for _, item := range []struct {
		flow identity.PreAuthTransactionID
		into *string
	}{{open.TransactionID, &openBinding}, {settled.TransactionID, &settledBinding}} {
		if err := f.pool.Raw().QueryRow(f.ctx, originalBinding, oneTapStartTenant, string(item.flow)).Scan(item.into); err != nil {
			t.Fatal("retain original authenticated binding and settlement", err)
		}
	}
	if err := f.pool.Raw().QueryRow(f.ctx, originalRow, oneTapStartTenant, string(fresh.TransactionID)).Scan(&freshRow); err != nil {
		t.Fatal(err)
	}
	const freshGrantSQL = `SELECT to_jsonb(g)::text FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$2`
	if err := f.pool.Raw().QueryRow(f.ctx, freshGrantSQL, oneTapStartTenant, string(fresh.CommandID)).Scan(&freshGrant); err != nil {
		t.Fatal(err)
	}

	for _, item := range []struct {
		origin  identity.CommandID
		flow    identity.PreAuthTransactionID
		binding string
		state   string
		uses    int
	}{{open.CommandID, open.TransactionID, openBinding, "revoked", 0}, {settled.CommandID, settled.TransactionID, settledBinding, "finalized", 1}} {
		request.CommandID = providerAuthorityCommand(t)
		request.OriginCommandID, request.FlowID = item.origin, item.flow
		result, err := f.forward.RetireDisabledProviderOrigin(f.ctx, retirementAuthority, request)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Validate() != nil ||
			result.Binding.CommandID != request.CommandID || result.Feature == nil || result.Feature.Operation != kernel.OAuthProxyOriginRetirementOperation() {
			t.Fatal("exact historical disable did not commit one native retirement receipt", err)
		}
		source, err := base64.RawURLEncoding.Strict().DecodeString(string(disable.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var erased, exactGrant, exactEffects bool
		command, err := base64.RawURLEncoding.Strict().DecodeString(string(request.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		const effects = `SELECT
 (SELECT version=3 AND retirement_source_command_id=$3 AND retirement_source_version=42
  AND retired_at IS NOT NULL AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL
  AND handoff_ciphertext IS NULL AND binding_ciphertext IS NOT NULL
  FROM onetap_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT count(*)=1 AND bool_and(state=$5 AND uses=$6 AND origin_command_id=$4 AND subject_id=$2
  AND purpose='identity.oauth.proxy-forward') FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$4),
 (SELECT count(*)=1 FROM audit.identity_command_bindings WHERE command_id=$7) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$7) AND
 (SELECT count(*)=1 FROM audit.records WHERE record_id=$8 AND action='identity.oauth.proxy_custody.retire')`
		if err := f.pool.Raw().QueryRow(f.ctx, effects, oneTapStartTenant, string(item.flow), source, string(item.origin), item.state, item.uses, command, result.AuditEventID).Scan(&erased, &exactGrant, &exactEffects); err != nil || !erased || !exactGrant || !exactEffects {
			t.Fatal("retirement did not atomically erase exact custody, conserve grant use and record its effects", err, erased, exactGrant, exactEffects)
		}
		var unchangedBinding string
		if err := f.pool.Raw().QueryRow(f.ctx, originalBinding, oneTapStartTenant, string(item.flow)).Scan(&unchangedBinding); err != nil || unchangedBinding != item.binding {
			t.Fatal("retirement rewrote the original outcome, settlement or authenticated binding", err)
		}
		committed := snapshot()
		replayed, err := f.forward.RetireDisabledProviderOrigin(f.ctx, retirementAuthority, request)
		if err != nil || !reflect.DeepEqual(replayed, result) || snapshot() != committed {
			t.Fatal("exact retirement replay changed its receipt or repeated local effects", err)
		}
	}
	var afterCallback, afterFreshRow, afterFreshGrant string
	if err := f.pool.Raw().QueryRow(f.ctx, callbackHistorySQL, oneTapStartTenant, string(settled.TransactionID)).Scan(&afterCallback); err != nil || afterCallback != callbackHistory {
		t.Fatal("local retirement changed the independently committed callback history", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, originalRow, oneTapStartTenant, string(fresh.TransactionID)).Scan(&afterFreshRow); err != nil || afterFreshRow != freshRow {
		t.Fatal("old disable erased newer-epoch custody", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, freshGrantSQL, oneTapStartTenant, string(fresh.CommandID)).Scan(&afterFreshGrant); err != nil || afterFreshGrant != freshGrant {
		t.Fatal("old disable retired the newer-epoch grant", err)
	}
	var noIdentityWrites, retirementDeliveries bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*)=0 FROM identity.users) AND (SELECT count(*)=0 FROM identity.accounts)
 AND (SELECT count(*)=0 FROM onetap_sessions.sessions),
 (SELECT count(*)=2 FROM public.outbox_messages WHERE topic='oauth.proxy.custody_retired.v1')`).Scan(&noIdentityWrites, &retirementDeliveries); err != nil || !noIdentityWrites || !retirementDeliveries {
		t.Fatal("production retirement wrote identity state or did not conserve exactly one lifecycle event per origin", err)
	}
}
