//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
)

func TestProxyCallbackRateSourceAuthenticatesOriginalWithoutEffects(t *testing.T) {
	f := newProxyForwardIntegration(t, true)
	// Rate attribution opens neither the verifier nor the state capability.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE onetap_oauth.proxy_transactions SET state_proof_ciphertext='invalid-proof'::bytea`); err != nil {
		t.Fatal("replace proof custody", err)
	}
	before := proxyCallbackRateSnapshot(t, f)
	want := oauth.CallbackRateContext{ProviderID: f.original.Evidence.ProviderID, TransactionID: string(f.locator.Transaction), Lifetime: 5 * time.Minute}
	for _, denied := range []bool{false, true, false} {
		lookup := f.lookup
		lookup.ProviderDenied = denied
		got, err := f.service.ProxyCallbackRateSource(f.ctx, f.locator.Tenant, lookup)
		if err != nil || got != want {
			t.Fatal("original tenant/provider/transaction and configured lifetime were not preserved", err)
		}
	}
	if after := proxyCallbackRateSnapshot(t, f); after != before {
		t.Fatal("attribution changed transaction custody, capability, command, audit, outbox or production identities")
	}
}

func TestProxyCallbackRateSourceRejectsMismatchedSelectionWithoutEffects(t *testing.T) {
	f := newProxyForwardIntegration(t, false)
	before := proxyCallbackRateSnapshot(t, f)
	cases := []struct {
		name   string
		tenant identity.TenantID
		change func(*oauthproxy.CallbackLookup)
	}{
		{name: "foreign tenant", tenant: "foreign-tenant"},
		{name: "missing tenant", tenant: ""},
		{name: "state", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.StateDigest[0] ^= 1 }},
		{name: "production", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.ProductionDeployment = "production-b" }},
		{name: "provider", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.ProviderID = "other-provider" }},
		{name: "configuration version", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.ProviderVersion++ }},
		{name: "exact callback path", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.ProductionCallback += "/other" }},
		{name: "issuer", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.Issuer = "https://other-issuer.example" }},
		{name: "client", tenant: f.locator.Tenant, change: func(l *oauthproxy.CallbackLookup) { l.ClientID = "other-client" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := f.lookup
			if tc.change != nil {
				tc.change(&lookup)
			}
			got, err := f.service.ProxyCallbackRateSource(f.ctx, tc.tenant, lookup)
			if !errors.Is(err, oauthproxy.ErrOriginalUnavailable) || got != (oauth.CallbackRateContext{}) {
				t.Fatal("mismatch disclosed attribution or lost authoritative-denial classification", err)
			}
		})
	}
	if after := proxyCallbackRateSnapshot(t, f); after != before {
		t.Fatal("rejected attribution changed persisted state")
	}
}

func TestProxyCallbackRateSourceRejectsUnavailableOriginalWithoutEffects(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want error
	}{
		{name: "expired", sql: `UPDATE onetap_oauth.proxy_transactions SET issued_at=issued_at-interval '10 minutes',expires_at=expires_at-interval '10 minutes'`, want: oauthproxy.ErrOriginalUnavailable},
		{name: "future", sql: `UPDATE onetap_oauth.proxy_transactions SET issued_at=issued_at+interval '10 minutes',expires_at=expires_at+interval '10 minutes'`, want: oauthproxy.ErrOriginalUnavailable},
		{name: "terminal", sql: `UPDATE onetap_oauth.proxy_transactions SET version=2,outcome=2,settled_at=clock_timestamp(),state_proof_ciphertext=NULL,pkce_ciphertext=NULL`, want: oauthproxy.ErrOriginalUnavailable},
		{name: "corrupt original", sql: `UPDATE onetap_oauth.proxy_transactions SET binding_ciphertext='invalid-binding'::bytea`, want: oauthproxy.CallbackReconcile},
		{name: "unauthenticated callback locator", sql: `UPDATE onetap_oauth.proxy_transactions SET callback_command_id=decode(repeat('07',16),'hex')`, want: oauthproxy.CallbackReconcile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProxyForwardIntegration(t, false)
			if _, err := f.pool.Raw().Exec(f.ctx, tc.sql); err != nil {
				t.Fatal("prepare original condition", err)
			}
			before := proxyCallbackRateSnapshot(t, f)
			got, err := f.service.ProxyCallbackRateSource(f.ctx, f.locator.Tenant, f.lookup)
			if !errors.Is(err, tc.want) || got != (oauth.CallbackRateContext{}) {
				t.Fatal("unavailable original disclosed attribution or changed stable failure classification", err)
			}
			if after := proxyCallbackRateSnapshot(t, f); after != before {
				t.Fatal("failed attribution changed persisted state")
			}
		})
	}
}

func TestProxyCallbackRateSourceAuthenticatesOriginalStateDigest(t *testing.T) {
	f := newProxyForwardIntegration(t, false)
	original := f.original
	original.Evidence.StateDigest[0] ^= 1
	wire, err := sealProxyOriginalBinding(f.ctx, f.service.envelopes, "binding-v1", f.locator, original)
	if err != nil {
		t.Fatal("seal mismatched authenticated state", err)
	}
	defer clear(wire)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE onetap_oauth.proxy_transactions SET binding_ciphertext=$1`, wire); err != nil {
		t.Fatal("store mismatched authenticated state", err)
	}
	before := proxyCallbackRateSnapshot(t, f)
	got, err := f.service.ProxyCallbackRateSource(f.ctx, f.locator.Tenant, f.lookup)
	if !errors.Is(err, oauthproxy.ErrOriginalUnavailable) || got != (oauth.CallbackRateContext{}) {
		t.Fatal("lookup digest was accepted without matching the authenticated original state", err)
	}
	if after := proxyCallbackRateSnapshot(t, f); after != before {
		t.Fatal("mismatched authenticated state changed persisted state")
	}
}

func TestProxyCallbackRateSourceFailsClosedOnCancellation(t *testing.T) {
	f := newProxyForwardIntegration(t, false)
	before := proxyCallbackRateSnapshot(t, f)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	for _, input := range []struct {
		service *ProxyForwardService
		ctx     context.Context
	}{{f.service, ctx}, {f.service, nil}, {nil, f.ctx}} {
		got, err := input.service.ProxyCallbackRateSource(input.ctx, f.locator.Tenant, f.lookup)
		if !errors.Is(err, oauthproxy.CallbackReconcile) || got != (oauth.CallbackRateContext{}) {
			t.Fatal("uncertain attribution disclosed information or became authoritative denial", err)
		}
	}
	if after := proxyCallbackRateSnapshot(t, f); after != before {
		t.Fatal("cancelled attribution changed persisted state")
	}
}

type proxyCallbackRateState struct {
	transaction, capabilities                           string
	commands, audits, events, users, accounts, sessions int
}

func proxyCallbackRateSnapshot(t *testing.T, f proxyForwardIntegration) proxyCallbackRateState {
	t.Helper()
	var state proxyCallbackRateState
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT md5(row_to_json(t)::text) FROM onetap_oauth.proxy_transactions t),
 (SELECT md5(COALESCE(string_agg(row_to_json(c)::text,'' ORDER BY replay_digest),'')) FROM public.capability_identity_one_use c),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM audit.identity_command_bindings),
 (SELECT count(*) FROM public.identity_outbox_bindings),
 (SELECT count(*) FROM identity.users),
 (SELECT count(*) FROM identity.accounts),
 (SELECT count(*) FROM onetap_sessions.sessions)`).Scan(&state.transaction, &state.capabilities,
		&state.commands, &state.audits, &state.events, &state.users, &state.accounts, &state.sessions)
	if err != nil {
		t.Fatal("read attribution no-effect snapshot", err)
	}
	return state
}
