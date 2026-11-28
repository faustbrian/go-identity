//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"reflect"
	"testing"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestProxyRetirementDiscoveryProductionFindsOnlyDisabledEpochWithoutEffects(t *testing.T) {
	f := newProxyStartIntegration(t)
	providerAuthority, operator := installProxyProviderEpochAuthority(t, f)
	f.forward.providerAuthority = providerAuthority
	key := ProviderAuthorityKey{TenantID: oneTapStartTenant, ProviderID: f.provider.ID}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 41, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(f.ctx, configure); err != nil || state != configure.Next {
		t.Fatal("configure the provider before real native origins", err)
	}
	firstRequest := f.request
	firstRequest.TransactionID = "AQEBAQEBAQEBAQEBAQEBAQ"
	secondRequest := freshProxyProviderEpochRequest(t, f.request)
	secondRequest.TransactionID = "AwMDAwMDAwMDAwMDAwMDAw"
	first, _ := startProxyProviderEpochOriginal(t, f, firstRequest, 41)
	second, _ := startProxyProviderEpochOriginal(t, f, secondRequest, 41)
	proxyRetirementDiscoveryInstall(t, f.ctx, f.pool, f.forward.config.Schema, kernel.OAuthProxyRetireProduction)
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 41, Next: ProviderAuthorityState{Version: 42, ProfileVersion: f.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 42, Next: ProviderAuthorityState{Version: 43, ProfileVersion: f.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	for _, change := range []ProviderAuthorityChange{disable, reenable} {
		if state, err := operator.Apply(f.ctx, change); err != nil || state != change.Next {
			t.Fatal("commit the exact disable followed by a distinct re-enabled epoch", err)
		}
	}
	// The filtered row sorts between the two old originals under the query's
	// byte order. A page of one must advance past it despite no returned match.
	freshRequest := freshProxyProviderEpochRequest(t, f.request)
	freshRequest.TransactionID = "AgICAgICAgICAgICAgICAg"
	fresh, _ := startProxyProviderEpochOriginal(t, f, freshRequest, 43)
	authority := proxyRetirementDiscoveryAuthority(t, providerAuthority.pool)
	before := proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions")
	proxyRetirementDiscoveryAssertPages(t, f.ctx, f.forward.ListDisabledProviderOrigins, authority, disable,
		[]ProxyRetirementOrigin{
			{OriginCommandID: first.CommandID, FlowID: first.TransactionID},
			{OriginCommandID: second.CommandID, FlowID: second.TransactionID},
		}, ProxyRetirementOrigin{OriginCommandID: fresh.CommandID, FlowID: fresh.TransactionID})
	proxyRetirementDiscoveryAssertDenied(t, f.ctx, f.forward.ListDisabledProviderOrigins, authority, disable, reenable)
	if proxyRetirementDiscoverySnapshot(t, f.ctx, f.pool, "proxy_transactions") != before {
		t.Fatal("discovery changed production custody, grants, command history, audit, outbox or identity state")
	}
}

func TestProxyRetirementDiscoveryPreviewFindsOnlyDisabledEpochWithoutEffects(t *testing.T) {
	production, preview, callback, operator, key := newProxyPreviewProviderAuthorityHandoff(t)
	proxyRetirementDiscoveryInstall(t, preview.ctx, preview.pool, preview.completion.start.config.Schema, kernel.OAuthProxyRetirePreview)
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: proxyPreviewAuthorityEpoch,
		Next:      ProviderAuthorityState{Version: proxyPreviewAuthorityEpoch + 1, ProfileVersion: production.provider.Version},
		CommandID: providerAuthorityCommand(t),
	}
	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: disable.Next.Version,
		Next:      ProviderAuthorityState{Version: disable.Next.Version + 1, ProfileVersion: production.provider.Version, Enabled: true},
		CommandID: providerAuthorityCommand(t),
	}
	for _, change := range []ProviderAuthorityChange{disable, reenable} {
		if state, err := operator.Apply(production.ctx, change); err != nil || state != change.Next {
			t.Fatal("commit the retained disable and re-enable through the production operator", err)
		}
	}
	newFlow, newCookie := preview.issueBrowser(t, production.request.Remember)
	newStart := production.request
	newStart.CommandID = providerAuthorityCommand(t)
	newStart.TransactionID = newFlow
	newStart.RequestFingerprint = sha256.Sum256([]byte("retirement-discovery-newer-preview-origin"))
	started, err := production.start.Start(production.ctx, newStart)
	if err != nil {
		t.Fatal("start the independent newer-epoch preview origin", err)
	}
	newBinding, ok := started.Binding()
	if !ok || newBinding.ProviderAuthorityEpoch != reenable.Next.Version {
		t.Fatal("new preview origin did not retain its distinct re-enabled epoch")
	}
	if err := preview.service.Bind(preview.ctx, ProxyPreviewBindRequest{
		Binding: newBinding, FlowCookie: newCookie, Origin: production.target.Origin,
		Network: "192.0.2.21", Device: "retirement-discovery-newer-browser",
	}); err != nil {
		t.Fatal("bind the newer origin through the actual preview owner", err)
	}
	authority := proxyRetirementDiscoveryAuthority(t, production.pool)
	beforePreview := proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings")
	beforeProduction := proxyRetirementDiscoverySnapshot(t, production.ctx, production.pool, "proxy_transactions")
	proxyRetirementDiscoveryAssertPages(t, preview.ctx, preview.service.ListDisabledProviderOrigins, authority, disable,
		[]ProxyRetirementOrigin{{OriginCommandID: production.request.CommandID, FlowID: callback.FlowID}},
		ProxyRetirementOrigin{OriginCommandID: newStart.CommandID, FlowID: newFlow})
	proxyRetirementDiscoveryAssertDenied(t, preview.ctx, preview.service.ListDisabledProviderOrigins, authority, disable, reenable)
	if proxyRetirementDiscoverySnapshot(t, preview.ctx, preview.pool, "proxy_preview_bindings") != beforePreview ||
		proxyRetirementDiscoverySnapshot(t, production.ctx, production.pool, "proxy_transactions") != beforeProduction {
		t.Fatal("preview discovery changed either origin's custody, grants, browser, command history, audit, outbox or identity state")
	}
	if preview.keys.opens.Load() != 0 {
		t.Fatal("discovery opened provider bearer evidence instead of authenticating only original binding")
	}
}

type proxyRetirementDiscoveryReader func(context.Context, *ProxyRetirementAuthority, ProxyRetirementDiscoveryRequest) (ProxyRetirementDiscoveryPage, error)

func proxyRetirementDiscoveryAssertPages(t *testing.T, ctx context.Context, list proxyRetirementDiscoveryReader, authority *ProxyRetirementAuthority,
	disable ProviderAuthorityChange, want []ProxyRetirementOrigin, filtered ProxyRetirementOrigin) {
	t.Helper()
	wantByFlow := make(map[identity.PreAuthTransactionID]ProxyRetirementOrigin, len(want))
	filteredHasSuccessor := false
	for _, origin := range want {
		wantByFlow[origin.FlowID] = origin
		filteredHasSuccessor = filteredHasSuccessor || filtered.FlowID < origin.FlowID
	}
	if _, exists := wantByFlow[filtered.FlowID]; exists {
		t.Fatal("the real newer origin is not independent of the old epoch fixtures")
	}
	for _, limit := range []uint16{1, 2, 32} {
		seen := make(map[identity.PreAuthTransactionID]bool, len(want))
		request := ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: limit}
		scanned, filteredRows := 0, 0
		finished, continuedPastFiltered := false, false
		for range len(want) + 2 {
			page, err := list(ctx, authority, request)
			if err != nil {
				t.Fatal("exact historical disable did not discover its retained local originals", err)
			}
			if page.Scanned == 0 || page.Scanned > limit || len(page.Origins) > int(page.Scanned) {
				t.Fatal("discovery did not report its bounded scanned-row work")
			}
			scanned += int(page.Scanned)
			filteredRows += int(page.Scanned) - len(page.Origins)
			for _, origin := range page.Origins {
				expected, eligible := wantByFlow[origin.FlowID]
				if !eligible || !reflect.DeepEqual(origin, expected) || seen[origin.FlowID] {
					t.Fatal("discovery returned a newer, duplicate or inexact original instead of only original IDs")
				}
				seen[origin.FlowID] = true
			}
			if page.NextAfterFlowID == "" {
				finished = true
				break
			}
			if string(page.NextAfterFlowID) <= string(request.AfterFlowID) {
				t.Fatal("a bounded page, including a filtered-only page, did not advance its scanned cursor")
			}
			if limit == 1 && len(page.Origins) == 0 {
				if page.NextAfterFlowID != filtered.FlowID {
					t.Fatal("the empty nonterminal page did not advance from its filtered row")
				}
				continuedPastFiltered = true
			}
			request.AfterFlowID = page.NextAfterFlowID
		}
		if !finished || len(seen) != len(want) || scanned != len(want)+1 || filteredRows != 1 {
			t.Fatal("bounded pages did not terminate with every old original exactly once and the newer row filtered")
		}
		if limit == 1 && continuedPastFiltered != filteredHasSuccessor {
			t.Fatal("the filtered row's continuation did not reflect whether more custody remained")
		}
	}
}

func proxyRetirementDiscoveryAssertDenied(t *testing.T, ctx context.Context, list proxyRetirementDiscoveryReader, authority *ProxyRetirementAuthority,
	disable, reenable ProviderAuthorityChange) {
	t.Helper()
	for _, test := range []struct {
		name   string
		change func(*ProviderAuthorityChange)
	}{
		{"uncommitted source", func(c *ProviderAuthorityChange) { c.CommandID = providerAuthorityCommand(t) }},
		{"re-enable source", func(c *ProviderAuthorityChange) { c.CommandID = reenable.CommandID }},
		{"enabled transition", func(c *ProviderAuthorityChange) { *c = reenable }},
		{"wrong provider", func(c *ProviderAuthorityChange) { c.Key.ProviderID = "another-provider" }},
		{"wrong tenant", func(c *ProviderAuthorityChange) { c.Key.TenantID = "AAAAAAAAAAAAAAAAAAAAAg" }},
		{"wrong prior epoch", func(c *ProviderAuthorityChange) { c.ExpectedVersion-- }},
		{"wrong disable epoch", func(c *ProviderAuthorityChange) { c.Next.Version++ }},
		{"wrong profile", func(c *ProviderAuthorityChange) { c.Next.ProfileVersion++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := disable
			test.change(&changed)
			page, err := list(ctx, authority, ProxyRetirementDiscoveryRequest{Disable: changed, ScanLimit: 1})
			proxyProviderDisableAssertDenied(t, err)
			if !reflect.DeepEqual(page, ProxyRetirementDiscoveryPage{}) {
				t.Fatal("unauthenticated disable disclosed a candidate or cursor")
			}
		})
	}
	for _, limit := range []uint16{0, 33} {
		page, err := list(ctx, authority, ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: limit})
		if err == nil || !reflect.DeepEqual(page, ProxyRetirementDiscoveryPage{}) {
			t.Fatal("out-of-range scan limit disclosed a page or was silently accepted")
		}
	}
	page, err := list(ctx, nil, ProxyRetirementDiscoveryRequest{Disable: disable, ScanLimit: 1})
	proxyProviderDisableAssertDenied(t, err)
	if !reflect.DeepEqual(page, ProxyRetirementDiscoveryPage{}) {
		t.Fatal("missing trusted authority disclosed a candidate or cursor")
	}
}

func proxyRetirementDiscoveryAuthority(t *testing.T, pool *database.Pool) *ProxyRetirementAuthority {
	t.Helper()
	reader, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct the separate retained-disable audit reader", err)
	}
	authority, err := NewProxyRetirementAuthority(reader, oneTapStartActor)
	if err != nil {
		t.Fatal("construct trusted discovery authority", err)
	}
	return authority
}

func proxyRetirementDiscoveryInstall(t *testing.T, ctx context.Context, pool *database.Pool, schema string, kind kernel.OAuthProxyRetirementKind) {
	t.Helper()
	history, err := (ProxyRetirementMigrationSource{Schema: schema, Version: 70, Kind: kind}).Load(ctx)
	if err != nil || len(history) != 2 {
		t.Fatal("load actual retirement expansion and validation", err)
	}
	for _, migration := range history {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal("begin retirement migration", err)
		}
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("apply retirement migration to populated original custody", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("commit retirement migration", err)
		}
	}
}

func proxyRetirementDiscoverySnapshot(t *testing.T, ctx context.Context, pool *database.Pool, custodyTable string) string {
	t.Helper()
	var snapshot string
	query := `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM onetap_oauth.` + custodyTable + ` x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM public.capability_identity_one_use x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM identity.commands x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM audit.records x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM audit.identity_command_bindings x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM public.outbox_messages x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM public.identity_outbox_bindings x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM onetap_sessions.preauth_transactions x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM onetap_sessions.sessions x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM identity.users x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM identity.accounts x))::text`
	if err := pool.Raw().QueryRow(ctx, query).Scan(&snapshot); err != nil {
		t.Fatal("snapshot actual discovery side effects", err)
	}
	return snapshot
}
