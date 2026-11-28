//go:build integration

package postgres

import (
	"errors"
	"testing"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
)

func TestProxyProviderDisableAuthenticatesExactHistoricalCommand(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	reader, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct the real retained audit reader", err)
	}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(ctx, configure); err != nil || state != configure.Next {
		t.Fatal("commit the selected enabled provider profile", state, err)
	}
	proxyProviderDisableAssertDenied(t, readProxyProviderDisable(ctx, reader, oneTapStartActor, configure))

	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t),
	}
	proxyProviderDisableAssertDenied(t, readProxyProviderDisable(ctx, reader, oneTapStartActor, disable))
	if state, err := operator.Apply(ctx, disable); err != nil || state != disable.Next {
		t.Fatal("commit the exact provider disable", state, err)
	}
	if err := readProxyProviderDisable(ctx, reader, oneTapStartActor, disable); err != nil {
		t.Fatal("the committed disable did not authenticate against retained audit", err)
	}
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)

	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 8, Next: ProviderAuthorityState{Version: 9, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if state, err := operator.Apply(ctx, reenable); err != nil || state != reenable.Next {
		t.Fatal("re-enable the same profile under a later authority epoch", state, err)
	}
	if err := readProxyProviderDisable(ctx, reader, oneTapStartActor, disable); err != nil {
		t.Fatal("current re-enable erased authentication of the exact historical disable", err)
	}
	proxyProviderDisableAssertDenied(t, readProxyProviderDisable(ctx, reader, oneTapStartActor, reenable))

	for _, test := range []struct {
		name   string
		change func(*ProviderAuthorityChange)
	}{
		{"wrong prior epoch", func(c *ProviderAuthorityChange) { c.ExpectedVersion = 6 }},
		{"wrong new epoch", func(c *ProviderAuthorityChange) { c.Next.Version = 9 }},
		{"wrong tenant", func(c *ProviderAuthorityChange) { c.Key.TenantID = "AAAAAAAAAAAAAAAAAAAAAg" }},
		{"wrong provider", func(c *ProviderAuthorityChange) { c.Key.ProviderID = "another-oidc" }},
		{"profile drift", func(c *ProviderAuthorityChange) { c.Next.ProfileVersion = 4 }},
		{"enabled attempt", func(c *ProviderAuthorityChange) { c.Next.Enabled = true }},
		{"uncommitted command", func(c *ProviderAuthorityChange) { c.CommandID = providerAuthorityCommand(t) }},
		{"configuration command substituted", func(c *ProviderAuthorityChange) { c.CommandID = configure.CommandID }},
		{"re-enable command substituted", func(c *ProviderAuthorityChange) { c.CommandID = reenable.CommandID }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := disable
			test.change(&changed)
			proxyProviderDisableAssertDenied(t, readProxyProviderDisable(ctx, reader, oneTapStartActor, changed))
		})
	}
	t.Run("wrong operator", func(t *testing.T) {
		proxyProviderDisableAssertDenied(t, readProxyProviderDisable(ctx, reader, identity.ActorID("AAAAAAAAAAAAAAAAAAAAAg"), disable))
	})
	providerAuthorityAssertState(t, ctx, authority, key, reenable.Next)
	if err := readProxyProviderDisable(ctx, reader, oneTapStartActor, disable); err != nil {
		t.Fatal("denied alternatives changed the retained disable evidence", err)
	}
}

func TestProxyProviderDisableRequiresRetainedPayload(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	reader, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct the real retained audit reader", err)
	}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t),
	}
	for _, change := range []ProviderAuthorityChange{configure, disable} {
		if state, err := operator.Apply(ctx, change); err != nil || state != change.Next {
			t.Fatal("commit real authority and audit before payload retention", state, err)
		}
	}
	if err := readProxyProviderDisable(ctx, reader, oneTapStartActor, disable); err != nil {
		t.Fatal("authenticate the exact disable before pruning its payload", err)
	}

	recordID := "oauth-provider-authority:" + string(disable.CommandID)
	var pruned bool
	if err := pool.Raw().QueryRow(ctx, `SELECT audit.prune_record(record_id,canonical_sha256)
 FROM audit.records WHERE record_id=$1`, recordID).Scan(&pruned); err != nil || !pruned {
		t.Fatal("prune only the fixture's exact disable payload through native retention", pruned, err)
	}
	var payloads, identities int
	if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM audit.records WHERE record_id=$1),
 (SELECT count(*) FROM audit.record_identities WHERE record_id=$1)`, recordID).Scan(&payloads, &identities); err != nil || payloads != 0 || identities != 1 {
		t.Fatal("native retention did not preserve only the disable identity tombstone", payloads, identities, err)
	}
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
	proxyProviderDisableAssertDenied(t, readProxyProviderDisable(ctx, reader, oneTapStartActor, disable))
}

func proxyProviderDisableAssertDenied(t *testing.T, err error) {
	t.Helper()
	var denied identity.ForbiddenError
	if !errors.As(err, &denied) || err.Error() != denied.Error() {
		t.Fatal("unproven provider disable did not return a typed redacted denial", err)
	}
}
