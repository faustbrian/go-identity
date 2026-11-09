//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// This adapter exercises the native RP erasure predicate in an owned SQL
// transaction. Root tests separately prove its coordinator invocation, proof
// release, audit and terminal receipt are atomic; it is not full callback proof.
type rpRecoverySQLTransaction struct{ pgx.Tx }

func (w rpRecoverySQLTransaction) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	result, err := w.Tx.Exec(ctx, sql, args...)
	return result.RowsAffected(), err
}

func TestRPRecoveryErasureUsesExactOriginalMetadataWithoutLiveCallbackCustody(t *testing.T) {
	ctx, start, retained, _, request, pool, now := storedRPCallbackFixture(t, 0)
	flow, err := start.service.loadRPLinkCallback(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.destroy()
	phase := &rpLinkPhase{service: start.service, flow: flow}
	spec, err := callbackSpecification(flow)
	if err != nil {
		t.Fatal(err)
	}
	// No callback-bearing command or final Grant exists in this phase. Even
	// expired execution freshness must not prevent authenticated terminal erasure.
	phase.flow.loadedAt = now.Add(-time.Minute)
	if phase.requireFresh(now) == nil || !phase.matchesRetainedLinkScope(spec.Binding, flow.statePlan) {
		t.Fatal("cleanup metadata was conflated with live execution freshness")
	}
	foreign := spec.Binding
	foreign.RecordID = "other-account"
	if phase.matchesRetainedLinkScope(foreign, flow.statePlan) {
		t.Fatal("foreign account matched retained cleanup scope")
	}
	wrongState := flow.statePlan
	wrongState.ProofFingerprint[0]++
	if phase.matchesRetainedLinkScope(spec.Binding, wrongState) {
		t.Fatal("another original state matched retained cleanup scope")
	}
	for name, mutate := range map[string]func(*rpLinkPhase){
		"tenant":      func(p *rpLinkPhase) { p.flow.binding.Input.Binding.TenantID = "other-tenant" },
		"user":        func(p *rpLinkPhase) { p.flow.binding.Input.Binding.UserID = "other-user" },
		"transaction": func(p *rpLinkPhase) { p.flow.binding.Input.Binding.RecordID = "other-transaction" },
		"origin": func(p *rpLinkPhase) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			p.flow.binding.Input.Binding.CommandID = id
		},
		"provider-version": func(p *rpLinkPhase) { p.flow.binding.Provider.Version++ },
		"issuer":           func(p *rpLinkPhase) { p.flow.binding.Provider.Issuer = "https://other.example" },
		"client":           func(p *rpLinkPhase) { p.flow.binding.Provider.ClientID = "other-client" },
		"redirect":         func(p *rpLinkPhase) { p.flow.binding.Provider.RedirectURI = "https://app.example/other" },
		"state-key":        func(p *rpLinkPhase) { p.flow.binding.StateKeyVersion++ },
		"pkce-key":         func(p *rpLinkPhase) { p.flow.binding.PKCEKeyVersion++ },
		"state-digest":     func(p *rpLinkPhase) { p.flow.binding.StateDigest[0]++ },
		"pkce-commitment":  func(p *rpLinkPhase) { p.flow.binding.PKCECommitment[0]++ },
		"issued":           func(p *rpLinkPhase) { p.flow.binding.IssuedAt = p.flow.binding.IssuedAt.Add(time.Second) },
		"expires":          func(p *rpLinkPhase) { p.flow.binding.ExpiresAt = p.flow.binding.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := *phase
			mutate(&wrong)
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if err := wrong.eraseExchangeSecrets(ctx, rpRecoverySQLTransaction{tx}); err == nil {
				t.Fatal("substituted original RP metadata erased exchange custody")
			}
		})
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := phase.eraseExchangeSecrets(ctx, rpRecoverySQLTransaction{tx}); err != nil {
		t.Fatal("exact historical metadata could not erase native RP custody", err)
	}
	b := retained.Binding.Input.binding()
	var erased bool
	if err := tx.QueryRow(ctx, `SELECT version=2 AND secrets_erased_at IS NOT NULL AND pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL FROM oauth_rp.transactions WHERE tenant_id=$1 AND transaction_id=$2`, string(b.TenantID), b.RecordID).Scan(&erased); err != nil || !erased {
		t.Fatal("native erasure omitted original exchange secrets", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT version=1 AND secrets_erased_at IS NULL AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL FROM oauth_rp.transactions WHERE tenant_id=$1 AND transaction_id=$2`, string(b.TenantID), b.RecordID).Scan(&erased); err != nil || !erased {
		t.Fatal("rolled-back terminal transaction erased native RP custody", err)
	}
}
