//go:build integration

package postgres

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestRPProviderDenialHistoricalCleanupUsesExpiredMetadataWithoutBrowserProof(t *testing.T) {
	ctx, start, out, _, _, pool, now := storedRPCallbackFixture(t, -11*time.Minute)
	b := out.Binding.Input.binding()
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	candidate := rpExpiredTransaction{position: rpExpiryPosition{expires: out.Binding.ExpiresAt, tenant: string(b.TenantID), id: b.RecordID}, provider: out.Binding.Provider.ID, origin: origin, digest: out.Binding.StateDigest[:], binding: out.BindingCiphertext, issued: out.Binding.IssuedAt}
	flow, err := start.service.expiredRecoveryFlow(ctx, candidate)
	if err != nil || !flow.binding.ExpiresAt.Before(now.Add(11*time.Minute)) {
		t.Fatal("historical owner could not authenticate expired RP metadata", err)
	}
	phase := &rpDenialPhase{service: start.service, flow: flow}
	if phase.request.Callback.Denied() || flow.stateGrant.EnvelopeDigest() != ([32]byte{}) || len(flow.pkce.ciphertext) != 0 {
		t.Fatal("historical cleanup fabricated live callback/proof custody")
	}
	for _, mode := range []string{"foreign-command", "foreign-state", "rollback", "commit"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			binding, state := phase.historicalBinding(), flow.statePlan
			if mode == "foreign-command" {
				binding.RecordID = "foreign-rp"
			}
			if mode == "foreign-state" {
				state.ProofFingerprint[0]++
			}
			err = phase.eraseDenialExchangeSecrets(ctx, binding, state, rpRecoverySQLTransaction{tx})
			if mode == "foreign-command" || mode == "foreign-state" {
				if err == nil {
					t.Fatal("foreign terminal metadata erased RP secrets")
				}
				return
			}
			if err != nil {
				t.Fatal("historical cleanup required live browser/proof", err)
			}
			if mode == "commit" {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var intact bool
			if err := pool.Raw().QueryRow(ctx, `SELECT pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL AND secrets_erased_at IS NULL FROM oauth_rp.transactions WHERE tenant_id=$1 AND transaction_id=$2`, string(b.TenantID), b.RecordID).Scan(&intact); err != nil || intact != (mode == "rollback") {
				t.Fatal("denial cleanup did not share terminal rollback/commit", err)
			}
		})
	}
}
