//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// The maintenance seam must work without a returning browser, live session or
// usable state proof. These fixtures retain genuine AEAD/checkpoint custody;
// the optional callback claim is storage evidence, not a simulated exchange.
type rpExpiryOwner interface {
	EraseExpiredUnused(context.Context, int, string) (int, string, error)
}

func TestRPExpiredUnusedCustodyErasure(t *testing.T) {
	for _, mode := range []string{"abandoned", "live", "callback-claimed", "callback-row-locked", "corrupt-binding"} {
		t.Run(mode, func(t *testing.T) {
			offset := -11 * time.Minute
			if mode == "live" {
				offset = 0
			}
			ctx, start, out, _, _, pool, _ := storedRPCallbackFixture(t, offset)
			owner, ok := any(start.service).(rpExpiryOwner)
			if !ok {
				t.Fatal("native RP owner has no bounded abandoned-expiry erasure entry point")
			}
			b := start.input.binding()
			if mode == "callback-claimed" {
				id, err := base64.RawURLEncoding.Strict().DecodeString(string(out.Binding.CallbackCommandID))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.account.link-token',$3,1,$4)`, id, string(b.TenantID), make([]byte, 32), []byte{1}); err != nil {
					t.Fatal("retain callback claim", err)
				}
			}
			if mode == "corrupt-binding" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE oauth_rp.transactions SET binding_ciphertext=$1`, []byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "callback-row-locked" {
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, `SELECT transaction_id FROM oauth_rp.transactions FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
				erased, _, err := owner.EraseExpiredUnused(ctx, 1, "")
				if err != nil || erased != 0 {
					t.Fatal("expiry competed with active callback admission", erased, err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
			erased, cursor, err := owner.EraseExpiredUnused(ctx, 1, "")
			want := 0
			if mode == "abandoned" || mode == "callback-row-locked" {
				want = 1
			}
			if mode == "corrupt-binding" {
				if err == nil || erased != 0 {
					t.Fatal("unauthenticated metadata authorized expiry erasure")
				}
			} else if err != nil || erased != want {
				t.Fatal("expiry confused unused custody with live or claimed callback", erased, want, err)
			}
			var retained bool
			if err := pool.Raw().QueryRow(ctx, `SELECT pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL AND secrets_erased_at IS NULL FROM oauth_rp.transactions`).Scan(&retained); err != nil || retained != (want == 0) {
				t.Fatal("expiry did not preserve exact secret ownership", err)
			}
			if mode != "corrupt-binding" {
				again, _, err := owner.EraseExpiredUnused(ctx, 1, cursor)
				if err != nil || again != 0 {
					t.Fatal("expiry pagination repeated an erased or claimed row", again, err)
				}
			}
		})
	}
}

func TestRPExpiryRejectsInvalidMaintenanceInput(t *testing.T) {
	ctx, start, _, _, _, _, _ := storedRPCallbackFixture(t, 0)
	owner, ok := any(start.service).(rpExpiryOwner)
	if !ok {
		t.Fatal("native RP owner has no bounded abandoned-expiry erasure entry point")
	}
	for _, limit := range []int{-1, 0, 101} {
		if _, _, err := owner.EraseExpiredUnused(ctx, limit, ""); err == nil {
			t.Fatal("unbounded expiry maintenance limit accepted")
		}
	}
	for _, cursor := range []string{"invalid", strings.Repeat("x", 1025), "expires=1&expires=2&tenant=a&transaction=b"} {
		if _, _, err := owner.EraseExpiredUnused(ctx, 1, cursor); err == nil {
			t.Fatal("invalid expiry cursor accepted")
		}
	}
}

func TestRPExpiryPaginationAdvancesPastUncertainCallback(t *testing.T) {
	ctx, start, first, _, _, pool, _ := storedRPCallbackFixture(t, -11*time.Minute)
	owner, ok := any(start.service).(rpExpiryOwner)
	if !ok {
		t.Fatal("native RP owner has no bounded abandoned-expiry erasure entry point")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	firstID := start.input.binding().RecordID
	transaction, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	start.input.Binding.CommandID, start.input.Binding.RecordID = command, string(transaction)
	wire, err := start.generateOutput(ctx, 1)
	if err != nil {
		t.Fatal("generate second genuine encrypted transaction", err)
	}
	second, _, _, err := start.restoreOutput(ctx, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(command))
	if err != nil {
		t.Fatal(err)
	}
	b := start.input.binding()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, origin, string(b.TenantID), b.OperationID, make([]byte, 32), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, origin, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal(err)
	}
	v := second.Binding
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO oauth_rp.transactions(tenant_id,transaction_id,origin_command_id,operation,user_id,session_id,session_version,provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,state_key_version,state_digest,pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version)
 SELECT tenant_id,$1,$2,operation,user_id,session_id,session_version,provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,$3,$4,$5,$6,$7,$8,$9,$10,$11,1 FROM oauth_rp.transactions WHERE transaction_id=$12`, b.RecordID, origin, v.StateKeyVersion, v.StateDigest[:], v.PKCEKeyVersion, v.PKCECommitment[:], second.PKCECiphertext, second.StateProofCiphertext, second.BindingCiphertext, v.IssuedAt, v.ExpiresAt, firstID); err != nil {
		t.Fatal("store second genuine encrypted transaction", err)
	}
	// Choose the first row in the real cursor ordering, rather than inventing
	// a transaction ID that violates the verifier's canonical 16-byte binding.
	uncertain := first.Binding.CallbackCommandID
	if string(transaction) < firstID {
		uncertain = second.Binding.CallbackCommandID
	}
	callback, err := base64.RawURLEncoding.Strict().DecodeString(string(uncertain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.account.link-token',$3,1,$4)`, callback, string(b.TenantID), make([]byte, 32), []byte{1}); err != nil {
		t.Fatal("retain uncertain callback", err)
	}
	erased, cursor, err := owner.EraseExpiredUnused(ctx, 1, "")
	if err != nil || erased != 0 || cursor == "" {
		t.Fatal("uncertain first row did not advance bounded pagination", erased, err)
	}
	erased, cursor, err = owner.EraseExpiredUnused(ctx, 1, cursor)
	if err != nil || erased != 1 {
		t.Fatal("uncertain callback starved later abandoned custody", erased, err)
	}
	var retained int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM oauth_rp.transactions WHERE secrets_erased_at IS NULL`).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("expiry pagination erased uncertain exchange custody", err)
	}
}
