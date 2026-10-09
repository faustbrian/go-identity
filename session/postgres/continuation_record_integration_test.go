//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func testContinuedPrimaryRecord(t *testing.T, ctx context.Context, pool *database.Pool, original session.Session) {
	for _, csrf := range []bool{false, true} {
		func() {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			base, _ := original.Bindings()
			base.Authentication.Proof.Method = "password"
			base.Authentication.CredentialID = "password-a"
			base.Authentication.CredentialVersion = math.MaxUint64 - 1
			vector, _ := base.Authority.Bindings()
			vector.Credential.Version = math.MaxUint64 - 1
			base.Authority, err = session.NewAuthoritySnapshot(vector)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			base.IssuedAt, base.LastActivityAt = now, now
			base.Authentication.Proof.IssuedAt, base.Authentication.Proof.ExpiresAt = now.Add(-time.Minute), now.Add(time.Minute)
			source, err := session.NewSession(base)
			if err != nil {
				t.Fatal(err)
			}
			if csrf {
				source = withCSRFState(t, source, 9)
			}
			expected, err := session.ContinuePasswordSession(source, session.CredentialContinuationSpec{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", BeforeAuthorityVersion: math.MaxUint64 - 1, BeforeCredentialVersion: math.MaxUint64 - 1})
			if err != nil {
				t.Fatal(err)
			}
			payload, expiry, err := encodeRecord(expected)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
				t.Fatal("continued primary record cannot persist", err)
			}
			var stored []byte
			if err := tx.QueryRow(ctx, `SELECT record FROM session_store.sessions WHERE tenant_id='tenant-a' AND session_id='session-a'`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			restored, err := decodeRecord(stored)
			if err != nil || restored.EffectiveCredentialVersion() != math.MaxUint64 {
				t.Fatal("jsonb lost exact effective version", err)
			}
			cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
			if err := RequireSession(ctx, tx, cfg, restored); err != nil {
				t.Fatal("complete continued record denied", err)
			}
			stripped, err := session.NewSession(base)
			if err != nil {
				t.Fatal(err)
			}
			var denied identity.ForbiddenError
			if err := RequireSession(ctx, tx, cfg, stripped); !errors.As(err, &denied) {
				t.Fatal("historical linkage admitted", err)
			}
			for _, mutate := range []func(map[string]json.RawMessage){
				func(v map[string]json.RawMessage) { delete(v, "Continuation") },
				func(v map[string]json.RawMessage) { v["Continuation"] = json.RawMessage(`null`) },
				func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`1`) },
				func(v map[string]json.RawMessage) { v["OTP"] = json.RawMessage(`{}`) },
				func(v map[string]json.RawMessage) {
					v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":18446744073709551615,"BeforeCredentialVersion":9}`)
				},
				func(v map[string]json.RawMessage) {
					v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":1,"BeforeCredentialVersion":9,"Unknown":1}`)
				},
			} {
				var top map[string]json.RawMessage
				json.Unmarshal(payload, &top)
				mutate(top)
				bad, _ := json.Marshal(top)
				if _, err := tx.Exec(ctx, "SAVEPOINT malformed_continuation"); err != nil {
					t.Fatal(err)
				}
				_, err := tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='tenant-a' AND session_id='session-a'`, bad)
				var check *pgconn.PgError
				if !errors.As(err, &check) || check.Code != "23514" {
					t.Fatal("database accepted malformed continuation", err)
				}
				if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT malformed_continuation"); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}
}
