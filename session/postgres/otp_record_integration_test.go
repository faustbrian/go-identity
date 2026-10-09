//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func testOTPPrimaryRecord(t *testing.T, ctx context.Context, pool *database.Pool) {
	for _, csrf := range []bool{false, true} {
		func() {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			original := otpRecordFixture(t, csrf)
			base, _ := original.Bindings()
			p, _ := original.OTPAuthentication().Bindings()
			now := time.Now().UTC()
			base.IssuedAt, base.LastActivityAt = now, now
			p.AuthenticatedAt, p.ValidUntil = now.Add(-time.Second), now.Add(time.Minute)
			metadata, err := session.NewOTPAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			var expected session.Session
			if csrf {
				expected, err = session.NewSessionWithOTPAndCSRF(base, metadata, original.CSRFState())
			} else {
				expected, err = session.NewSessionWithOTP(base, metadata)
			}
			if err != nil {
				t.Fatal(err)
			}
			payload, expiry, err := encodeRecord(expected)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
				t.Fatal("native OTP record cannot persist", err)
			}
			cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
			if err := RequireSession(ctx, tx, cfg, expected); err != nil {
				t.Fatal("exact current primary OTP record denied", err)
			}
			p.AttemptID = "BAQEBAQEBAQEBAQEBAQEBA"
			substituted, err := session.NewOTPAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			var changed session.Session
			if csrf {
				changed, err = session.NewSessionWithOTPAndCSRF(base, substituted, original.CSRFState())
			} else {
				changed, err = session.NewSessionWithOTP(base, substituted)
			}
			if err != nil {
				t.Fatal(err)
			}
			var denied identity.ForbiddenError
			if err := RequireSession(ctx, tx, cfg, changed); !errors.As(err, &denied) {
				t.Fatal("substituted original attempt admitted", err)
			}
			for _, mutate := range []func(map[string]json.RawMessage){
				func(v map[string]json.RawMessage) { delete(v, "OTP") },
				func(v map[string]json.RawMessage) { v["OTP"] = json.RawMessage(`null`) },
				func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`1`) },
				func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`2`) },
				func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`5`) },
				func(v map[string]json.RawMessage) { delete(v, "CSRF"); v["Schema"] = json.RawMessage(`4`) },
			} {
				var top map[string]json.RawMessage
				if err := json.Unmarshal(payload, &top); err != nil {
					t.Fatal(err)
				}
				mutate(top)
				bad, err := json.Marshal(top)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, "SAVEPOINT malformed_otp"); err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='tenant-a' AND session_id='session-a'`, bad)
				var check *pgconn.PgError
				if !errors.As(err, &check) || check.Code != "23514" {
					t.Fatal("database admitted an incomplete method profile", err)
				}
				if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT malformed_otp"); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}
}
