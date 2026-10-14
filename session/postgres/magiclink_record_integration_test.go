//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func testMagicLinkPrimaryRecord(t *testing.T, ctx context.Context, pool *database.Pool) {
	for _, csrf := range []bool{false, true} {
		func() {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			original := magicLinkRecordFixture(t, csrf)
			s, _ := original.Bindings()
			p, _ := original.MagicLinkAuthentication().Bindings()
			now := time.Now().UTC()
			s.IssuedAt, s.LastActivityAt = now, now
			p.AuthenticatedAt, p.ValidUntil = now.Add(-time.Second), now.Add(time.Minute)
			m, err := session.NewMagicLinkAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			var expected session.Session
			if csrf {
				expected, err = session.NewSessionWithMagicLinkAndCSRF(s, m, original.CSRFState())
			} else {
				expected, err = session.NewSessionWithMagicLink(s, m)
			}
			if err != nil {
				t.Fatal(err)
			}
			payload, expiry, err := encodeRecord(expected)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry); err != nil {
				t.Fatal("persist magic-link record", err)
			}
			cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
			if err := RequireSession(ctx, tx, cfg, expected); err != nil {
				t.Fatal("primary magic-link record denied", err)
			}
			p.CapabilityID = "substituted-grant"
			other, err := session.NewMagicLinkAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			var changed session.Session
			if csrf {
				changed, err = session.NewSessionWithMagicLinkAndCSRF(s, other, original.CSRFState())
			} else {
				changed, err = session.NewSessionWithMagicLink(s, other)
			}
			if err != nil {
				t.Fatal(err)
			}
			var denied identity.ForbiddenError
			if err := RequireSession(ctx, tx, cfg, changed); !errors.As(err, &denied) {
				t.Fatal("substituted grant admitted", err)
			}
			_, err = tx.Exec(ctx, `UPDATE session_store.sessions SET record=record-'MagicLink' WHERE tenant_id='tenant-a' AND session_id='session-a'`)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23514" {
				t.Fatal("database admitted lossy provenance", err)
			}
		}()
	}
}
