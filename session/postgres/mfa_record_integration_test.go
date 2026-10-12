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

// A rolled-back storage oracle, not native MFA authentication or session
// issuance. Real JSONB, constraints and exact primary-record comparison are
// exercised here; the public protected workflow remains a separate obligation.
func testMFAPrimaryRecord(t *testing.T, ctx context.Context, pool *database.Pool) {
	for _, csrf := range []bool{false, true} {
		func() {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			source := magicLinkRecordFixture(t, csrf)
			s, _ := source.Bindings()
			primary, _ := source.MagicLinkAuthentication().Bindings()
			now := time.Now().UTC()
			s.IssuedAt, s.LastActivityAt = now, now
			primary.AuthenticatedAt, primary.ValidUntil = now.Add(-time.Minute), now.Add(time.Minute)
			m, _ := session.NewMagicLinkAuthentication(primary)
			a, _ := s.Authority.Bindings()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor/user", Version: 7}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
			remember, _ := s.Remember.Bindings()
			p := session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: primary.CommandID, ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: remember, VerifiedAt: now, ValidUntil: primary.ValidUntil}
			factor, err := session.NewMFAAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			var expected session.Session
			if csrf {
				expected, err = session.NewSessionWithMagicLinkMFAAndCSRF(s, m, factor, source.CSRFState())
			} else {
				expected, err = session.NewSessionWithMagicLinkMFA(s, m, factor)
			}
			if err != nil {
				t.Fatal(err)
			}
			payload, expiry, err := encodeRecord(expected)
			if err != nil {
				t.Fatal(err)
			}
			tag, err := tx.Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='tenant-a' AND session_id='session-a'`, payload, expiry)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("complete MFA record rejected", err)
			}
			cfg := Config{Schema: "session_store", MaximumDuration: time.Second}
			if err := RequireSession(ctx, tx, cfg, expected); err != nil {
				t.Fatal("exact primary MFA comparison denied", err)
			}
			p.EnrollmentVersion++
			other, _ := session.NewMFAAuthentication(p)
			var changed session.Session
			if csrf {
				changed, err = session.NewSessionWithMagicLinkMFAAndCSRF(s, m, other, source.CSRFState())
			} else {
				changed, err = session.NewSessionWithMagicLinkMFA(s, m, other)
			}
			var denied identity.ForbiddenError
			if err != nil || !errors.As(RequireSession(ctx, tx, cfg, changed), &denied) {
				t.Fatal("substituted factor enrollment accepted", err)
			}
			for _, mutation := range []string{
				`record-'MFA'`,
				`jsonb_set(record,'{MFA,FactorAuthorityVersion}','8')`,
				`jsonb_set(record,'{MFA,Method}','"passkey"')`,
				`jsonb_set(record,'{MFA,ContinuationScopeDigest}','[1]')`,
				`jsonb_set(record,'{MFA,ContinuationScopeDigest,0}','null')`,
				`jsonb_set(record,'{MFA,ContinuationScopeDigest,0}','0.5')`,
				`jsonb_set(record,'{MFA,ContinuationScopeDigest,0}','256')`,
				`jsonb_set(record,'{MFA,EnrollmentVersion}','0')`,
				`jsonb_set(record,'{MFA,ContinuationVersion}','18446744073709551615')`,
				`jsonb_set(record,'{MFA,PrimaryCommandID}','"BwcHBwcHBwcHBwcHBwcHBw"')`,
				`jsonb_set(record,'{MFA,Remember,Choice}','3')`,
				`jsonb_set(record,'{Authority,Factor,Present}','false')`,
			} {
				if _, err := tx.Exec(ctx, `SAVEPOINT bad_record`); err != nil {
					t.Fatal(err)
				}
				_, err := tx.Exec(ctx, `UPDATE session_store.sessions SET record=`+mutation+` WHERE tenant_id='tenant-a' AND session_id='session-a'`)
				var constraint *pgconn.PgError
				if !errors.As(err, &constraint) || constraint.Code != "23514" {
					t.Fatal("database admitted malformed factor state", err)
				}
				if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT bad_record`); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}
}

// Only the purpose constraint is isolated here. The real coordinator/native
// issuance effect must separately prove authenticated atomic session creation.
func testMFASigninPurposes(t *testing.T, ctx context.Context, pool *database.Pool) {
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `CREATE SCHEMA session_mfa_purpose;
CREATE TABLE session_mfa_purpose.session_issuances(purpose text NOT NULL,CONSTRAINT session_issuances_purpose_v5 CHECK(purpose IN('identity.session.issue','identity.otp.signin','identity.password.signin','identity.password.signup','identity.magic-link.consume')));
INSERT INTO session_mfa_purpose.session_issuances(purpose) VALUES('identity.password.signin'),('identity.magic-link.consume');`); err != nil {
		t.Fatal(err)
	}
	source, err := (MFASigninMigrationSource{Schema: "session_mfa_purpose", Version: 18}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, source[0].UpSQL()); err != nil {
		t.Fatal("populated issuance purpose migration failed", err)
	}
	for _, purpose := range []string{"identity.mfa.totp-verify", "identity.mfa.otp-verify", "identity.mfa.recovery-use", "identity.mfa.security-key-assert-verify"} {
		if _, err := tx.Exec(ctx, `INSERT INTO session_mfa_purpose.session_issuances(purpose) VALUES($1)`, purpose); err != nil {
			t.Fatal("closed MFA completion purpose denied", err)
		}
	}
	var legacy int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM session_mfa_purpose.session_issuances WHERE purpose IN('identity.password.signin','identity.magic-link.consume')`).Scan(&legacy); err != nil || legacy != 2 {
		t.Fatal("migration rewrote existing purposes", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO session_mfa_purpose.session_issuances(purpose) VALUES('identity.mfa.enable')`)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "23514" {
		t.Fatal("non-completion purpose became session issuance", err)
	}
}
