//go:build integration

package postgres

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Populated storage proof only: these synthetic challenge rows do not claim
// genuine session admission, native phone issuance or SMS delivery.
func TestPhonePurposePopulatedUpgrade(t *testing.T) {
	ctx, db, _ := otpDatabase(t)
	base, err := (MigrationSource{Schema: "otp_store", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, base[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO otp_store.digest_keys VALUES(1,'hmac-sha256-v1')`); err != nil {
		t.Fatal(err)
	}
	issue := otpCommand(t, ctx, db, "tenant", 81)
	fp := bytes.Repeat([]byte{81}, 32)
	if _, err := db.Exec(ctx, insertChallenge, "tenant", "old-challenge", issue, fp); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := db.QueryRow(ctx, `SELECT row_to_json(c)::text FROM otp_store.challenges c WHERE challenge_id='old-challenge'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	phone := strings.Replace(insertChallenge, "'email-verification'", "'phone-verification'", 1)
	phoneIssue := otpCommand(t, ctx, db, "tenant", 82)
	phoneScope := bytes.Repeat([]byte{82}, 32)
	_, err = db.Exec(ctx, phone, "tenant", "phone-challenge", phoneIssue, phoneScope)
	var prior *pgconn.PgError
	if !errors.As(err, &prior) || prior.Code != "23514" || prior.ConstraintName != "challenges_purpose_check" {
		t.Fatal("old schema did not specifically reject the new purpose")
	}
	forward, err := (PhonePurposeMigrationSource{Schema: "otp_store", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, forward[0].UpSQL()); err != nil {
		t.Fatal("phone purpose upgrade", err)
	}
	if _, err := db.Exec(ctx, phone, "tenant", "phone-challenge", phoneIssue, phoneScope); err != nil {
		t.Fatal("phone purpose not admitted by forward schema", err)
	}
	var after string
	if err := db.QueryRow(ctx, `SELECT row_to_json(c)::text FROM otp_store.challenges c WHERE challenge_id='old-challenge'`).Scan(&after); err != nil || after != before {
		t.Fatal("upgrade changed original digest/policy/attempt/deadline state", err)
	}
	for index, purpose := range []string{"signin", "password-reset", "email-change", "mfa", "step-up"} {
		sql := strings.Replace(insertChallenge, "'email-verification'", "'"+purpose+"'", 1)
		legacyIssue := otpCommand(t, ctx, db, "tenant", byte(83+index))
		legacyScope := bytes.Repeat([]byte{byte(83 + index)}, 32)
		if _, err := db.Exec(ctx, sql, "tenant", "old-"+purpose, legacyIssue, legacyScope); err != nil {
			t.Fatal("legacy purpose lost compatibility", err)
		}
	}
	foreign := strings.Replace(insertChallenge, "'email-verification'", "'phone-other'", 1)
	foreignIssue := otpCommand(t, ctx, db, "tenant", 90)
	_, err = db.Exec(ctx, foreign, "tenant", "foreign-challenge", foreignIssue, bytes.Repeat([]byte{90}, 32))
	var invalid *pgconn.PgError
	if !errors.As(err, &invalid) || invalid.Code != "23514" || invalid.ConstraintName != "challenges_purpose_v2" {
		t.Fatal("foreign purpose was not denied by the exact new constraint")
	}
	// A missing expected predecessor cannot silently remove another constraint.
	if _, err := db.Exec(ctx, forward[0].UpSQL()); err == nil {
		t.Fatal("mismatched predecessor was silently ignored")
	}
}
