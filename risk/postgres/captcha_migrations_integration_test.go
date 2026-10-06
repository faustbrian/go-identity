//go:build integration

package postgres

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/jackc/pgx/v5"
)

// This independently exercises the actual owned SQL constraints, not the
// unfinished native executor. It certifies no provider or evidence signature.
func TestCaptchaMigrationSQL(t *testing.T) {
	dsn := os.Getenv("IDENTITY_RISK_POSTGRES_TEST_DSN")
	c, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || c.Host != "127.0.0.1" || c.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup", err)
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "captcha_schema_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup", err)
		}
	}()
	c.Database = name
	db, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := db.Close(cleanup); err != nil {
			t.Error("connection cleanup", err)
		}
	}()
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base, err := (MigrationSource{Schema: "risk_store", Version: 20}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range append(kernel, base...) {
		if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("existing namespace install", err)
		}
	}
	// Existing command custody is populated before the optional upgrade.
	command := bytes.Repeat([]byte{1}, 16)
	digest := bytes.Repeat([]byte{2}, 32)
	seed := func(tenant string, command []byte) {
		t.Helper()
		if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.risk.captcha-issue',$3,1,$4)`, command, tenant, digest, []byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.risk.captcha-issue')`, command, tenant); err != nil {
			t.Fatal(err)
		}
	}
	seed("tenant", command)
	var before, after string
	if err := db.QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, command).Scan(&before); err != nil {
		t.Fatal(err)
	}
	history, err := (CaptchaMigrationSource{Schema: "risk_store", Version: 40}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("CAPTCHA install", err)
	}
	if err := db.QueryRow(ctx, `SELECT row_to_json(c)::text FROM identity.commands c WHERE command_id=$1`, command).Scan(&after); err != nil || before != after {
		t.Fatal("populated command custody changed", err)
	}
	winner := func(tenant string, command []byte) {
		t.Helper()
		if _, err := db.Exec(ctx, `INSERT INTO risk_store.captcha_replay_winners(tenant_id,command_id,command_purpose,command_fingerprint,generation,binding_digest,intent_digest,configuration_digest,provider,site,api_profile,configuration_version,reserved_at) VALUES($1,$2,'identity.risk.captcha-issue',$3,1,$3,$3,$3,'turnstile','fixture-@schema@-site','siteverify/v0','fixture-v1',clock_timestamp())`, tenant, command, digest); err != nil {
			t.Fatal(err)
		}
	}
	winner("tenant", command)
	alias := `INSERT INTO risk_store.captcha_replay_aliases VALUES($1,'turnstile','fixture-@schema@-site','siteverify/v0','fixture-v1',$2,$3)`
	fingerprint := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := db.Exec(ctx, alias, "tenant", fingerprint, command); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{3}, 16)
	seed("tenant", other)
	winner("tenant", other)
	if _, err := db.Exec(ctx, alias, "tenant", fingerprint, other); err == nil {
		t.Fatal("different command acquired same replay alias")
	}
	// The same digest may legitimately name multiple retained key versions,
	// but all versions remain foreign-key-linked to the sole immutable alias.
	for _, version := range []int64{1, 2} {
		if _, err := db.Exec(ctx, `INSERT INTO risk_store.captcha_replay_alias_versions VALUES('tenant','turnstile','fixture-@schema@-site','siteverify/v0','fixture-v1',$1,$2)`, fingerprint, version); err != nil {
			t.Fatal("retained version conservation", err)
		}
	}
	foreign := bytes.Repeat([]byte{4}, 16)
	seed("other-tenant", foreign)
	winner("other-tenant", foreign)
	if _, err := db.Exec(ctx, alias, "other-tenant", fingerprint, foreign); err != nil {
		t.Fatal("tenant-isolated replay scope collided", err)
	}
	missingKeys, err := (CaptchaScopeMigrationSource{Schema: "risk_store", Version: 41}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, missingKeys[0].UpSQL()); err == nil {
		t.Fatal("populated upgrade inferred absent key custody")
	}
	var partial *string
	if err := db.QueryRow(ctx, `SELECT to_regclass('risk_store.captcha_replay_scopes')::text`).Scan(&partial); err != nil || partial != nil {
		t.Fatal("failed upgrade left partial scope authority", err)
	}
	key1, err := risk.NewCaptchaReplayKey(1, bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key2, err := risk.NewCaptchaReplayKey(2, bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, _, profile := captchaConfiguredKeyFixture(t, captchaFlowFixture(), time.Now().UTC(), []risk.CaptchaReplayKey{key2, key1}, "fixture-@schema@-site")
	custody, err := risk.NewCaptchaEvidenceCustody(profile)
	if err != nil {
		t.Fatal(err)
	}
	scopeHistory, err := (CaptchaScopeMigrationSource{Schema: "risk_store", Version: 41, Custody: []risk.CaptchaEvidenceCustody{custody}}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, scopeHistory[0].UpSQL()); err != nil {
		t.Fatal("populated scope upgrade", err)
	}
	var scopes, keys, retained int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_store.captcha_replay_scopes),(SELECT count(*) FROM risk_store.captcha_replay_scope_keys),(SELECT count(*) FROM risk_store.captcha_replay_alias_versions)`).Scan(&scopes, &keys, &retained); err != nil || scopes != 2 || keys != 2 || retained != 2 {
		t.Fatalf("scope upgrade lost existing custody %d/%d/%d: %v", scopes, keys, retained, err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM risk_store.captcha_replay_scope_keys WHERE key_version=1`); err == nil {
		t.Fatal("referenced replay key retired")
	}
	if _, err := db.Exec(ctx, alias, "tenant", fingerprint, other); err == nil {
		t.Fatal("scope upgrade released existing winner")
	}
	// Valid synthetic storage projection; no production bearer is fabricated.
	insertEvidence := `INSERT INTO risk_store.captcha_issued_evidence(tenant_id,command_id,command_purpose,user_id,anonymous_flow_id,binding_digest,intent_digest,proof_digest,evidence_digest,key_version,hostname,issued_at,expires_at,state,response_envelope) VALUES('tenant',$1,'identity.risk.captcha-issue',$2,$3,$4,$4,$4,$4,1,'example.com',clock_timestamp(),clock_timestamp()+interval '1 minute','issued',$5)`
	if _, err := db.Exec(ctx, insertEvidence, command, "user", "flow", digest, bytes.Repeat([]byte{5}, 100)); err == nil {
		t.Fatal("dual target namespace admitted")
	}
	if _, err := db.Exec(ctx, insertEvidence, command, "", "flow", digest, bytes.Repeat([]byte{5}, 100)); err != nil {
		t.Fatal("anonymous evidence storage", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM risk_store.captcha_issued_evidence WHERE tenant_id='tenant' AND command_id=$1`, command); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, alias, "tenant", fingerprint, other); err == nil {
		t.Fatal("evidence removal released replay winner")
	}
	if _, err := db.Exec(ctx, `DELETE FROM risk_store.captcha_replay_winners WHERE tenant_id='tenant' AND command_id=$1`, command); err == nil {
		t.Fatal("referenced winner deletion discarded tombstones")
	}
	var versions int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM risk_store.captcha_replay_alias_versions WHERE tenant_id='tenant'`).Scan(&versions); err != nil || versions != 2 {
		t.Fatal("key retirement references lost", err)
	}
}
