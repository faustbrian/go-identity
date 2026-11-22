//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func testProviderRefreshVersionedVault(t *testing.T, ctx context.Context, db *pgx.Conn, original rpPreparedTokenSet, origin []byte) {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	b := original.Binding
	load := func(user identity.UserID) (rpPreparedTokenSet, error) {
		row := tx.QueryRow(ctx, providerRefreshVaultReadSQL("oauth_rp"), string(b.TenantID), string(user), string(b.AccountID))
		return scanProviderRefreshVault(row, b.TenantID, user, b.AccountID)
	}
	if found, err := load(b.UserID); err != nil || !reflect.DeepEqual(found, original) {
		t.Fatalf("existing vault could not be reconstructed exactly: %v", err)
	}
	if _, err := load("another-owner"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unrelated owner matched: %v", err)
	}
	write := func(predecessor, successor rpPreparedTokenSet) error {
		return compareAndSetProviderRefreshVault(ctx, func(ctx context.Context, sql string, args ...any) (int64, error) {
			result, err := tx.Exec(ctx, sql, args...)
			return result.RowsAffected(), err
		}, "oauth_rp", predecessor, successor)
	}
	// The fixture uses opaque, distinct bytes here to isolate SQL custody;
	// the envelope and complete service tests prove cryptographic validity.
	successor := original
	successor.Schema, successor.Version, successor.SocialConnectionVersion = 2, 2, 2
	successor.Binding.SocialLinkVersion++
	successor.Ciphertext = []byte{8, 7, 6}
	invalid := successor
	invalid.Binding.UserID = "another-owner"
	var invalidInput identity.InvalidInputError
	if err := write(original, invalid); !errors.As(err, &invalidInput) {
		t.Fatalf("foreign successor accepted: %v", err)
	}
	changed := original
	changed.Ciphertext = []byte{4, 5, 6}
	var conflict identity.ConflictError
	if err := write(changed, successor); !errors.As(err, &conflict) {
		t.Fatalf("incorrect predecessor ciphertext did not conflict: %v", err)
	}
	if err := write(original, successor); err != nil {
		t.Fatal("exact token custody rotation failed", err)
	}
	if err := write(original, successor); !errors.As(err, &conflict) {
		t.Fatalf("stale predecessor survived advancement: %v", err)
	}
	if found, err := load(b.UserID); err != nil || !reflect.DeepEqual(found, successor) {
		t.Fatalf("successor changed during roundtrip: %v", err)
	}
	var operation string
	var command []byte
	if err := tx.QueryRow(ctx, `SELECT origin_operation,origin_command_id FROM oauth_rp.token_sets WHERE tenant_id=$1 AND account_id=$2`, string(b.TenantID), string(b.AccountID)).Scan(&operation, &command); err != nil || operation != "identity.account.link-token" || !bytes.Equal(command, origin) {
		t.Fatal("refresh rewrote original link custody", err)
	}
}

func testProviderRefreshRejectedStorage(t *testing.T, ctx context.Context, db *pgx.Conn) {
	t.Helper()
	history, err := (ProviderRefreshReceiptMigrationSource{Schema: "oauth_rp", Version: 104}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("missing receipt migration", err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("receipt migration over populated vault", err)
	}
	raw := bytes.Repeat([]byte{65}, 16)
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
VALUES($1,'tenant-a','identity.account.refresh-token',$2,1,$3)`, raw, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal("refresh claim", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose)
VALUES($1,'tenant-a','identity.account.refresh-token')`, raw); err != nil {
		t.Fatal("refresh journal", err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const tenant, user, account, schema = "tenant-a", "user-a", "account-1", "oauth_rp"
	read := func() (rpPreparedTokenSet, error) {
		row := tx.QueryRow(ctx, providerRefreshVaultReadSQL(schema), tenant, user, account)
		return scanProviderRefreshVault(row, tenant, user, account)
	}
	exec := func(ctx context.Context, sql string, args ...any) (int64, error) {
		tag, err := tx.Exec(ctx, sql, args...)
		return tag.RowsAffected(), err
	}
	original, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if err := retireRejectedProviderRefreshVault(ctx, exec, schema, original, original.Binding.SocialLinkVersion+1); err != nil {
		t.Fatal("retire exact sealed predecessor", err)
	}
	next, err := read()
	if err != nil || bytes.Equal(next.Ciphertext, original.Ciphertext) || len(next.Ciphertext) != 1 ||
		!next.AccessExpiresAt.IsZero() || next.Version != 2 || next.Binding.SocialLinkVersion != 2 {
		t.Fatal("retirement retained grant, invented expiry, or lost version fence", err)
	}
	statement := func(sql string) string { return strings.ReplaceAll(sql, "@schema@", rpQuotedSchema(schema)) }
	if _, err := tx.Exec(ctx, statement(providerRefreshReceiptInsert), tenant, user, account, raw, uint64(1), uint64(2), true, nil, nil); err != nil {
		t.Fatal("safe receipt insert", err)
	}
	id := identity.CommandID(base64.RawURLEncoding.EncodeToString(raw))
	receipt, err := scanProviderRefreshReceipt(tx.QueryRow(ctx, statement(providerRefreshReceiptRead), tenant, user, account, raw), id)
	if err != nil || receipt.CommandID != id || !receipt.Rejected || !receipt.AccessExpiresAt.IsZero() ||
		receipt.BeforeVersion != 1 || receipt.AfterVersion != 2 {
		t.Fatal("original rejected receipt changed", err)
	}
	if _, err := scanProviderRefreshReceipt(tx.QueryRow(ctx, statement(providerRefreshReceiptRead), tenant, "other-user", account, raw), id); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("receipt matched a different owner", err)
	}
	change := identity.AccountUnlinkChange{TenantID: tenant, UserID: user, AccountID: account, ExpectedAccountVersion: 1, ExpectedSocialLinkVersion: 2}
	if err := eraseUnlinkProviderTokens(ctx, exec, schema, change); err != nil {
		t.Fatal("retired vault row prevented unlink", err)
	}
	if _, err := read(); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("unlink retained a vault row", err)
	}
}
