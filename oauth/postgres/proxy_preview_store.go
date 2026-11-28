package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type proxyPreviewRow struct {
	locator        proxyPreviewBindingLocator
	binding, proof []byte
	observed       time.Time
}

func (proxyPreviewRow) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth postgres proxy preview custody (redacted)"))
}

func (row *proxyPreviewRow) clear() {
	clear(row.binding)
	clear(row.proof)
	*row = proxyPreviewRow{}
}

func readProxyPreviewSQL(schema string) string {
	// Guard sizes in SQL before pgx allocates result buffers, even if storage
	// constraints have been weakened. The native owner still authenticates AAD.
	return `SELECT
CASE WHEN octet_length(origin_command_id)=16 THEN origin_command_id END,
CASE WHEN octet_length(callback_command_id)=16 THEN callback_command_id END,
issued_at,expires_at,
CASE WHEN octet_length(binding_ciphertext) BETWEEN 1 AND 65536 THEN binding_ciphertext END,
CASE WHEN version=1 AND settled_at IS NULL AND octet_length(proof_ciphertext) BETWEEN 1 AND 65536 THEN proof_ciphertext END,
statement_timestamp()
FROM ` + rpQuotedSchema(schema) + `.proxy_preview_bindings
WHERE tenant_id=$1 AND flow_id=$2`
}

func insertProxyPreviewSQL(schema string) string {
	return proxyPreviewInsertSQL(schema, false)
}

func proxyPreviewInsertSQL(schema string, fenced bool) string {
	var columns, values string
	if fenced {
		columns, values = ",fence_provider_id,fence_provider_epoch", ",$9,$10::numeric"
	}
	return `INSERT INTO ` + rpQuotedSchema(schema) + `.proxy_preview_bindings
(tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,binding_ciphertext,proof_ciphertext,version` + columns + `)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,1` + values + `)`
}

func recoverProxyPreviewBindingSQL(schema string) string {
	return `SELECT flow_id FROM ` + rpQuotedSchema(schema) + `.proxy_preview_bindings
WHERE tenant_id=$1 AND flow_id=$2 AND origin_command_id=$3`
}

// The original locator and both opaque values come from authenticated native
// custody, never from the delivered profile envelope. There is one PK probe.
const proxyPreviewOriginalPredicate = `tenant_id=$1 AND flow_id=$2 AND origin_command_id=$3 AND callback_command_id=$4
AND issued_at=$5 AND expires_at=$6 AND binding_ciphertext=$7
AND issued_at<=statement_timestamp() AND expires_at>statement_timestamp()`

func requireProxyPreviewSQL(schema string, settled bool) string {
	stage := `version=1 AND proof_ciphertext=$8 AND settled_at IS NULL`
	if settled {
		stage = `version=2 AND proof_ciphertext IS NULL AND settled_at>=issued_at AND settled_at<=statement_timestamp()`
	}
	return `SELECT version::text FROM ` + rpQuotedSchema(schema) + `.proxy_preview_bindings
WHERE ` + proxyPreviewOriginalPredicate + ` AND ` + stage + ` FOR UPDATE`
}

func settleProxyPreviewSQL(schema string) string {
	return `UPDATE ` + rpQuotedSchema(schema) + `.proxy_preview_bindings
SET version=2,proof_ciphertext=NULL,settled_at=statement_timestamp()
WHERE ` + proxyPreviewOriginalPredicate + ` AND version=1 AND proof_ciphertext=$8 AND settled_at IS NULL`
}

func readProxyPreviewRow(ctx context.Context, db proxyLookupQueryer, schema string, tenant identity.TenantID, flow identity.PreAuthTransactionID) (row proxyPreviewRow, err error) {
	_, flowErr := identity.ParsePreAuthTransactionID(string(flow))
	if ctx == nil || db == nil || !rpSchemaName(schema) || !rpDirectoryID(string(tenant)) || flowErr != nil {
		return row, identity.InvalidInputError{Field: "oauth_proxy_preview_custody"}
	}
	if err := ctx.Err(); err != nil {
		return row, err
	}
	defer func() {
		if err != nil {
			row.clear()
		}
	}()
	work, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	rows, err := db.Query(work, readProxyPreviewSQL(schema), string(tenant), string(flow))
	if err != nil {
		return row, proxyPreviewStoreFailure(work)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return row, proxyPreviewStoreFailure(work)
		}
		return row, identity.ForbiddenError{}
	}
	var origin, callback []byte
	if rows.Scan(&origin, &callback, &row.locator.IssuedAt, &row.locator.ExpiresAt, &row.binding, &row.proof, &row.observed) != nil || rows.Next() || rows.Err() != nil {
		return row, proxyPreviewStoreFailure(work)
	}
	if work.Err() != nil {
		return row, work.Err()
	}
	row.locator.Tenant, row.locator.Flow = tenant, flow
	row.locator.OriginCommand = identity.CommandID(base64.RawURLEncoding.EncodeToString(origin))
	row.locator.CallbackCommand = identity.CommandID(base64.RawURLEncoding.EncodeToString(callback))
	row.locator.IssuedAt, row.locator.ExpiresAt = row.locator.IssuedAt.UTC(), row.locator.ExpiresAt.UTC()
	row.observed = row.observed.UTC()
	if !validProxyPreviewRow(row) || !proxyBindingSQLTime(row.observed) || row.observed.Before(row.locator.IssuedAt) || !row.observed.Before(row.locator.ExpiresAt) {
		return row, identity.ForbiddenError{}
	}
	return row, nil
}

func insertProxyPreviewRow(ctx context.Context, w kernel.Work, schema string, row proxyPreviewRow, fenced bool, provider string, epoch uint64) error {
	if ctx == nil || !rpSchemaName(schema) || !validProxyPreviewRow(row) {
		return identity.InvalidInputError{Field: "oauth_proxy_preview_custody"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	args := proxyPreviewOriginalArgs(row)
	statement := insertProxyPreviewSQL(schema)
	if fenced {
		if !rpProviderID(provider) || epoch == 0 {
			return identity.ForbiddenError{}
		}
		args = append(args, provider, strconv.FormatUint(epoch, 10))
		statement = proxyPreviewInsertSQL(schema, true)
	}
	count, err := w.Exec(ctx, statement, args...)
	if err != nil {
		return err // Work owns bounded SQL execution and redacted error translation.
	}
	if count != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

func requireProxyPreviewRow(ctx context.Context, w kernel.Work, schema string, row proxyPreviewRow, settled bool) error {
	if ctx == nil || !rpSchemaName(schema) || !validProxyPreviewRow(row) {
		return identity.InvalidInputError{Field: "oauth_proxy_preview_custody"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	args := proxyPreviewOriginalArgs(row)
	if settled {
		args = args[:7]
	}
	rows, err := w.Query(ctx, requireProxyPreviewSQL(schema, settled), args...)
	if err != nil {
		return err
	}
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var version string
	if err := rows.Scan(&version); err != nil {
		rows.Close()
		return err
	}
	want := "1"
	if settled {
		want = "2"
	}
	if version != want || rows.Next() {
		rows.Close()
		return identity.ForbiddenError{}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// statement_timestamp predates a blocking row lock. Recheck the existing
	// Work clock after acquisition so waiting never renews original custody.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(row.locator.IssuedAt) || !now.Before(row.locator.ExpiresAt) || !row.observed.IsZero() && now.Before(row.observed) {
		return identity.ForbiddenError{}
	}
	return nil
}

func settleProxyPreviewRow(ctx context.Context, w kernel.Work, schema string, row proxyPreviewRow) error {
	if ctx == nil || !rpSchemaName(schema) || !validProxyPreviewRow(row) {
		return identity.InvalidInputError{Field: "oauth_proxy_preview_custody"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	count, err := w.Exec(ctx, settleProxyPreviewSQL(schema), proxyPreviewOriginalArgs(row)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func validProxyPreviewRow(row proxyPreviewRow) bool {
	l := row.locator
	_, flowErr := identity.ParsePreAuthTransactionID(string(l.Flow))
	_, originErr := identity.ParseCommandID(string(l.OriginCommand))
	_, callbackErr := identity.ParseCommandID(string(l.CallbackCommand))
	if !rpDirectoryID(string(l.Tenant)) || flowErr != nil || originErr != nil || callbackErr != nil || l.OriginCommand == l.CallbackCommand {
		return false
	}
	validIssuance := proxyBindingSQLTime(l.IssuedAt) && l.IssuedAt.Unix() > 0 && l.IssuedAt.Nanosecond() == 0
	validExpiry := proxyBindingSQLTime(l.ExpiresAt) && l.ExpiresAt.Nanosecond() == 0 && l.ExpiresAt.After(l.IssuedAt) && l.ExpiresAt.Sub(l.IssuedAt) <= 5*time.Minute
	boundedCiphertext := len(row.binding) > 0 && len(row.binding) <= proxyBindingMaximumWire && len(row.proof) > 0 && len(row.proof) <= proxyBindingMaximumWire
	return validIssuance && validExpiry && boundedCiphertext
}

func proxyPreviewOriginalArgs(row proxyPreviewRow) []any {
	l := row.locator
	origin, _ := base64.RawURLEncoding.DecodeString(string(l.OriginCommand))
	callback, _ := base64.RawURLEncoding.DecodeString(string(l.CallbackCommand))
	return []any{string(l.Tenant), string(l.Flow), origin, callback, l.IssuedAt, l.ExpiresAt, row.binding, row.proof}
}

func proxyPreviewStoreFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.UnavailableError{}
}
