package postgres

import (
	"context"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProviderRefreshReceiptMigrationSource installs only the safe native result
// projection. Install after the token-vault/nullable-expiry and identity
// command histories, before constructing the optional refresh service. No
// existing row is rewritten or enrolled.
type ProviderRefreshReceiptMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ProviderRefreshReceiptMigrationSource{}

func (s ProviderRefreshReceiptMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_refresh_receipt_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(providerRefreshReceiptSchema, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_provider_refresh_receipts", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

// No provider credentials, token metadata other than original access expiry,
// or independent workflow state. The actual commit remains in the identity
// journal; this projection never grants execution or current read authority.
const providerRefreshReceiptSchema = `CREATE TABLE @schema@.provider_refresh_receipts(
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 account_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 operation_id text COLLATE "C" GENERATED ALWAYS AS ('identity.account.refresh-token'::text) STORED,
 previous_version identity.version NOT NULL,
 result_version identity.version NOT NULL CHECK(result_version=previous_version+1),
 rejected boolean NOT NULL,
 expires_seconds bigint CHECK(expires_seconds BETWEEN 1 AND 253402300799),
 expires_nanoseconds integer CHECK(expires_nanoseconds BETWEEN 0 AND 999999999),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(tenant_id,operation_id,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(rejected AND expires_seconds IS NULL AND expires_nanoseconds IS NULL
    OR NOT rejected AND expires_seconds IS NOT NULL AND expires_nanoseconds IS NOT NULL)
);`

const providerRefreshReceiptInsert = `INSERT INTO @schema@.provider_refresh_receipts
 (tenant_id,user_id,account_id,command_id,previous_version,result_version,rejected,expires_seconds,expires_nanoseconds)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`

const providerRefreshReceiptRead = `SELECT previous_version::text,result_version::text,rejected,expires_seconds,expires_nanoseconds
 FROM @schema@.provider_refresh_receipts WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND command_id=$4`

func providerRefreshReceiptKey(b identity.CommandBinding) ([]any, error) {
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if b.ValidateFor(providerRefreshOperation()) != nil || err != nil || len(id) != 16 {
		return nil, identity.ForbiddenError{}
	}
	return []any{string(b.TenantID), string(b.UserID), b.RecordID, id}, nil
}

func (p *providerRefreshPhase) persistReceipt(ctx context.Context, w kernel.Work, rejected bool, expires time.Time) error {
	args, err := providerRefreshReceiptKey(p.input.binding())
	if err != nil {
		return err
	}
	var sec, ns any
	if !rejected {
		if !rpUTCTime(expires) {
			return identity.InvalidInputError{Field: "oauth_refresh_receipt"}
		}
		sec, ns = expires.Unix(), expires.Nanosecond()
	}
	lifecycle := p.lifecycle()
	args = append(args, lifecycle.BeforeVersion, lifecycle.AfterVersion, rejected, sec, ns)
	statement := strings.ReplaceAll(providerRefreshReceiptInsert, "@schema@", rpQuotedSchema(p.service.link.config().Schema))
	n, err := w.Exec(ctx, statement, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *providerRefreshPhase) readReceipt(ctx context.Context) (ProviderRefreshResult, error) {
	b, lifecycle := p.input.binding(), p.lifecycle()
	args, err := providerRefreshReceiptKey(b)
	if err != nil {
		return ProviderRefreshResult{}, err
	}
	link := p.service.link
	statement := strings.ReplaceAll(providerRefreshReceiptRead, "@schema@", rpQuotedSchema(link.config().Schema))
	result, err := scanProviderRefreshReceipt(link.pool.Raw().QueryRow(ctx, statement, args...), b.CommandID)
	if err != nil || result.BeforeVersion != lifecycle.BeforeVersion || result.AfterVersion != lifecycle.AfterVersion {
		return ProviderRefreshResult{}, identity.UnavailableError{}
	}
	return result, nil
}

func scanProviderRefreshReceipt(row providerRefreshVaultRow, id identity.CommandID) (ProviderRefreshResult, error) {
	var before, after string
	var rejected bool
	var sec, ns *int64
	if err := row.Scan(&before, &after, &rejected, &sec, &ns); err != nil {
		return ProviderRefreshResult{}, err
	}
	previous, firstErr := strconv.ParseUint(before, 10, 64)
	next, secondErr := strconv.ParseUint(after, 10, 64)
	if firstErr != nil || secondErr != nil || previous == 0 || previous == math.MaxUint64 || next != previous+1 ||
		(sec == nil) != (ns == nil) || rejected != (sec == nil) {
		return ProviderRefreshResult{}, identity.UnavailableError{}
	}
	out := ProviderRefreshResult{CommandID: id, BeforeVersion: previous, AfterVersion: next, Rejected: rejected}
	if !rejected {
		if *sec < 1 || *sec > 253402300799 || *ns < 0 || *ns > 999999999 {
			return ProviderRefreshResult{}, identity.UnavailableError{}
		}
		out.AccessExpiresAt = time.Unix(*sec, *ns).UTC()
	}
	return out, nil
}

func (p *providerRefreshPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	args, err := providerRefreshReceiptKey(b)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	statement := strings.ReplaceAll(providerRefreshReceiptRead, "@schema@", rpQuotedSchema(p.service.link.config().Schema))
	rows, err := w.Query(ctx, statement, args...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	if _, err := scanProviderRefreshReceipt(rows, b.CommandID); err != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
