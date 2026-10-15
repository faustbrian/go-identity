// Package passwordpostgres owns durable password material and primary reads.
// Existing-password material replacement participates in the kernel transaction;
// complete password workflows, history and lifecycle remain in development.
package passwordpostgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgtype"
)

// Config fixes explicit read/write budgets and primitive-owned parsing policy.
// MaximumDuration is in (0,10s]. HashPolicy is the owning workflow's constructed
// primitive policy, not an adapter-selected password policy. Its verification
// limits admit supported legacy algorithms; the reader does not require hashes
// to use the current issuance profile. New material writes require the exact
// selected issuance algorithm and its parameters. Zero is invalid and copied.
type Config struct {
	MaximumDuration time.Duration
	HashPolicy      primitive.Policy
}

// Repository borrows a caller-owned primary-only pool, never closes it and owns
// no goroutines, process locks, cache or authority lease. Calls are concurrency-
// safe; zero denies. Close the pool only after in-flight calls finish. The fixed
// identity_password schema is installed after the kernel credential history.
type Repository struct {
	pool            *database.Pool
	maximumDuration time.Duration
	limits          primitive.Limits
	policy          primitive.Policy
}

// Format redacts pool configuration from direct diagnostics.
func (Repository) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.Repository(redacted)")
}

var _ password.CredentialVerificationRepository = (*Repository)(nil)

// NewRepository validates trusted composition without IO. The pool must target
// authoritative primary endpoints only; replica/cached reads are unsupported.
// Migration installation and pool lifetime remain explicit caller composition.
func NewRepository(pool *database.Pool, config Config) (*Repository, error) {
	if pool == nil || pool.Raw() == nil || config.MaximumDuration <= 0 || config.MaximumDuration > 10*time.Second || config.HashPolicy.Algorithm() == "" {
		return nil, password.ErrPasswordWork
	}
	return &Repository{pool: pool, maximumDuration: config.MaximumDuration, limits: config.HashPolicy.Limits(), policy: config.HashPolicy}, nil
}

// ReadPasswordCredential joins owned material and kernel reference/user state
// in one PostgreSQL statement snapshot. Tenant/account selection is exact and
// already canonicalized; this method performs no identifier lookup or authority
// decision. Blocked/disabled/expired projections are preserved for the core.
// Missing exact account/password is ErrCredentialAbsent. Corrupt, duplicate,
// inconsistent, unavailable or missing-schema data is redacted ErrPasswordWork,
// never a partial positive result or raw driver diagnostic. Context cancellation
// is preserved. Query result transfer bounds hash bytes before client allocation.
func (r *Repository) ReadPasswordCredential(ctx context.Context, key password.CredentialKey) (password.CredentialSnapshot, error) {
	if r == nil || ctx == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || r.maximumDuration > 10*time.Second || (identity.CredentialAuthorityQuery{TenantID: key.TenantID, UserID: key.SubjectID, CredentialID: "password"}).Validate() != nil {
		return password.CredentialSnapshot{}, password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return password.CredentialSnapshot{}, err
	}
	rows, err := r.pool.Raw().Query(bounded, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,
c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at,
p.version::text,p.algorithm,CASE WHEN octet_length(p.encoded_hash)<=$3 THEN p.encoded_hash ELSE '' END,
p.created_at,p.updated_at
FROM identity_password.credentials p
JOIN identity.users u ON u.tenant_id=p.tenant_id AND u.user_id=p.user_id
JOIN identity.credential_references c ON c.tenant_id=p.tenant_id AND c.user_id=p.user_id AND c.credential_id=p.credential_id
WHERE p.tenant_id=$1 AND p.user_id=$2 LIMIT 2`, string(key.TenantID), string(key.SubjectID), r.limits.EncodedHashBytes)
	if err != nil {
		return password.CredentialSnapshot{}, readerFailure(bounded)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return password.CredentialSnapshot{}, readerFailure(bounded)
		}
		if err := bounded.Err(); err != nil {
			return password.CredentialSnapshot{}, err
		}
		return password.CredentialSnapshot{}, password.ErrCredentialAbsent
	}
	var stored credentialRow
	if err := rows.Scan(&stored.tenant, &stored.user, &stored.status, &stored.userVersion, &stored.epoch, &stored.id, &stored.kind, &stored.owner, &stored.referenceVersion, &stored.enabled, &stored.expiry, &stored.materialVersion, &stored.algorithm, &stored.hash, &stored.created, &stored.updated); err != nil {
		return password.CredentialSnapshot{}, readerFailure(bounded)
	}
	if rows.Next() || rows.Err() != nil {
		return password.CredentialSnapshot{}, readerFailure(bounded)
	}
	if err := bounded.Err(); err != nil {
		return password.CredentialSnapshot{}, err
	}
	result, err := decodeCredential(key, stored, r.limits)
	if canceled := bounded.Err(); canceled != nil {
		return password.CredentialSnapshot{}, canceled
	}
	return result, err
}

func readerFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return password.ErrPasswordWork
}

type credentialRow struct {
	tenant, user, status, userVersion, epoch                      string
	id, owner, referenceVersion, materialVersion, algorithm, hash string
	kind                                                          int16
	enabled                                                       bool
	expiry                                                        pgtype.Timestamptz
	created, updated                                              time.Time
}

func decodeCredential(key password.CredentialKey, row credentialRow, limits primitive.Limits) (password.CredentialSnapshot, error) {
	version, ve := canonicalVersion(row.userVersion)
	epoch, ee := canonicalVersion(row.epoch)
	reference, re := canonicalVersion(row.referenceVersion)
	material, me := canonicalVersion(row.materialVersion)
	if ve != nil || ee != nil || re != nil || me != nil || reference != material || row.tenant != string(key.TenantID) || row.user != string(key.SubjectID) || row.kind != int16(identity.CredentialPassword) || row.owner != "identity/password" || !storedTime(row.created) || !storedTime(row.updated) || row.updated.Before(row.created) {
		return password.CredentialSnapshot{}, password.ErrPasswordWork
	}
	hash, err := primitive.ParseEncodedHash(row.hash, limits)
	if err != nil || string(hash.Algorithm()) != row.algorithm {
		return password.CredentialSnapshot{}, password.ErrPasswordWork
	}
	var expiry time.Time
	if row.expiry.Valid {
		if row.expiry.InfinityModifier != pgtype.Finite || !storedTime(row.expiry.Time) {
			return password.CredentialSnapshot{}, password.ErrPasswordWork
		}
		expiry = row.expiry.Time.UTC()
	}
	return password.NewCredentialSnapshot(identity.CredentialAuthorityRecord{
		User:             identity.User{ID: identity.UserID(row.user), TenantID: identity.TenantID(row.tenant), Status: identity.Status(row.status), Version: version},
		AuthorityVersion: epoch, Credential: identity.CredentialRef{ID: identity.CredentialID(row.id), TenantID: key.TenantID, UserID: key.SubjectID, Kind: identity.CredentialPassword, Owner: row.owner, Version: reference}, Enabled: row.enabled, ExpiresAt: expiry,
	}, hash)
}

func canonicalVersion(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
		return 0, errors.New("invalid version")
	}
	return value, nil
}

func storedTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999 && t.Nanosecond()%1000 == 0
}
