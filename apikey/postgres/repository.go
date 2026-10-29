package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

func (s *Service) currentRecord(ctx context.Context, tenant identity.TenantID, id apikey.KeyID) (apikey.Record, error) {
	var wire []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, string(tenant), s.config().Configuration.Spec().ID, string(id)).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return apikey.Record{}, apikey.ErrDenied
	}
	if err != nil {
		return apikey.Record{}, nativeError(ctx, err)
	}
	record, err := decodeRecord(wire, s.config().Configuration)
	if err != nil || record.ID != id || record.Owner.Spec().TenantID != tenant {
		return apikey.Record{}, identity.UnavailableError{}
	}
	return record, nil
}

func (p *creationPhase) tombstone() apikey.Record {
	if p.revocation {
		return p.input.Record
	}
	r := *p.input.PreviousRecord
	r.Owner = p.input.Record.Owner
	r.Version++
	r.AuthorityVersion++
	r.RootVersion++
	r.Status, r.Grant = apikey.KeyRevoked, []string{}
	return r
}

// Configuration UPDATE precedes the exact key UPDATE on every native mutation.
// Comparing canonical records retains all original CAS, lineage and grant
// dimensions; a contender cannot rotate/revoke an already changed credential.
func (p *creationPhase) requirePrevious(ctx context.Context, w kernel.Work) error {
	if p.input.PreviousRecord == nil {
		return nil
	}
	expected := *p.input.PreviousRecord
	if p.applied {
		expected = p.tombstone()
	}
	configuration := p.input.Configuration
	if p.input.PreviousConfiguration != nil {
		configuration = *p.input.PreviousConfiguration
	}
	want, err := encodeRecord(expected, configuration)
	if err != nil {
		return err
	}
	query := `SELECT user_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3 FOR UPDATE`
	organizationOwned := expected.Owner.Spec().Kind == apikey.OwnerOrganization
	if organizationOwned {
		query = `SELECT coalesce(user_id::text,''),organization_id::text,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3 FOR UPDATE`
	}
	rows, err := w.Query(ctx, query, string(p.input.Binding.TenantID), configuration.Spec().ID, string(expected.ID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ConflictError{}
	}
	var user, organizationID string
	var wire []byte
	if organizationOwned {
		err = rows.Scan(&user, &organizationID, &wire)
	} else {
		err = rows.Scan(&user, &wire)
	}
	if err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if user != string(expected.Owner.Spec().UserID) || organizationOwned && organizationID != string(expected.Owner.Spec().OrganizationID) || !bytes.Equal(want, wire) {
		return identity.ConflictError{}
	}
	return nil
}

func configurationDigest(configuration apikey.Configuration) ([32]byte, error) {
	if configuration.Validate() != nil {
		return [32]byte{}, apikey.ErrInvalid
	}
	wire, err := json.Marshal(configuration.Spec())
	if err != nil {
		return [32]byte{}, apikey.ErrInvalid
	}
	return sha256.Sum256(wire), nil
}

// CheckConfiguration performs a bounded primary read of the exact configured
// tenant/profile. It rejects absent, different or disabled authority without
// inserting, resetting lifecycle state or issuing a reusable validity proof.
// This is trusted deployment observation, not caller authentication. Runtime
// operations still perform their own current-authority reads and final fences.
func (s *Service) CheckConfiguration(ctx context.Context, tenant identity.TenantID) error {
	if s == nil || s.config == nil || ctx == nil || !scope(string(tenant)) {
		return apikey.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	_, err := s.configurationAuthority(bounded, tenant)
	return err
}

// InitializeConfiguration is explicit trusted deployment bootstrap, not an
// authenticated request or upsert. It creates only a previously absent exact
// tenant/configuration at epoch one. Existing state conflicts, never resets or
// enables a disabled configuration. The caller must authorize provisioning;
// Create and verification never call it. Cancellation may leave its single
// INSERT committed; query the exact configuration rather than resetting it.
func (s *Service) InitializeConfiguration(ctx context.Context, tenant identity.TenantID) error {
	if s == nil || s.config == nil || ctx == nil || !scope(string(tenant)) {
		return apikey.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	digest, err := configurationDigest(s.config().Configuration)
	if err != nil {
		return err
	}
	n, err := s.pool.Raw().Exec(ctx, `INSERT INTO identity_api_keys.configurations(tenant_id,configuration_id,configuration_digest,authority_version,enabled) VALUES($1,$2,$3,1,$4) ON CONFLICT DO NOTHING`, string(tenant), s.config().Configuration.Spec().ID, digest[:], s.config().Configuration.AllowsVerification())
	if err != nil {
		return nativeError(ctx, err)
	}
	if n.RowsAffected() != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (s *Service) configurationAuthority(ctx context.Context, tenant identity.TenantID) (apikey.ConfigurationAuthorityBinding, error) {
	var version string
	var digest []byte
	var enabled bool
	err := s.pool.Raw().QueryRow(ctx, `SELECT authority_version::text,configuration_digest,enabled FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2`, string(tenant), s.config().Configuration.Spec().ID).Scan(&version, &digest, &enabled)
	if err != nil {
		return apikey.ConfigurationAuthorityBinding{}, nativeError(ctx, err)
	}
	want, _ := configurationDigest(s.config().Configuration)
	n, err := positive(version)
	if err != nil || !enabled || !bytes.Equal(digest, want[:]) {
		return apikey.ConfigurationAuthorityBinding{}, apikey.ErrDenied
	}
	return apikey.ConfigurationAuthorityBinding{TenantID: tenant, ConfigurationID: s.config().Configuration.Spec().ID, Version: n}, nil
}

func (s *Service) originalRecord(ctx context.Context, b identity.CommandBinding) (apikey.Record, error) {
	var binding, wire []byte
	if err := s.pool.Raw().QueryRow(ctx, `SELECT binding,record FROM identity_api_keys.command_effects WHERE tenant_id=$1 AND command_id=$2 AND key_id=$3`, string(b.TenantID), string(b.CommandID), b.RecordID).Scan(&binding, &wire); err != nil {
		return apikey.Record{}, nativeError(ctx, err)
	}
	want, _ := json.Marshal(storedBinding(b))
	if !bytes.Equal(binding, want) {
		return apikey.Record{}, identity.UnavailableError{}
	}
	record, err := decodeRecord(wire, s.config().Configuration)
	if err != nil || record.ID != apikey.KeyID(b.RecordID) || record.Owner.Spec().TenantID != b.TenantID || !s.managementOwnerMatches(record, b) {
		return apikey.Record{}, identity.UnavailableError{}
	}
	return record, nil
}

func positive(wire string) (uint64, error) {
	n, err := strconv.ParseUint(wire, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != wire {
		return 0, identity.UnavailableError{}
	}
	return n, nil
}

// MigrationSource installs this owner's forward-only schema in the composition's
// existing migration history after identity/authorization. Version is permanently
// allocated by that composition; preexisting unmanaged objects deliberately fail.
// No credential plaintext or recoverable encrypted key column exists.
type MigrationSource struct{ Version migrations.Version }

func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, apikey.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_api_keys_human_modern", migrations.TransactionModeDefault, schemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const schemaSQL = `CREATE SCHEMA identity_api_keys;
CREATE TABLE identity_api_keys.configurations(
 tenant_id identity.directory_id NOT NULL,
 configuration_id identity.directory_id NOT NULL,
 configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32),
 authority_version identity.version NOT NULL,
 enabled boolean NOT NULL,
 PRIMARY KEY(tenant_id,configuration_id)
);
CREATE TABLE identity_api_keys.keys(
 tenant_id identity.directory_id NOT NULL,
 configuration_id identity.directory_id NOT NULL,
 key_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 pepper_version bigint NOT NULL CHECK(pepper_version BETWEEN 1 AND 4294967295),
 lookup_digest bytea NOT NULL CHECK(octet_length(lookup_digest)=32),
 record bytea NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 65536),
 PRIMARY KEY(tenant_id,configuration_id,key_id),
 UNIQUE(tenant_id,configuration_id,pepper_version,lookup_digest),
 FOREIGN KEY(tenant_id,configuration_id) REFERENCES identity_api_keys.configurations(tenant_id,configuration_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE TABLE identity_api_keys.command_effects(
 command_id text COLLATE "C" PRIMARY KEY CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 key_id identity.directory_id NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 4096),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 generation identity.version NOT NULL,
 record bytea NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 393216)
);`
