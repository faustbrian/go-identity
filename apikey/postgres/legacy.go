package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

var _ apikey.LegacyImporter = (*Service)(nil)

func importOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.import", SchemaID: "apikey-import-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, VersionPolicy: identity.FeatureVersionSnapshotImport}
}

type legacyImportBinding struct {
	SourceID      string
	SourceVersion uint64
	Digest        [32]byte
}

func (s *Service) withConfiguration(c apikey.Configuration) *Service {
	out, config := *s, s.config()
	config.Configuration = c
	out.config = func() ServiceConfig { return config }
	return &out
}

func (s *Service) selectedConfiguration(id string, revision uint64) (apikey.Configuration, error) {
	for _, c := range []apikey.Configuration{s.issuanceConfiguration, s.config().LegacyConfiguration} {
		if c.Validate() == nil && c.Spec().ID == id && (revision == 0 || c.Spec().Revision == revision) {
			return c, nil
		}
	}
	return apikey.Configuration{}, apikey.ErrInvalid
}

// Import accepts only authenticated, authorized immutable source snapshots.
// A matching original client key recovers its exact command first, even after
// another explicit command imported the same source. With an unused client key,
// an already committed identical source is status-only recovery of that source's
// original command; no new mapping, command, counters or effects are created.
// Different-key contenders may conflict. Changed snapshots require an explicit
// supported workflow, never an import upsert or tombstone resurrection.
func (s *Service) Import(ctx context.Context, r apikey.ImportRequest) (identity.CommandResult, error) {
	if s == nil || s.config == nil || ctx == nil || s.config().LegacyConfiguration.Validate() != nil {
		return identity.CommandResult{}, apikey.ErrInvalid
	}
	selected := s.withConfiguration(s.config().LegacyConfiguration)
	if r.Validate(selected.config().Configuration) != nil {
		return identity.CommandResult{}, apikey.ErrInvalid
	}
	r.Record.Grant = slices.Clone(r.Record.Grant)
	request := apikey.CreateRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, Name: r.Record.Name, Permissions: slices.Clone(r.Record.Grant), ExpiresAt: r.Record.ExpiresAt, CorrelationID: r.CorrelationID, Network: r.Network}
	out, err := selected.manage(ctx, request, nil, false, &r)
	return out.receipt, err
}

// InitializeLegacyConfiguration explicitly provisions the selected legacy
// tenant profile, with the same absent-only rules as modern configuration.
// Neither import nor verification calls provisioning or enables a disabled row.
func (s *Service) InitializeLegacyConfiguration(ctx context.Context, tenant identity.TenantID) error {
	if s == nil || s.config == nil || s.config().LegacyConfiguration.Validate() != nil {
		return apikey.ErrInvalid
	}
	return s.withConfiguration(s.config().LegacyConfiguration).InitializeConfiguration(ctx, tenant)
}

// CheckLegacyConfiguration observes the exact selected legacy profile without
// provisioning or repairing it. Missing, disabled or different authority denies.
func (s *Service) CheckLegacyConfiguration(ctx context.Context, tenant identity.TenantID) error {
	if s == nil || s.config == nil || s.config().LegacyConfiguration.Validate() != nil {
		return apikey.ErrInvalid
	}
	return s.withConfiguration(s.config().LegacyConfiguration).CheckConfiguration(ctx, tenant)
}

func (s *Service) managementRecord(ctx context.Context, tenant identity.TenantID, id apikey.KeyID) (apikey.Record, apikey.Configuration, error) {
	ids := []string{s.issuanceConfiguration.Spec().ID}
	if s.config().LegacyConfiguration.Validate() == nil {
		ids = append(ids, s.config().LegacyConfiguration.Spec().ID)
	}
	rows, err := s.pool.Raw().Query(ctx, `SELECT configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2 AND configuration_id=ANY($3::text[]) LIMIT 3`, string(tenant), string(id), ids)
	if err != nil {
		return apikey.Record{}, apikey.Configuration{}, nativeError(ctx, err)
	}
	defer rows.Close()
	var configurationID string
	var wire []byte
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return apikey.Record{}, apikey.Configuration{}, nativeError(ctx, err)
		}
		return apikey.Record{}, apikey.Configuration{}, apikey.ErrDenied
	}
	if err := rows.Scan(&configurationID, &wire); err != nil {
		return apikey.Record{}, apikey.Configuration{}, nativeError(ctx, err)
	}
	if rows.Next() {
		return apikey.Record{}, apikey.Configuration{}, apikey.ErrDenied
	}
	if err := rows.Err(); err != nil {
		return apikey.Record{}, apikey.Configuration{}, nativeError(ctx, err)
	}
	configuration, err := s.selectedConfiguration(configurationID, 0)
	if err != nil {
		return apikey.Record{}, apikey.Configuration{}, apikey.ErrDenied
	}
	record, err := decodeRecord(wire, configuration)
	if err != nil || record.ID != id || record.Owner.Spec().TenantID != tenant {
		return apikey.Record{}, apikey.Configuration{}, identity.UnavailableError{}
	}
	return record, configuration, nil
}

func importFingerprint(r apikey.ImportRequest, c apikey.Configuration) ([32]byte, error) {
	record, err := encodeRecord(r.Record, c)
	if err != nil {
		return [32]byte{}, err
	}
	wire, err := json.Marshal(struct {
		Record []byte
		Source legacyImportBinding
	}{record, legacyImportBinding{r.SourceID, r.SourceVersion, r.Digest.Sum()}})
	if err != nil {
		return [32]byte{}, apikey.ErrInvalid
	}
	return sha256.Sum256(wire), nil
}

func (s *Service) importIntent(r apikey.ImportRequest) (identity.RequestIntent, error) {
	fingerprint, err := importFingerprint(r, s.config().Configuration)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	wire, err := json.Marshal(struct {
		Source        [32]byte
		Configuration apikey.ConfigurationSpec
		PolicyID      string
		PolicyVersion uint64
		Network       string
	}{fingerprint, s.config().Configuration.Spec(), s.config().PolicyID, s.config().PolicyVersion, r.Network})
	if err != nil {
		return identity.RequestIntent{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "apikey.import.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

func (s *Service) importSource(ctx context.Context, r apikey.ImportRequest) (identity.CommandBinding, bool, error) {
	var source, version, command string
	var fingerprint, bound []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT s.source_id,s.source_version::text,s.source_fingerprint,s.command_id,e.binding FROM identity_api_keys.legacy_imports s JOIN identity_api_keys.command_effects e ON e.command_id=s.command_id WHERE s.tenant_id=$1 AND s.configuration_id=$2 AND s.key_id=$3`, string(r.Authentication.TenantID), r.Record.ConfigurationID, string(r.Record.ID)).Scan(&source, &version, &fingerprint, &command, &bound)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.CommandBinding{}, false, nil
	}
	if err != nil {
		return identity.CommandBinding{}, false, nativeError(ctx, err)
	}
	v, err := positive(version)
	if err != nil || len(fingerprint) != 32 {
		return identity.CommandBinding{}, false, identity.UnavailableError{}
	}
	if source != r.SourceID {
		return identity.CommandBinding{}, false, identity.ConflictError{}
	}
	if v > r.SourceVersion {
		return identity.CommandBinding{}, false, apikey.StaleImportError{}
	}
	want, err := importFingerprint(r, s.config().Configuration)
	if err != nil {
		return identity.CommandBinding{}, false, err
	}
	if v != r.SourceVersion || !bytes.Equal(fingerprint, want[:]) {
		return identity.CommandBinding{}, false, identity.ConflictError{}
	}
	var b storedBinding
	if len(bound) > 4096 || decodeCanonical(bound, &b) != nil || string(b.CommandID) != command || b.TenantID != r.Record.Owner.Spec().TenantID || b.UserID != r.Record.Owner.Spec().UserID || b.RecordID != string(r.Record.ID) || identity.CommandBinding(b).ValidateFor(importOperation()) != nil {
		return identity.CommandBinding{}, false, identity.UnavailableError{}
	}
	return identity.CommandBinding(b), true, nil
}

// LegacyMigrationSource is an additive source; Base retains all historical
// migration bytes. It refuses preexisting ambiguous tenant/key identities rather
// than choosing a configuration or rewriting records. Zero pepper_version is
// reserved for explicitly configured legacy SHA-256, never a modern fallback.
type LegacyMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

func (s LegacyMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, apikey.ErrInvalid
	}
	base, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		return nil, apikey.ErrInvalid
	}
	for _, m := range base {
		if m.Version() >= s.Version {
			return nil, apikey.ErrInvalid
		}
	}
	m, err := migrations.NewMigration(s.Version, "identity_api_keys_legacy_digest_import", migrations.TransactionModeDefault, legacySchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), base...), m), nil
}

const legacySchemaSQL = `ALTER TABLE identity_api_keys.keys DROP CONSTRAINT keys_pepper_version_check;
ALTER TABLE identity_api_keys.keys ADD CONSTRAINT keys_pepper_version_check CHECK(pepper_version BETWEEN 0 AND 4294967295);
CREATE UNIQUE INDEX identity_api_keys_tenant_key_id ON identity_api_keys.keys(tenant_id,key_id);
CREATE TABLE identity_api_keys.legacy_imports(
 tenant_id identity.directory_id NOT NULL,
 configuration_id identity.directory_id NOT NULL,
 key_id identity.directory_id NOT NULL,
 source_id identity.directory_id NOT NULL,
 source_version identity.version NOT NULL,
 source_fingerprint bytea NOT NULL CHECK(octet_length(source_fingerprint)=32),
 command_id text COLLATE "C" NOT NULL,
 PRIMARY KEY(tenant_id,configuration_id,key_id),
 UNIQUE(command_id),
 FOREIGN KEY(tenant_id,configuration_id,key_id) REFERENCES identity_api_keys.keys(tenant_id,configuration_id,key_id),
 FOREIGN KEY(command_id) REFERENCES identity_api_keys.command_effects(command_id) DEFERRABLE INITIALLY DEFERRED
);`

func (p *creationPhase) persistImport(ctx context.Context, w kernel.Work) error {
	if p.imported == nil {
		return nil
	}
	fingerprint, err := importFingerprint(*p.imported, p.input.Configuration)
	if err != nil {
		return err
	}
	b := p.input.Binding
	n, err := w.Exec(ctx, `INSERT INTO identity_api_keys.legacy_imports(tenant_id,configuration_id,key_id,source_id,source_version,source_fingerprint,command_id) VALUES($1,$2,$3,$4,$5::numeric,$6,$7)`, string(b.TenantID), p.input.Record.ConfigurationID, b.RecordID, p.imported.SourceID, strconv.FormatUint(p.imported.SourceVersion, 10), fingerprint[:], string(b.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *creationPhase) requireImportTarget(ctx context.Context, w kernel.Work) error {
	if p.imported == nil {
		return nil
	}
	rows, err := w.Query(ctx, `SELECT user_id,pepper_version,lookup_digest,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2 FOR UPDATE`, string(p.input.Binding.TenantID), p.input.Binding.RecordID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		if p.applied {
			return identity.UnavailableError{}
		}
		return nil
	}
	if !p.applied {
		return identity.ConflictError{}
	}
	var user string
	var pepper int64
	var digest, record []byte
	if rows.Scan(&user, &pepper, &digest, &record) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	want, err := encodeRecord(p.input.Record, p.input.Configuration)
	sum := p.imported.Digest.Sum()
	if err != nil || user != string(p.input.Binding.UserID) || pepper != 0 || !bytes.Equal(digest, sum[:]) || !bytes.Equal(record, want) {
		return identity.ConflictError{}
	}
	return nil
}

func (p *creationPhase) recoverImport(ctx context.Context, w kernel.RecoveryWork, b identity.CommandBinding, record apikey.Record) error {
	rows, err := w.Query(ctx, `SELECT s.source_id,s.source_version::text,s.source_fingerprint,k.pepper_version,k.lookup_digest FROM identity_api_keys.legacy_imports s JOIN identity_api_keys.keys k USING(tenant_id,configuration_id,key_id) WHERE s.tenant_id=$1 AND s.configuration_id=$2 AND s.key_id=$3 AND s.command_id=$4`, string(b.TenantID), record.ConfigurationID, b.RecordID, string(b.CommandID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var source, version string
	var fingerprint, digest []byte
	var pepper int64
	if !rows.Next() || rows.Scan(&source, &version, &fingerprint, &pepper, &digest) != nil || rows.Next() || rows.Err() != nil || pepper != 0 || len(digest) != 32 || len(fingerprint) != 32 {
		return identity.UnavailableError{}
	}
	v, err := positive(version)
	if err != nil || !scope(source) {
		return identity.UnavailableError{}
	}
	verifier, err := apikey.NewLegacyDigest([32]byte(digest))
	if err != nil {
		return identity.UnavailableError{}
	}
	want, err := importFingerprint(apikey.ImportRequest{Record: record, SourceID: source, SourceVersion: v, Digest: verifier}, p.service.config().Configuration)
	if err != nil || !bytes.Equal(fingerprint, want[:]) {
		return identity.UnavailableError{}
	}
	return nil
}
