package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// keyedAdmission owns only request-key to original-command allocation. It is
// not a command journal, receipt, lease or execution authority. Authenticated
// Queue composition must authorize before resolve and use the returned original
// command through the kernel coordinator. An allocated ID proves no execution.
// The namespace key is fixed for this deployment; changing it would split
// concurrent lookup, so the database rejects it rather than silently rotate it.
// Envelope and confidential intent keys retain their separate rotation policy.
type keyedAdmission struct {
	pool       *pgxpool.Pool
	deployment string
	key        [32]byte
	timeout    time.Duration
}

func (keyedAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres(redacted)"))
}
func (keyedAdmission) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

func newKeyedAdmission(ctx context.Context, pool *pgxpool.Pool, deployment string, key [32]byte, timeout time.Duration) (*keyedAdmission, error) {
	if ctx == nil {
		return nil, delivery.ErrInvalidInput
	}
	s, err := prepareKeyedAdmission(pool, deployment, key, timeout)
	if err != nil {
		return nil, err
	}
	if err := s.initialize(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func prepareKeyedAdmission(pool *pgxpool.Pool, deployment string, key [32]byte, timeout time.Duration) (*keyedAdmission, error) {
	if pool == nil || !safeID(deployment, false) || key == ([32]byte{}) || timeout < time.Second || timeout > 5*time.Second {
		return nil, delivery.ErrInvalidInput
	}
	return &keyedAdmission{pool, deployment, key, timeout}, nil
}

func (s *keyedAdmission) initialize(ctx context.Context) error {
	w, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if err := w.Err(); err != nil {
		return err
	}
	identity := custodyMAC(s.key, "identity-delivery-admission-namespace-v1", []byte(s.deployment), nil)
	tx, err := s.pool.Begin(w)
	if err != nil {
		return attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	if _, err := tx.Exec(w, `INSERT INTO identity.delivery_admission_namespaces(deployment,key_identity) VALUES($1,$2) ON CONFLICT(deployment) DO NOTHING`, s.deployment, identity[:]); err != nil {
		return attemptFailure(w, err)
	}
	var installed []byte
	if err := tx.QueryRow(w, `SELECT key_identity FROM identity.delivery_admission_namespaces WHERE deployment=$1`, s.deployment).Scan(&installed); err != nil {
		return attemptFailure(w, err)
	}
	if !hmac.Equal(installed, identity[:]) {
		return delivery.ErrConflict
	}
	if err := tx.Commit(w); err != nil {
		return delivery.ErrOutcomeUnknown
	}
	return nil
}

// resolve accepts a complete confidential logical-intent digest from owned
// workflow preparation. It never hashes raw addresses/content or invokes policy,
// encryption or a provider. Caller binding and logical intent must stay stable
// across retries; a different candidate command ID is not a different intent.
// A lost commit acknowledgement returns unknown and must be resolved under
// this same key, never treated as permission to use a replacement namespace.
func (s *keyedAdmission) resolve(ctx context.Context, b identity.CommandBinding, requestKey string, logical [32]byte) (identity.CommandID, error) {
	id, _, err := s.resolveVersion(ctx, b, requestKey, logical, 1)
	return id, err
}

// resolveVersion binds the original custody fingerprint key to the allocation.
// Current keys may change on restart, but replay must rebuild the original
// kernel command fingerprint with its retained key. The MAC authenticates this
// selected version as well as the logical intent; unavailable keys fail closed.
func (s *keyedAdmission) resolveVersion(ctx context.Context, b identity.CommandBinding, requestKey string, logical [32]byte, current uint32) (identity.CommandID, uint32, error) {
	return s.resolveVersionMode(ctx, b, requestKey, logical, current, true)
}

// Observe exact historical allocation without creating a key for expired input.
// An allocation remains correlation only; the kernel owns every outcome.
func (s *keyedAdmission) observeVersion(ctx context.Context, b identity.CommandBinding, requestKey string, logical [32]byte, current uint32) (identity.CommandID, uint32, error) {
	return s.resolveVersionMode(ctx, b, requestKey, logical, current, false)
}

func (s *keyedAdmission) resolveVersionMode(ctx context.Context, b identity.CommandBinding, requestKey string, logical [32]byte, current uint32, allocate bool) (identity.CommandID, uint32, error) {
	if ctx == nil || s == nil || s.pool == nil || s.key == ([32]byte{}) || b.RecordID != "" || len(requestKey) < 16 || !safeID(requestKey, false) || logical == ([32]byte{}) || current == 0 {
		return "", 0, delivery.ErrInvalidInput
	}
	w, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if err := w.Err(); err != nil {
		return "", 0, err
	}
	checked := b
	checked.RecordID = "enqueue-validation"
	if checked.ValidateFor(EnqueueOperation()) != nil {
		return "", 0, delivery.ErrInvalidInput
	}
	scope := keyedFields(s.deployment, string(b.TenantID), string(b.UserID), string(b.ActorID), string(b.ActorKind), b.OperationID)
	lookup := custodyMAC(s.key, "identity-delivery-request-key-v1", scope, []byte(requestKey))
	// Keep versions and correlation in intent identity, not lookup scope. A
	// changed retry conflicts instead of allocating a duplicate under a new key.
	metadata := keyedFields(b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), b.SchemaID, strconv.FormatUint(uint64(b.SchemaVersion), 10), b.CorrelationID, strconv.FormatUint(uint64(b.LinkMode), 10))
	versionedIntent := func(version uint32) [32]byte {
		versionMetadata := append(slices.Clone(metadata), keyedFields(strconv.FormatUint(uint64(version), 10))...)
		return custodyMAC(s.key, "identity-delivery-keyed-intent-v1", versionMetadata, logical[:])
	}
	intent := versionedIntent(current)
	tx, err := s.pool.Begin(w)
	if err != nil {
		return "", 0, attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	if allocate {
		if _, err := tx.Exec(w, `INSERT INTO identity.delivery_keyed_commands(deployment,lookup_digest,intent_digest,command_id,digest_key_version) VALUES($1,$2,$3,$4,$5) ON CONFLICT(deployment,lookup_digest) DO NOTHING`, s.deployment, lookup[:], intent[:], string(b.CommandID), int64(current)); err != nil {
			var collision *pgconn.PgError
			if errors.As(err, &collision) && collision.Code == "23505" {
				return "", 0, delivery.ErrConflict
			}
			return "", 0, attemptFailure(w, err)
		}
	}
	var original string
	var digest []byte
	var version int64
	if err := tx.QueryRow(w, `SELECT command_id,intent_digest,digest_key_version FROM identity.delivery_keyed_commands WHERE deployment=$1 AND lookup_digest=$2`, s.deployment, lookup[:]).Scan(&original, &digest, &version); err != nil {
		if !allocate && errors.Is(err, pgx.ErrNoRows) {
			return "", 0, delivery.ErrExpired
		}
		return "", 0, attemptFailure(w, err)
	}
	if version < 1 || version > 4294967295 {
		return "", 0, delivery.ErrUnavailable
	}
	intent = versionedIntent(uint32(version))
	if !hmac.Equal(digest, intent[:]) {
		return "", 0, delivery.ErrConflict
	}
	id, err := identity.ParseCommandID(original)
	if err != nil {
		return "", 0, delivery.ErrUnavailable
	}
	if err := tx.Commit(w); err != nil {
		return "", 0, delivery.ErrOutcomeUnknown
	}
	return id, uint32(version), nil
}

func keyedFields(fields ...string) []byte {
	var wire []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		wire = append(wire, size[:]...)
		wire = append(wire, field...)
	}
	return wire
}

// Derive complete logical identity before randomized encryption. Candidate
// command/effect IDs are allocation metadata, not message semantics; normalize
// only those fields while retaining every other scope and confidential input.
// Each encoding is already bounded by the shared input validator and cleared.
func (s *keyedAdmission) logical(bindings []payloadBinding, inputs []IntentInput) ([32]byte, error) {
	if s == nil || len(bindings) < 1 || len(bindings) > 16 || len(bindings) != len(inputs) {
		return [32]byte{}, delivery.ErrInvalidInput
	}
	h := hmac.New(sha256.New, s.key[:])
	_, _ = h.Write([]byte("identity-delivery-keyed-message-v1"))
	var size [8]byte
	for n, b := range bindings {
		b.Command.CommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
		b.Command.RecordID = "enqueue-validation"
		b.Intent.EffectID = "pending"
		// The allocation selects this storage key, not the caller's intent.
		// Its actual original version is separately MAC-bound in resolveVersion.
		b.DigestKeyVersion = 1
		aad, err := custodyContext(b, false)
		if err != nil {
			return [32]byte{}, err
		}
		wire, err := encodePayload(payload{Recipient: inputs[n].Recipient, Rendered: inputs[n].Rendered})
		if err != nil {
			return [32]byte{}, err
		}
		contextBytes := aad.AdditionalData()
		binary.BigEndian.PutUint64(size[:], uint64(len(contextBytes)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(contextBytes)
		binary.BigEndian.PutUint64(size[:], uint64(len(wire)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(wire)
		clear(wire)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

const keyedSchemaSQL = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
CREATE TABLE identity.delivery_admission_namespaces (
 deployment identity.directory_id PRIMARY KEY,
 key_identity bytea NOT NULL CHECK (octet_length(key_identity)=32)
);
CREATE TABLE identity.delivery_keyed_commands (
 deployment identity.directory_id NOT NULL REFERENCES identity.delivery_admission_namespaces,
 lookup_digest bytea NOT NULL CHECK (octet_length(lookup_digest)=32),
 intent_digest bytea NOT NULL CHECK (octet_length(intent_digest)=32),
 digest_key_version bigint NOT NULL CHECK (digest_key_version BETWEEN 1 AND 4294967295),
 command_id text COLLATE "C" NOT NULL CHECK (command_id ~ '^[A-Za-z0-9_-]{22}$'),
 PRIMARY KEY(deployment,lookup_digest),
 UNIQUE(deployment,command_id)
);
CREATE TRIGGER identity_delivery_namespace_immutable BEFORE UPDATE OR DELETE ON identity.delivery_admission_namespaces FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_delivery_policy_profiles();
CREATE TRIGGER identity_delivery_namespace_no_truncate BEFORE TRUNCATE ON identity.delivery_admission_namespaces FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_delivery_policy_profiles();
CREATE TRIGGER identity_delivery_keyed_immutable BEFORE UPDATE OR DELETE ON identity.delivery_keyed_commands FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_delivery_policy_profiles();
CREATE TRIGGER identity_delivery_keyed_no_truncate BEFORE TRUNCATE ON identity.delivery_keyed_commands FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_delivery_policy_profiles();
`
