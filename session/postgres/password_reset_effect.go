package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// PasswordResetEffect terminally revokes the complete active-state session set
// in the password reset owner's sole Work. Unlike password change, reset has no
// authenticated source session and permits no preservation. It owns no pool,
// transaction, callbacks or goroutines. Immutable instances permit concurrent
// independent invocations; each borrowed Work remains serial.
type PasswordResetEffect struct {
	config Config
	schema string
}

// NewPasswordResetEffect validates trusted storage configuration without IO.
// Install PasswordResetMigrationSource after the session and kernel histories.
// Each complete set is capped at 100000 rows; overflow fails the whole reset,
// rather than revoking a prefix and declaring success. All active-state rows,
// including expired and other-method sessions, count. Empty sets are valid.
func NewPasswordResetEffect(c Config) (*PasswordResetEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	return &PasswordResetEffect{config: c, schema: pgx.Identifier{c.Schema}.Sanitize()}, nil
}

// Format omits deployment configuration for all formatting verbs.
func (*PasswordResetEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordResetEffect(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (*PasswordResetEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text and map-key export.
func (*PasswordResetEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

func passwordResetSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-complete", SchemaID: "password-reset-complete", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func resetSessionScope(b identity.CommandBinding, op identity.FeatureOperation, l kernel.LifecyclePlan) bool {
	return op == passwordResetSessionOperation() && b.OperationID == op.OperationID && l.EventType == "password.reset.v1" && l.BeforeVersion > 0 && l.BeforeVersion < ^uint64(0) && l.AfterVersion == l.BeforeVersion+1
}

// Apply stages revocation and hash-free original effect evidence. Only the exact
// registered native CredentialResetContributor can lend Work. The kernel has
// fenced the reset's aggregate, password reference and credential epoch; the
// native workflow must additionally verify original issuance, current account,
// identifier/factors, risk/HIBP and atomic capability consumption. This method
// is not reset authorization and never issues a session or upgrades authority.
// Propagate every error so the coordinator aborts password and session effects.
// A returned receipt is provisional until the complete command commits.
func (e *PasswordResetEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.CredentialResetContributor, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || owner == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return identity.FeatureReceipt{}, readError(bounded, bounded.Err())
	}
	b, f, l, err := w.FeatureScope(owner)
	spec, ok := command.PasswordResetFeature()
	if err != nil || !ok || spec.Binding != b || spec.Operation != f.Operation || !resetSessionScope(b, f.Operation, l) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	i, err := owner.CredentialReset(command)
	r := i.Replacement
	if err != nil || r.Credential.TenantID != b.TenantID || r.Credential.UserID != b.UserID || string(r.Credential.ID) != b.RecordID || r.Credential.Kind != identity.CredentialPassword || r.Credential.Owner != "identity/password" || r.Credential.Version != l.BeforeVersion || r.ExpectedUserVersion == 0 || r.ExpectedUserVersion == ^uint64(0) || r.ExpectedAuthorityVersion == 0 || r.ExpectedAuthorityVersion == ^uint64(0) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	// Native issuance/rotation/reset all hold the kernel tenant mutation mutex.
	// Stable bounded pages retain row locks until the same commit. No transaction
	// or SQL array is introduced, and no caller code runs while locks are held.
	cursor, count, chain := "", uint32(0), resetSessionChain()
	for {
		rows, err := w.Query(bounded, `SELECT session_id,user_id,version::text FROM `+e.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active' AND session_id>$3 ORDER BY session_id LIMIT 16 FOR UPDATE`, string(b.TenantID), string(b.UserID), cursor)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		type selected struct {
			id, version string
			value       uint64
		}
		page := make([]selected, 0, 16)
		for rows.Next() {
			var row selected
			var user string
			if err = rows.Scan(&row.id, &user, &row.version); err != nil {
				break
			}
			row.value, err = canonicalPasswordVersion(row.version)
			if err != nil || !scopeID(row.id) || row.id <= cursor || user != string(b.UserID) || len(page) == 16 {
				err = ErrInvalidRecord
				break
			}
			cursor = row.id
			page = append(page, row)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if uint64(count)+uint64(len(page)) > 100000 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		for _, row := range page {
			n, err := w.Exec(bounded, `UPDATE `+e.schema+`.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active'`, string(b.TenantID), string(b.UserID), row.id, row.version)
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
			if n != 1 {
				return identity.FeatureReceipt{}, identity.ConflictError{}
			}
			count++
			chain = resetSessionNext(chain, row.id, row.value)
		}
		if len(page) < 16 {
			break
		}
	}
	key, binding := revocationEvidence(b, l)
	result := resetSessionDigest(binding, r.ExpectedUserVersion, r.ExpectedAuthorityVersion, l.BeforeVersion, count, chain)
	n, err := w.Exec(bounded, `INSERT INTO `+e.schema+`.password_resets(tenant_id,command_id,purpose,user_id,credential_id,before_user_version,before_authority_version,before_credential_version,revoked_count,effects_digest,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9,$10,$11,$12)`, string(b.TenantID), key, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(r.ExpectedUserVersion, 10), strconv.FormatUint(r.ExpectedAuthorityVersion, 10), strconv.FormatUint(l.BeforeVersion, 10), int64(count), chain[:], binding[:], result[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: f.Operation, BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}

// Recover reconciles retained original effect evidence, not mutable session
// payloads. Cleanup and later logins cannot erase original commitment. Absence
// is NotCommitted only because insertion is atomic and evidence is not pruned
// independently. Corruption or unavailable infrastructure remains Unknown.
// This reveals no bearer and does not establish current result-access policy;
// the coordinator must reconcile all participants before disclosing an outcome.
func (e *PasswordResetEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.CredentialResetContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || owner == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || !resetSessionScope(b, f.Operation, l) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	key, binding := revocationEvidence(b, l)
	rows, err := w.Query(bounded, `SELECT purpose,user_id,credential_id,before_user_version::text,before_authority_version::text,before_credential_version::text,revoked_count,effects_digest,binding_digest,result_digest FROM `+e.schema+`.password_resets WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), key)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var purpose, user, credential, uv, av, cv string
	var count int64
	var effects, storedBinding, storedResult []byte
	if err := rows.Scan(&purpose, &user, &credential, &uv, &av, &cv, &count, &effects, &storedBinding, &storedResult); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	u, ue := canonicalPasswordVersion(uv)
	a, ae := canonicalPasswordVersion(av)
	c, ce := canonicalPasswordVersion(cv)
	if purpose != b.OperationID || user != string(b.UserID) || credential != b.RecordID || ue != nil || ae != nil || ce != nil || u == ^uint64(0) || a == ^uint64(0) || c != l.BeforeVersion || count < 0 || count > 100000 || len(effects) != 32 || subtle.ConstantTimeCompare(storedBinding, binding[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	var chain [32]byte
	copy(chain[:], effects)
	if chain == ([32]byte{}) || count == 0 && chain != resetSessionChain() {
		return kernel.RecoveryUnknown, nil
	}
	result := resetSessionDigest(binding, u, a, c, uint32(count), chain)
	if subtle.ConstantTimeCompare(storedResult, result[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

func resetSessionChain() [32]byte {
	return sha256.Sum256([]byte("identity-password-reset-sessions-empty-v1\x00"))
}

func resetSessionNext(previous [32]byte, id string, version uint64) [32]byte {
	encoded, _ := json.Marshal(struct {
		Previous [32]byte
		ID       string
		Version  uint64
	}{previous, id, version})
	return sha256.Sum256(append([]byte("identity-password-reset-session-chain-v1\x00"), encoded...))
}

func resetSessionDigest(binding [32]byte, user, authority, credential uint64, count uint32, chain [32]byte) [32]byte {
	encoded, _ := json.Marshal(struct {
		Binding                     [32]byte
		User, Authority, Credential uint64
		Count                       uint32
		Chain                       [32]byte
	}{binding, user, authority, credential, count, chain})
	return sha256.Sum256(append([]byte("identity-password-reset-session-effect-v1\x00"), encoded...))
}
