package postgres

import (
	"bytes"
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

// PasswordChangeEffect owns session disposition inside the native password
// owner's original consuming Work. It owns no pool, coordinator, transaction,
// registry, callback or goroutine. Immutable configuration supports concurrent
// independent invocations; Work itself remains serial and borrowed. Zero is
// invalid. This seam is not a password verifier, proof or public change endpoint.
type PasswordChangeEffect struct {
	config  Config
	profile IdentifierAdmissionConfig
	schema  string
}

// Format redacts deployment and authority configuration for every verb.
func (*PasswordChangeEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordChangeEffect(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (*PasswordChangeEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export and map-key disclosure.
func (*PasswordChangeEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewPasswordChangeEffect freezes trusted single-factor password configuration
// without IO. Install CredentialContinuationMigrationSource and
// PasswordChangeMigrationSource alongside the kernel credential-replacement
// history before use. The registered password contributor alone lends the sole
// primary Work during its synchronous consuming invocation. No application store
// or independently managed transaction is accepted.
func NewPasswordChangeEffect(c Config, p IdentifierAdmissionConfig) (*PasswordChangeEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.AuthenticationMethod, p.CredentialOwner = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience), strings.Clone(p.AuthenticationMethod), strings.Clone(p.CredentialOwner)
	return &PasswordChangeEffect{config: c, profile: p, schema: pgx.Identifier{c.Schema}.Sanitize()}, nil
}

// Apply stages the original command's bounded session choice before the kernel
// advances the password reference and independent credential-authority epoch.
// Source bearer/proof possession, HIBP, reuse and one-use proof consumption are
// mandatory native password-owner responsibilities in this same Work. This
// helper admits that exact participant, compares the source's current owners,
// locks the complete selected set in bounded bytewise keyset pages, then stages
// continuation/revocation and retained effect evidence. The original source must
// remain valid after waits. No timestamp, lifetime, proof, assurance, remember,
// lookup, CSRF or unrelated authority is renewed.
//
// Preserve supports only the configured password reference and single-factor
// records without organization/factor/passkey dimensions. Mixed unsupported
// profiles deny preservation until their owners are composed. Stale, expired or
// family-denied supported rows are revoked, never upgraded. Revoke-other/all can
// terminally revoke other stored profiles without granting them authority.
// Already revoked rows are unchanged and excluded from the whole-set cap.
// Every error must propagate from ApplyFeature so the coordinator aborts all
// staged effects. Provisional success cannot authorize disclosure before commit.
func (e *PasswordChangeEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.CredentialReplacementContributor, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return identity.FeatureReceipt{}, readError(bounded, bounded.Err())
	}
	i, err := passwordChangeSessions(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p, _ := passwordChangeMetadata(command)
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || b != p.Binding || f.Operation != p.Operation || !passwordEffectLifecycle(b, l) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	native, err := owner.CredentialReplacement(command)
	if err != nil || native != i.replacement || l.BeforeVersion != native.Credential.Version {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	directory, credential, policy, err := OriginalSessionAdmission(e.profile, i.original, b)
	if err != nil || credential.Credential != native.Credential || credential.CredentialAuthorityVersion != native.ExpectedAuthorityVersion {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := w.RequireActiveCredential(bounded, owner, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.RequireActiveUserAuthorization(bounded, owner, policy); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, i.original); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := i.original.Bindings()
	original, _, err := encodeRecord(i.original)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	sourceDigest := sha256.Sum256(original)
	var preserved, revoked uint32
	var chain [32]byte
	found := false
	cursor := ""
	// The existing tenant mutation mutex excludes native issuance and rotation.
	// Owner locks above and session/family locks below persist until commit.
	// Work allows no SQL arrays/custom codecs and caps each result to 1MiB.
	for {
		rows, err := w.Query(bounded, `SELECT s.record::text,s.state,f.state,f.version::text,s.expires_at,s.tenant_id,s.session_id,s.user_id,s.family_id,s.version::text,s.family_version::text,s.digest_version,s.digest FROM `+e.schema+`.sessions s JOIN `+e.schema+`.families f USING(tenant_id,family_id,user_id) WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.state='active' AND s.session_id>$3 ORDER BY s.session_id LIMIT 16 FOR UPDATE OF s FOR SHARE OF f`, string(b.TenantID), string(b.UserID), cursor)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		page := make([]StoredSession, 0, 16)
		for rows.Next() {
			row := primaryStoredRow{}
			if err = row.scan(rows); err != nil {
				break
			}
			var stored StoredSession
			stored, err = row.decode(b.TenantID, "", nil)
			if err != nil {
				break
			}
			s, _ := stored.Session.Bindings()
			if s.UserID != b.UserID || s.SessionID <= cursor || len(page) == 16 {
				err = ErrInvalidRecord
				break
			}
			cursor = s.SessionID
			page = append(page, stored)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if uint64(preserved)+uint64(revoked)+uint64(len(page)) > uint64(i.maximum) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		now, err := passwordEffectTime(bounded, w, i.original)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		for _, stored := range page {
			record := stored.Session
			s, _ := record.Bindings()
			before, _, err := encodeRecord(record)
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
			isSource := s.SessionID == spec.SessionID
			if isSource {
				found = true
				if !bytes.Equal(before, original) {
					return identity.FeatureReceipt{}, identity.ConflictError{}
				}
			}
			keep := i.disposition == PasswordChangePreserveSessions || i.disposition == PasswordChangeRevokeOtherSessions && isSource
			if keep {
				if !passwordSessionProfile(record) || s.Authentication.CredentialID != string(i.replacement.Credential.ID) {
					return identity.FeatureReceipt{}, identity.ForbiddenError{}
				}
				life, lifeErr := record.Lifetime(now)
				d, c, a, admissionErr := OriginalSessionAdmission(e.profile, record, b)
				keep = lifeErr == nil && !now.Before(s.IssuedAt) && !now.Before(s.LastActivityAt) && now.Before(life.ExpiresAt) && !stored.FamilyRevoked && stored.CurrentFamilyVersion == s.FamilyVersion && admissionErr == nil && d == directory && c == credential && a == policy
				if isSource && !keep {
					return identity.FeatureReceipt{}, identity.ForbiddenError{}
				}
			}
			after := before
			if keep {
				next, err := passwordChangeSessionSuccessor(record, b, i.replacement)
				if err != nil {
					return identity.FeatureReceipt{}, err
				}
				after, _, err = encodeRecord(next)
				if err != nil {
					return identity.FeatureReceipt{}, err
				}
				n, err := w.Exec(bounded, `UPDATE `+e.schema+`.sessions SET record=$5::jsonb WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active' AND record=$6::jsonb`, string(b.TenantID), string(b.UserID), s.SessionID, strconv.FormatUint(s.Version, 10), string(after), string(before))
				if err != nil {
					return identity.FeatureReceipt{}, err
				}
				if n != 1 {
					return identity.FeatureReceipt{}, identity.ConflictError{}
				}
				preserved++
			} else {
				n, err := w.Exec(bounded, `UPDATE `+e.schema+`.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active' AND record=$5::jsonb`, string(b.TenantID), string(b.UserID), s.SessionID, strconv.FormatUint(s.Version, 10), string(before))
				if err != nil {
					return identity.FeatureReceipt{}, err
				}
				if n != 1 {
					return identity.FeatureReceipt{}, identity.ConflictError{}
				}
				revoked++
			}
			chain = passwordEffectChain(chain, sha256.Sum256(after), !keep)
		}
		if len(page) < 16 {
			break
		}
	}
	if !found {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	key, bindingDigest := revocationEvidence(b, l)
	resultDigest := passwordEffectDigest(bindingDigest, i.disposition, i.maximum, i.replacement.ExpectedUserVersion, i.replacement.ExpectedAuthorityVersion, i.replacement.Credential.Version, spec.SessionID, spec.Version, preserved, revoked, sourceDigest, chain)
	n, err := w.Exec(bounded, `INSERT INTO `+e.schema+`.password_changes(tenant_id,command_id,purpose,user_id,credential_id,source_id,source_version,disposition,maximum_sessions,before_user_version,before_authority_version,before_credential_version,preserved_count,revoked_count,source_digest,effects_digest,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10::numeric,$11::numeric,$12::numeric,$13,$14,$15,$16,$17,$18)`, string(b.TenantID), key, b.OperationID, string(b.UserID), b.RecordID, spec.SessionID, strconv.FormatUint(spec.Version, 10), int64(i.disposition), int64(i.maximum), strconv.FormatUint(i.replacement.ExpectedUserVersion, 10), strconv.FormatUint(i.replacement.ExpectedAuthorityVersion, 10), strconv.FormatUint(i.replacement.Credential.Version, 10), int64(preserved), int64(revoked), sourceDigest[:], chain[:], bindingDigest[:], resultDigest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if _, err := passwordEffectTime(bounded, w, i.original); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: f.Operation, BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}

func passwordEffectLifecycle(b identity.CommandBinding, l kernel.LifecyclePlan) bool {
	return b.OperationID == passwordChangeOperation().OperationID && l.EventType == "password.changed.v1" && l.BeforeVersion > 0 && l.BeforeVersion < ^uint64(0) && l.AfterVersion == l.BeforeVersion+1
}

func passwordEffectTime(ctx context.Context, w kernel.Work, original session.Session) (time.Time, error) {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	s, _ := original.Bindings()
	life, err := original.Lifetime(now)
	if err != nil || now.Before(s.IssuedAt) || now.Before(s.LastActivityAt) || !now.Before(life.ExpiresAt) {
		return time.Time{}, identity.ForbiddenError{}
	}
	return now, nil
}

func passwordEffectChain(previous, record [32]byte, revoked bool) [32]byte {
	encoded, _ := json.Marshal(struct {
		Previous, Record [32]byte
		Revoked          bool
	}{previous, record, revoked})
	return sha256.Sum256(append([]byte("identity-password-session-chain-v1\x00"), encoded...))
}

func passwordEffectDigest(binding [32]byte, mode PasswordChangeSessionDisposition, maximum uint32, user, authority, credential uint64, source string, sourceVersion uint64, preserved, revoked uint32, original, effects [32]byte) [32]byte {
	encoded, _ := json.Marshal(struct {
		Binding                     [32]byte
		Mode                        PasswordChangeSessionDisposition
		Maximum                     uint32
		User, Authority, Credential uint64
		Source                      string
		SourceVersion               uint64
		Preserved, Revoked          uint32
		Original, Effects           [32]byte
	}{binding, mode, maximum, user, authority, credential, source, sourceVersion, preserved, revoked, original, effects})
	return sha256.Sum256(append([]byte("identity-password-session-effect-v1\x00"), encoded...))
}

// Recover supplies only the retained original session-effect commitment during
// the password participant's invocation-fenced recovery. It authenticates no
// current access, reveals no session and never infers rollback from expiry or
// live-payload absence. The original coordinator must reconcile all participants.
// Missing infrastructure/corrupt evidence remains unknown; retained commitment
// survives session cleanup. No Work/rows/transaction is retained or closed.
func (e *PasswordChangeEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.CredentialReplacementContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || f.Operation != passwordChangeOperation() || !passwordEffectLifecycle(b, l) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	return recoverPasswordSessionEffect(bounded, w, e.schema, b, l)
}

func recoverPasswordSessionEffect[R SessionRows](ctx context.Context, q SessionQueryer[R], schema string, b identity.CommandBinding, l kernel.LifecyclePlan) (kernel.RecoveryStatus, error) {
	key, binding := revocationEvidence(b, l)
	rows, err := q.Query(ctx, `SELECT purpose,user_id,credential_id,source_id,source_version::text,disposition,maximum_sessions,before_user_version::text,before_authority_version::text,before_credential_version::text,preserved_count,revoked_count,source_digest,effects_digest,binding_digest,result_digest FROM `+schema+`.password_changes WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), key)
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
	var purpose, user, credential, source, sourceVersion, beforeUser, beforeAuthority, beforeCredential string
	var mode, maximum, preserved, revoked int64
	var sourceHash, effectsHash, storedBinding, storedResult []byte
	if err := rows.Scan(&purpose, &user, &credential, &source, &sourceVersion, &mode, &maximum, &beforeUser, &beforeAuthority, &beforeCredential, &preserved, &revoked, &sourceHash, &effectsHash, &storedBinding, &storedResult); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	uv, uerr := canonicalPasswordVersion(beforeUser)
	av, aerr := canonicalPasswordVersion(beforeAuthority)
	cv, cerr := canonicalPasswordVersion(beforeCredential)
	sv, serr := canonicalPasswordVersion(sourceVersion)
	if purpose != b.OperationID || user != string(b.UserID) || credential != b.RecordID || !scopeID(source) || uerr != nil || aerr != nil || cerr != nil || serr != nil || uv == ^uint64(0) || av == ^uint64(0) || cv != l.BeforeVersion || mode < 1 || mode > 3 || maximum < 1 || maximum > 100000 || preserved < 0 || revoked < 0 || preserved+revoked < 1 || preserved+revoked > maximum || mode == int64(PasswordChangeRevokeAllSessions) && preserved != 0 || mode == int64(PasswordChangeRevokeOtherSessions) && preserved != 1 || mode == int64(PasswordChangePreserveSessions) && preserved < 1 || len(sourceHash) != 32 || len(effectsHash) != 32 || subtle.ConstantTimeCompare(storedBinding, binding[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	var original, effects [32]byte
	copy(original[:], sourceHash)
	copy(effects[:], effectsHash)
	if original == ([32]byte{}) || effects == ([32]byte{}) {
		return kernel.RecoveryUnknown, nil
	}
	digest := passwordEffectDigest(binding, PasswordChangeSessionDisposition(mode), uint32(maximum), uv, av, cv, source, sv, uint32(preserved), uint32(revoked), original, effects)
	if subtle.ConstantTimeCompare(storedResult, digest[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

func canonicalPasswordVersion(raw string) (uint64, error) {
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != raw {
		return 0, ErrInvalidRecord
	}
	return v, nil
}
