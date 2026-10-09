package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

var _ kernel.CredentialReplacementContributor = (*Repository)(nil)

// Descriptor declares this immutable native material owner. Registration is
// not caller authentication or permission to begin a transaction.
func (*Repository) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}

// FeatureOperations returns fresh declarations for the existing-password change
// storage profile. Registration/reset/rehash are separate pending profiles.
func (*Repository) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{replacementOperation()}
}

func replacementOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (r *Repository) configuredWriter() bool {
	return r != nil && r.pool != nil && r.pool.Raw() != nil && r.maximumDuration > 0 && r.maximumDuration <= 10*time.Second && r.policy.Algorithm() != ""
}

// CredentialReplacement maps the original command's exact kernel predecessors
// and validates its new verifier under the configured current issuance profile.
// It is pure, bounded and does not hash, verify or authorize passwords.
func (r *Repository) CredentialReplacement(c identity.Command) (kernel.CredentialReplacementIntent, error) {
	if !r.configuredWriter() {
		return kernel.CredentialReplacementIntent{}, password.ErrPasswordWork
	}
	i, _, err := passwordReplacement(c, r.policy)
	return i, err
}

// ValidateFeatureCommand checks the closed storage schema, exact native owner,
// protected audit and version transition before SQL. This trusted persistence
// seam is not an authenticated endpoint: the password workflow must separately
// compose reauthentication, HIBP/reuse and session policy with the coordinator.
func (r *Repository) ValidateFeatureCommand(c identity.Command, p kernel.CommandPlan) error {
	if !r.configuredWriter() {
		return password.ErrPasswordWork
	}
	i, _, err := passwordReplacement(c, r.policy)
	if err != nil || p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != replacementOperation() || p.SubjectType != "credential" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "password.changed.v1" || p.Lifecycle.BeforeVersion != i.Credential.Version || p.Lifecycle.AfterVersion != i.Credential.Version+1 || len(p.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := p.Audits[0]
	if a.EventType != "identity.password.change" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	return nil
}

func passwordReplacement(c identity.Command, policy primitive.Policy) (kernel.CredentialReplacementIntent, primitive.EncodedHash, error) {
	fail := func() (kernel.CredentialReplacementIntent, primitive.EncodedHash, error) {
		return kernel.CredentialReplacementIntent{}, primitive.EncodedHash{}, password.ErrPasswordWork
	}
	s, ok := c.PasswordHashFeature()
	raw, hasHash := c.PasswordHash()
	if !ok || !hasHash || s.Operation != replacementOperation() || len(s.Fields) != 8 || policy.Algorithm() == "" {
		return fail()
	}
	values := make(map[string]identity.FeatureValue, 8)
	for _, f := range s.Fields {
		if _, duplicate := values[f.Name]; duplicate {
			return fail()
		}
		values[f.Name] = f.Value
	}
	i := kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: identity.CredentialID(values["credential.id"].Text), TenantID: identity.TenantID(values["credential.tenant"].Text), UserID: identity.UserID(values["credential.user"].Text), Owner: values["credential.owner"].Text, Kind: identity.CredentialPassword, Version: values["credential.version"].Uint64}, ExpectedUserVersion: values["credential.expected-user-version"].Uint64, ExpectedAuthorityVersion: values["credential.expected-authority-version"].Uint64}
	expected, err := kernel.CredentialReplacementFields(i)
	if err != nil || i.Credential.TenantID != s.Binding.TenantID || i.Credential.UserID != s.Binding.UserID || string(i.Credential.ID) != s.Binding.RecordID {
		return fail()
	}
	for _, f := range expected {
		v := values[f.Name]
		if v.Kind != f.Value.Kind || v.Text != f.Value.Text || v.Uint64 != f.Value.Uint64 || v.Bytes != nil || v.Int64 != 0 || v.Bool || v.Time != (time.Time{}) {
			return fail()
		}
	}
	hash, err := primitive.ParseEncodedHash(raw, policy.Limits())
	if err != nil || hash.Algorithm() != policy.Algorithm() {
		return fail()
	}
	// Policies may retain unused fields for another algorithm. Only the selected
	// issuance algorithm owns work parameters; verification limits remain broader.
	if hash.Algorithm() == primitive.Argon2id && hash.Argon2idParameters() != policy.Argon2idParameters() || hash.Algorithm() == primitive.Bcrypt && hash.BcryptCost() != policy.BcryptCost() {
		return fail()
	}
	return i, hash, nil
}

// ApplyFeature replaces only owned material through this exact repository's
// active native invocation. The kernel has already locked and checked user/ref
// authority; this phase locks the material predecessor and performs one CAS.
// It retains hash-free original-command evidence in the same transaction.
// No transaction, Work or caller secret is retained or closed. The returned
// receipt is provisional until the coordinator commits all declared effects.
// Earlier caller and coordinator deadlines win over this adapter's budget.
// Errors require coordinator Abort; no private retry or authority refresh runs.
func (r *Repository) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || !r.configuredWriter() {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	i, hash, err := passwordReplacement(c, r.policy)
	s, _ := c.PasswordHashFeature()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	return r.applyReplacement(ctx, w, r, s, i, hash)
}

func (r *Repository) applyReplacement(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, s identity.FeatureCommandSpec, i kernel.CredentialReplacementIntent, hash primitive.EncodedHash) (identity.FeatureReceipt, error) {
	b, feature, transition, scopeErr := w.FeatureScope(owner)
	if scopeErr != nil || b != s.Binding || feature.Operation != replacementOperation() || transition.EventType != "password.changed.v1" || transition.BeforeVersion != i.Credential.Version || transition.AfterVersion != i.Credential.Version+1 {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	rows, err := w.Query(bounded, `SELECT version::text,algorithm,CASE WHEN octet_length(encoded_hash)<=$4 THEN encoded_hash ELSE '' END,created_at,updated_at FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 FOR UPDATE`, string(b.TenantID), string(b.UserID), b.RecordID, r.limits.EncodedHashBytes)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{}, password.ErrCredentialAbsent
	}
	var version, algorithm, previous string
	var created, updated time.Time
	err = rows.Scan(&version, &algorithm, &previous, &created, &updated)
	if err != nil {
		rows.Close()
		return identity.FeatureReceipt{}, err
	}
	if rows.Next() {
		rows.Close()
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	v, err := canonicalVersion(version)
	if err != nil || v != i.Credential.Version {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	old, err := primitive.ParseEncodedHash(previous, r.limits)
	if err != nil || string(old.Algorithm()) != algorithm || !storedTime(created) || !storedTime(updated) || updated.Before(created) {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	n, err := w.Exec(bounded, `UPDATE identity_password.credentials SET version=version+1,algorithm=$5,encoded_hash=$6,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND version=$4::numeric`, string(b.TenantID), string(b.UserID), b.RecordID, version, string(hash.Algorithm()), hash.String())
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, digest := replacementEvidence(b, transition)
	n, err = w.Exec(bounded, `INSERT INTO identity_password.replacements(tenant_id,command_id,purpose,user_id,credential_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, version, strconv.FormatUint(v+1, 10), digest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: v, AfterVersion: v + 1}, nil
}

// RecoverParticipant inspects original retained material-effect evidence, never
// a mutable current hash/version. Absence is native NotCommitted only because
// evidence is atomically inserted and not independently pruned. Exact presence
// proves this participant's effect, not the complete command: the original
// journal and other native owners still decide the recoverable outcome.
// Corruption, missing infrastructure or a foreign/expired invocation is Unknown.
func (r *Repository) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return r.recoverReplacement(ctx, w, r)
}

func (r *Repository) recoverReplacement(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || !r.configuredWriter() {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != replacementOperation() || transition.EventType != "password.changed.v1" || transition.BeforeVersion == 0 || transition.BeforeVersion == ^uint64(0) || transition.AfterVersion != transition.BeforeVersion+1 {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	id, digest := replacementEvidence(b, transition)
	rows, err := w.Query(bounded, `SELECT user_id,credential_id,purpose,before_version::text,after_version::text,binding_digest FROM identity_password.replacements WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
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
	var user, credential, purpose, before, after string
	var stored []byte
	if err := rows.Scan(&user, &credential, &purpose, &before, &after, &stored); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if err := rows.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if user != string(b.UserID) || credential != b.RecordID || purpose != b.OperationID || before != strconv.FormatUint(transition.BeforeVersion, 10) || after != strconv.FormatUint(transition.AfterVersion, 10) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

// Non-secret binding complements the keyed journal rather than copying it.
func replacementEvidence(b identity.CommandBinding, l kernel.LifecyclePlan) ([]byte, [32]byte) {
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	data, _ := json.Marshal(struct {
		Binding       identity.CommandBinding
		Before, After uint64
	}{b, l.BeforeVersion, l.AfterVersion})
	return id, sha256.Sum256(append([]byte("identity-password-replacement-v1\x00"), data...))
}
