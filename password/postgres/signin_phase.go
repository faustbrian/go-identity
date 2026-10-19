package passwordpostgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

// Only the native login invocation constructs this owner after real comparison.
// The exact immutable command identity retains the original Secret owner: a
// structurally identical command carrying a different password cannot replace it.
// No public comparison result or caller-created proof can obtain this custody.
type signinPhase struct {
	operation        identity.FeatureOperation
	expected         identity.Command
	effect           *sessionpg.PasswordSigninEffect
	recipient        kernel.RecipientRecord
	username         kernel.UsernameRecord
	material         password.CredentialSnapshot
	request          password.SigninRequest
	flow             session.PreAuthTransaction
	flowKey          session.DigestKey
	record           auth.SignedSignInRecord
	verificationKeys map[string]ed25519.PublicKey
	admission        risk.AuthenticationAdmission
	maximumHashBytes int
	upgrade          *kernel.PasswordHashUpgradeIntent
	replacement      primitive.EncodedHash
	hashPolicy       primitive.Policy
	factorVersion    uint64
}

var _ kernel.FeatureExecutionContributor = (*signinPhase)(nil)
var _ kernel.FeatureCommitContributor = (*signinPhase)(nil)

func (*signinPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}

func (p *signinPhase) FeatureOperations() []identity.FeatureOperation {
	if p == nil {
		return nil
	}
	return []identity.FeatureOperation{p.operation}
}

func (p *signinPhase) matches(c identity.Command) bool {
	if p == nil || p.effect == nil || c != p.expected {
		return false
	}
	f, ok := c.PasswordSigninFeature()
	secret, cookie, custody := c.PasswordSigninCustody()
	return ok && f.Operation == p.operation && custody && secret.Len() != 0 && cookie.Token() == p.request.Cookie.Token()
}

func (p *signinPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if !p.matches(c) || p.maximumHashBytes <= 0 || p.maximumHashBytes > 1<<20 || p.request.Validate() != nil || p.recipient.Validate() != nil || p.recipient.Suppressed {
		return password.ErrPasswordWork
	}
	f, _ := c.PasswordSigninFeature()
	if p.validateUsernameFields() != nil {
		return password.ErrPasswordWork
	}
	if p.operation.OperationID == "identity.phone.password-signin" && p.factorVersion == 0 {
		return password.ErrPasswordWork
	}
	scope := p.admission.Prepared().Scope
	if scope.Tenant != string(f.Binding.TenantID) || scope.Operation != risk.Action(f.Binding.OperationID) || scope.Attempt != string(f.Binding.CommandID) || p.request.TenantID != f.Binding.TenantID {
		return password.ErrPasswordWork
	}
	if plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != f.Operation || plan.SubjectType != "session" || plan.Capability != nil || plan.OTP != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "session.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := plan.Audits[0]
	if a.EventType != f.Operation.OperationID || !a.Required || a.RequiredRecordCount != 1 || a.SchemaVersion != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	s, err := sessionpg.PasswordSigninSession(c)
	if err != nil {
		return password.ErrPasswordWork
	}
	spec, _ := s.Bindings()
	material := p.material.Authority()
	if material.AuthorityVersion != p.recipient.CredentialAuthorityVersion || material.User.ID != p.recipient.User.ID || material.User.Status != identity.StatusActive || !material.Enabled {
		return password.ErrPasswordWork
	}
	r := p.record
	expectedVersion := material.Credential.Version
	if p.upgrade != nil {
		expected := kernel.PasswordHashUpgradeIntent{Admission: kernel.CredentialAdmission{Credential: material.Credential, UserAuthorityVersion: p.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: p.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.recipient.CredentialAuthorityVersion}, ExpectedUserVersion: p.recipient.User.Version}
		if *p.upgrade != expected || expectedVersion == ^uint64(0) {
			return password.ErrPasswordWork
		}
		expectedVersion++
	}
	frame, err := r.SigningBytes()
	key := p.verificationKeys[r.KeyID]
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, r.Signature) || r.State != auth.SignInStateAuthenticated || r.Proof != spec.Authentication.Proof || r.ProofVersion != spec.Authentication.ProofVersion || r.CredentialID != spec.Authentication.CredentialID || r.CredentialVersion != spec.Authentication.CredentialVersion || r.Proof.ID != auth.ProofID(f.Binding.CommandID) || material.User.ID != spec.UserID || material.Credential.ID != identity.CredentialID(r.CredentialID) || expectedVersion != r.CredentialVersion || p.material.EncodedHash().String() == "" {
		return password.ErrPasswordWork
	}
	// Session owns its closed projection. Native rehash adds only the exact
	// predecessor projection and material commitment to the same keyed command.
	if len(f.Fields) == 0 {
		return password.ErrPasswordWork
	}
	return p.validateRehashFields(f.Fields)
}

func (p *signinPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || !p.matches(c) {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	b, f, transition, err := w.FeatureScope(p)
	original, _ := c.PasswordSigninFeature()
	if err != nil || b != original.Binding || f.Operation != original.Operation || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Directory and kernel predecessor locks precede material. Rehash reserves
	// exclusive authority before CAS; ordinary signin retains shared admission.
	var provisional identity.FeatureReceipt
	if p.upgrade != nil {
		err = p.effect.PrepareHashUpgrade(ctx, w, p, c, p.recipient)
	} else {
		provisional, err = p.effect.Apply(ctx, w, p, c, p.recipient, p.flow)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.operation.OperationID == "identity.username.signin" {
		if err := w.RequireUsername(ctx, p, p.username); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.factorVersion != 0 {
		if err := mfapg.RequirePasswordSigninFactors(ctx, w, p, c, p.recipient.User.ID, p.factorVersion, false); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	m := p.material.Authority().Credential
	lock := " FOR SHARE"
	if p.upgrade != nil {
		lock = " FOR UPDATE"
	}
	rows, err := w.Query(ctx, `SELECT version::text,CASE WHEN octet_length(encoded_hash)<=$4 THEN encoded_hash ELSE '' END FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`+lock, string(m.TenantID), string(m.UserID), string(m.ID), p.maximumHashBytes)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var version, hash string
	if !rows.Next() {
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return identity.FeatureReceipt{}, rowErr
		}
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	err = rows.Scan(&version, &hash)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if version != strconv.FormatUint(m.Version, 10) || hash != p.material.EncodedHash().String() {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.upgrade != nil {
		n, e := w.Exec(ctx, `UPDATE identity_password.credentials SET version=version+1,algorithm=$5,encoded_hash=$6,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND version=$4::numeric`, string(m.TenantID), string(m.UserID), string(m.ID), version, string(p.replacement.Algorithm()), p.replacement.String())
		if e != nil {
			return identity.FeatureReceipt{}, e
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		if _, err = w.ApplyPasswordHashUpgrade(ctx, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		provisional, err = p.effect.ApplyHashUpgrade(ctx, w, p, c, p.flow)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	payload, err := encodeSigninRecord(p.record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_password.signin_records(proof_id,tenant_id,user_id,command_id,purpose,record) VALUES($1,$2,$3,$4,$5,$6)`, string(p.record.Proof.ID), string(b.TenantID), string(m.UserID), id, b.OperationID, payload)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err := p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return provisional, nil
}

// Only the coordinator can grant final scope, after required persistence and
// journal writes. Checking before Commit would miss audit/outbox waits.
func (p *signinPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if !p.matches(command) {
		return password.ErrPasswordWork
	}
	b, feature, transition, err := w.FeatureScope(p)
	f, _ := command.PasswordSigninFeature()
	if err != nil || b != f.Binding || feature.Operation != f.Operation || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return password.ErrPasswordWork
	}
	if err := p.checkTime(ctx, w); err != nil {
		return err
	}
	if p.factorVersion != 0 {
		return mfapg.RequirePasswordSigninFactors(ctx, w, p, command, p.recipient.User.ID, p.factorVersion, false)
	}
	return nil
}

func (p *signinPhase) checkTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.checkDelivery(ctx, now)
}

// Primary time controls commit admission; the same original bounds are also
// checked against the trusted issuer clock after commit before token delivery.
// Neither observation rewrites or renews any contributing authority evidence.
func (p *signinPhase) checkDelivery(ctx context.Context, now time.Time) error {
	if ctx == nil || p == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return password.ErrPasswordWork
	}
	f, ok := p.expected.PasswordSigninFeature()
	if !ok || admitSigninFlow(p.request, p.flow, p.flowKey, f.Binding.PolicyID, f.Binding.PolicyVersion, now) != nil || now.Before(p.record.Proof.IssuedAt) || !now.Before(p.record.Proof.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	record, err := sessionpg.PasswordSigninSession(p.expected)
	if err != nil {
		return password.ErrPasswordWork
	}
	spec, _ := record.Bindings()
	lifetime, err := record.Lifetime(now)
	if err != nil || now.Before(spec.IssuedAt) || !lifetime.Fresh {
		return identity.ForbiddenError{}
	}
	expires := p.material.Authority().ExpiresAt
	if !expires.IsZero() && !now.Before(expires) {
		return identity.ForbiddenError{}
	}
	return p.admission.CheckAt(ctx, now)
}

func (p *signinPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if ctx == nil || p == nil || p.effect == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	b, f, transition, err := w.FeatureScope(p)
	if err != nil || f.Operation != p.operation || (f.Operation.OperationID != "identity.password.signin" && f.Operation.OperationID != "identity.username.signin" && f.Operation.OperationID != "identity.phone.password-signin") || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	effect, err := p.effect.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	rows, err := w.Query(ctx, `SELECT proof_id,user_id,CASE WHEN octet_length(record)<=$3 THEN record ELSE ''::bytea END FROM identity_password.signin_records WHERE tenant_id=$1 AND purpose=$4 AND command_id=$2`, string(b.TenantID), id, maximumSigninRecordBytes, b.OperationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || effect != kernel.RecoveryNotCommitted {
			return kernel.RecoveryUnknown, password.ErrPasswordWork
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var proofID, user string
	var payload []byte
	if rows.Scan(&proofID, &user, &payload) != nil || rows.Next() || rows.Err() != nil || effect != kernel.RecoveryCommitted || proofID != string(b.CommandID) || b.UserID != "" && user != string(b.UserID) {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	r, err := decodeSigninRecord(auth.ProofID(proofID), string(b.TenantID), user, payload)
	if err != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	frame, err := r.SigningBytes()
	key := p.verificationKeys[r.KeyID]
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, r.Signature) {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	return kernel.RecoveryCommitted, nil
}
