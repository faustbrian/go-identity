package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func credentialCompromiseOperation(op identity.FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.mark-compromised" || op.Owner == "passkey" && op.OperationID == "identity.passkey.mark-compromised"
}

func prepareCredentialCompromise(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var repo *Repository
	var native CredentialCompromiseContributor
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" {
			repo, _ = entry.contributor.(*Repository)
		}
		if entry.descriptor == plan.feature.Contributor {
			native, _ = entry.contributor.(CredentialCompromiseContributor)
		}
	}
	if repo == nil || repo.read == nil || native == nil || w.state.credentialIntent != nil {
		return w.fail(ctx, invalidCredentialCompromise())
	}
	intent, err := compromiseCommand(native, command, plan.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	q := identity.CredentialAuthorityQuery{TenantID: intent.Credential.TenantID, UserID: intent.Credential.UserID, CredentialID: intent.Credential.ID}
	rows, err := w.Query(ctx, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at
 FROM identity.users u JOIN identity.credential_references c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3 FOR UPDATE OF u,c`, string(q.TenantID), string(q.UserID), string(q.CredentialID))
	if err != nil {
		return err
	}
	var row credentialStorageRow
	var expiry *time.Time
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return w.fail(ctx, identity.ConflictError{})
	}
	err = rows.Scan(&row.tenant, &row.user, &row.status, &row.userVersion, &row.authority, &row.id, &row.kind, &row.owner, &row.version, &row.enabled, &expiry)
	if err != nil {
		rows.Close()
		return err
	}
	if rows.Next() {
		rows.Close()
		return w.fail(ctx, identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if expiry != nil {
		row.expires = pgtype.Timestamptz{Time: *expiry, Valid: true}
	}
	current, err := decodeCredentialAuthority(q, row)
	if err != nil {
		return w.fail(ctx, err)
	}
	if current.Credential != intent.Credential || current.User.Version != intent.ExpectedUserVersion || current.AuthorityVersion != intent.ExpectedAuthorityVersion || !current.Enabled {
		return w.fail(ctx, identity.ConflictError{})
	}
	if current.User.Status == identity.StatusDeleted || current.User.Status == identity.StatusAnonymized {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	// Sample primary time after both locks; the existing Work lease cannot be
	// renewed by waiting, and no caller timestamp establishes eligibility.
	if _, err := w.DatabaseTime(ctx); err != nil {
		return err
	}
	copy := intent
	w.state.credentialIntent = &copy
	return nil
}

func applyCredentialCompromise(ctx context.Context, w Work) error {
	if w.state.credentialIntent == nil || w.state.credentialReceipt != nil {
		return w.fail(ctx, invalidCredentialCompromise())
	}
	s := *w.state.credentialIntent
	c := s.Credential
	n, err := w.Exec(ctx, `UPDATE identity.users SET version=version+1,credential_version=credential_version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND credential_version=$4::numeric AND status NOT IN ('deleted','anonymized')`, string(c.TenantID), string(c.UserID), strconv.FormatUint(s.ExpectedUserVersion, 10), strconv.FormatUint(s.ExpectedAuthorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity.credential_references SET enabled=false,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND kind=$4 AND owner=$5 AND version=$6::numeric AND enabled=true`, string(c.TenantID), string(c.UserID), string(c.ID), int16(c.Kind), c.Owner, strconv.FormatUint(c.Version, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	key, err := base64.RawURLEncoding.DecodeString(string(w.state.binding.CommandID))
	if err != nil {
		return w.fail(ctx, invalidCredentialCompromise())
	}
	n, err = w.Exec(ctx, `INSERT INTO identity.credential_compromises(command_id,command_key,tenant_id,user_id,credential_id,operation,owner,kind,before_user_version,after_user_version,before_authority_version,after_authority_version,before_credential_version,after_credential_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11::numeric,$12::numeric,$13::numeric,$14::numeric)`, string(w.state.binding.CommandID), key, string(c.TenantID), string(c.UserID), string(c.ID), w.state.binding.OperationID, c.Owner, int16(c.Kind), strconv.FormatUint(s.ExpectedUserVersion, 10), strconv.FormatUint(s.ExpectedUserVersion+1, 10), strconv.FormatUint(s.ExpectedAuthorityVersion, 10), strconv.FormatUint(s.ExpectedAuthorityVersion+1, 10), strconv.FormatUint(c.Version, 10), strconv.FormatUint(c.Version+1, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	before := c.Version
	c.Version++
	w.state.credentialReceipt = &CredentialCompromiseReceipt{Credential: c, BeforeUserVersion: s.ExpectedUserVersion, AfterUserVersion: s.ExpectedUserVersion + 1, BeforeAuthorityVersion: s.ExpectedAuthorityVersion, AfterAuthorityVersion: s.ExpectedAuthorityVersion + 1, BeforeCredentialVersion: before}
	return nil
}

func recoverCredentialCompromise(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.credential_compromises WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	// A retained effect beside a pending journal is an atomicity conflict, not
	// permission to reconstruct success from a current/changed credential.
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}
