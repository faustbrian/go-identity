package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func credentialReplacementOperation(op identity.FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.change"
}

func prepareCredentialReplacement(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var repo *Repository
	var native CredentialReplacementContributor
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" {
			repo, _ = entry.contributor.(*Repository)
		}
		if entry.descriptor == plan.feature.Contributor {
			native, _ = entry.contributor.(CredentialReplacementContributor)
		}
	}
	if repo == nil || repo.read == nil || native == nil || w.state.replacementIntent != nil {
		return w.fail(ctx, invalidCredentialReplacement())
	}
	intent, err := replacementCommand(native, command, plan.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	return lockCredentialReplacement(ctx, w, repo, intent, nil)
}

func lockCredentialReplacement(ctx context.Context, w Work, repo *Repository, intent CredentialReplacementIntent, reset *CredentialResetIntent) error {
	if repo == nil || repo.read == nil || w.state.replacementIntent != nil {
		return w.fail(ctx, invalidCredentialReplacement())
	}
	c := intent.Credential
	rows, err := w.Query(ctx, `SELECT u.tenant_id,u.user_id,u.status,u.version::text,u.credential_version::text,c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at
 FROM identity.users u JOIN identity.credential_references c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3 FOR UPDATE OF u,c`, string(c.TenantID), string(c.UserID), string(c.ID))
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
		return w.fail(ctx, identity.ForbiddenError{})
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
	current, err := decodeCredentialAuthority(identity.CredentialAuthorityQuery{TenantID: c.TenantID, UserID: c.UserID, CredentialID: c.ID}, row)
	if err != nil {
		return w.fail(ctx, err)
	}
	// Waiting for either row cannot renew the original Work lease. Eligibility
	// uses primary time sampled only after both authority locks are acquired.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if reset != nil {
		if current.Enabled != reset.ExpectedEnabled {
			return w.fail(ctx, identity.ForbiddenError{})
		}
		// Reset's separately admitted recovery profile may restore a disabled
		// reference. The existing exact authority check still owns every other
		// scope/status/version/expiry bound; authenticated change is unchanged.
		current.Enabled = true
	}
	if current.User.Version != intent.ExpectedUserVersion || identity.CheckCredentialAuthority(current, c, intent.ExpectedAuthorityVersion, now) != nil {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	copy := intent
	w.state.replacementIntent = &copy
	if reset != nil {
		copy := *reset
		w.state.resetIntent = &copy
	}
	return nil
}

func applyCredentialReplacement(ctx context.Context, w Work) error {
	if w.state.replacementIntent == nil || w.state.replacementReceipt != nil {
		return w.fail(ctx, invalidCredentialReplacement())
	}
	s := *w.state.replacementIntent
	c := s.Credential
	expectedEnabled := true
	if w.state.resetIntent != nil {
		if w.state.resetApplied {
			return w.fail(ctx, invalidCredentialReset())
		}
		expectedEnabled = w.state.resetIntent.ExpectedEnabled
		if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
			return err
		}
	}
	n, err := w.Exec(ctx, `UPDATE identity.users SET version=version+1,credential_version=credential_version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND credential_version=$4::numeric AND status='active'`, string(c.TenantID), string(c.UserID), strconv.FormatUint(s.ExpectedUserVersion, 10), strconv.FormatUint(s.ExpectedAuthorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity.credential_references SET version=version+1,enabled=true WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND kind=1 AND owner='identity/password' AND version=$4::numeric AND enabled=$5 AND (expires_at IS NULL OR expires_at>clock_timestamp())`, string(c.TenantID), string(c.UserID), string(c.ID), strconv.FormatUint(c.Version, 10), expectedEnabled)
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	key, err := base64.RawURLEncoding.DecodeString(string(w.state.binding.CommandID))
	if err != nil {
		return w.fail(ctx, invalidCredentialReplacement())
	}
	n, err = w.Exec(ctx, `INSERT INTO identity.credential_replacements(command_id,command_key,tenant_id,user_id,credential_id,operation,before_user_version,after_user_version,before_authority_version,after_authority_version,before_credential_version,after_credential_version)
 VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9::numeric,$10::numeric,$11::numeric,$12::numeric)`, string(w.state.binding.CommandID), key, string(c.TenantID), string(c.UserID), string(c.ID), w.state.binding.OperationID, strconv.FormatUint(s.ExpectedUserVersion, 10), strconv.FormatUint(s.ExpectedUserVersion+1, 10), strconv.FormatUint(s.ExpectedAuthorityVersion, 10), strconv.FormatUint(s.ExpectedAuthorityVersion+1, 10), strconv.FormatUint(c.Version, 10), strconv.FormatUint(c.Version+1, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	before := c.Version
	c.Version++
	w.state.replacementReceipt = &CredentialReplacementReceipt{Credential: c, BeforeUserVersion: s.ExpectedUserVersion, AfterUserVersion: s.ExpectedUserVersion + 1, BeforeAuthorityVersion: s.ExpectedAuthorityVersion, AfterAuthorityVersion: s.ExpectedAuthorityVersion + 1, BeforeCredentialVersion: before}
	if w.state.resetIntent != nil {
		w.state.resetApplied = true
	}
	return nil
}

func recoverCredentialReplacement(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.credential_replacements WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	// The committed journal is the only success owner. Retained effects beside
	// a pending journal are an atomicity conflict, not a reconstructed success.
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}
