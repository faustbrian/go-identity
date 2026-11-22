//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// This proves only the kernel storage transition. It deliberately does not
// stand in for actual password eligibility, fresh proof, token-vault deletion,
// session effects, one-use consumption or the complete native unlink consumer.
func TestAccountUnlinkMutationStorage(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.accounts
 (tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 VALUES('tenant-a','owner','provider-link','configured-oidc','https://provider.example','synthetic-subject',
 sha256(convert_to(octet_length('configured-oidc')::text||':configured-oidc'||octet_length('https://provider.example')::text||':https://provider.example'||octet_length('synthetic-subject')::text||':synthetic-subject','UTF8')),1,1,true);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 VALUES('tenant-a','owner','provider-key',3,'identity/oauth',1,true),('tenant-a','owner','password-key',1,'identity/password',1,true);
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 VALUES('tenant-a','owner','provider-key','provider-link')`); err != nil {
		t.Fatal(err)
	}
	query := identity.AccountUnlinkQuery{TenantID: "tenant-a", UserID: "owner", AccountID: "provider-link"}
	change := identity.AccountUnlinkChange{TenantID: query.TenantID, UserID: query.UserID, AccountID: query.AccountID,
		ExpectedUserVersion: 1, ExpectedAccountVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}
	open := func(t *testing.T) (Work, pgx.Tx) {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
		t.Cleanup(cancel)
		tx, err := pool.Raw().Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(ctx) })
		w := Work{state: &workState{tx: tx, ctx: bounded, cancel: cancel, binding: identity.CommandBinding{TenantID: query.TenantID, UserID: query.UserID}, generation: 1}}
		if err := configureKernelWork(bounded, w); err != nil {
			t.Fatal(err)
		}
		return w, tx
	}
	apply := func(t *testing.T, w Work) (identity.AccountUnlinkMutation, error) {
		t.Helper()
		state, now, err := lockAccountUnlinkState(ctx, w, change)
		if err != nil {
			return identity.AccountUnlinkMutation{}, err
		}
		// Controlled storage-only eligibility; the full consumer must ask the
		// real password and factor owners rather than enabling reference rows.
		for i := range state.Access.Methods {
			state.Access.Methods[i].Usable = state.Access.Methods[i].Credential.ID == "password-key"
		}
		next, err := identity.ApplyAccountUnlink(state, change, now)
		if err != nil {
			return identity.AccountUnlinkMutation{}, w.fail(ctx, err)
		}
		return next, persistAccountUnlinkMutation(ctx, w, change, next)
	}
	read := func(t *testing.T) identity.AccountUnlinkState {
		t.Helper()
		state, err := repo.GetAccountUnlinkState(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := read(t)
	if before.Access.User.Version != 1 || before.CredentialVersion != 1 || before.SocialLinkVersion != 1 || len(before.Access.Methods) != 2 {
		t.Fatal("original unlink partition incomplete")
	}
	for _, m := range before.Access.Methods {
		if m.Usable {
			t.Fatal("reference read invented credential eligibility")
		}
	}
	t.Run("rollback-preserves-all-authority", func(t *testing.T) {
		w, tx := open(t)
		if _, err := apply(t, w); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		s := read(t)
		if s.Access.User.Version != 1 || s.CredentialVersion != 1 || s.SocialLinkVersion != 1 || len(s.Access.Accounts) != 1 || len(s.Access.Methods) != 2 {
			t.Fatal("provisional unlink escaped rollback")
		}
	})
	t.Run("atomic-tombstone-and-provider-retirement", func(t *testing.T) {
		w, tx := open(t)
		next, err := apply(t, w)
		if err != nil || !next.InvalidatesCredential || next.TombstoneVersion != 2 || next.SocialLinkVersion != 2 || next.CredentialVersion != 2 {
			t.Fatal("wrong proposed unlink transition", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		s := read(t)
		if s.Access.User.Version != 2 || s.CredentialVersion != 2 || s.SocialLinkVersion != 2 || len(s.Access.Accounts) != 0 || len(s.Access.Methods) != 1 || s.Access.Methods[0].Credential.ID != "password-key" {
			t.Fatal("committed unlink lost tombstone or independent password")
		}
		retired, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: query.TenantID, UserID: query.UserID, CredentialID: "provider-key"})
		if err != nil || retired.Enabled || retired.Credential.Version != 2 || retired.AuthorityVersion != 2 {
			t.Fatal("removed provider credential remained active or lost history", err)
		}
		password, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: query.TenantID, UserID: query.UserID, CredentialID: "password-key"})
		if err != nil || !password.Enabled || password.Credential.Version != 1 {
			t.Fatal("unlink retired independent password", err)
		}
	})
	t.Run("stale-repeat-cannot-advance-epochs", func(t *testing.T) {
		w, tx := open(t)
		_, err := apply(t, w)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || w.usable() == nil {
			t.Fatal("stale unlink applied twice or failure ignored", err)
		}
		_ = tx.Rollback(ctx)
		if s := read(t); s.Access.User.Version != 2 || s.SocialLinkVersion != 2 || s.CredentialVersion != 2 {
			t.Fatal("stale unlink advanced retained authority")
		}
	})
	for _, foreign := range []identity.AccountUnlinkQuery{
		{TenantID: "tenant-a", UserID: "other", AccountID: query.AccountID},
		{TenantID: "tenant-b", UserID: "owner", AccountID: query.AccountID},
	} {
		if _, err := repo.GetAccountUnlinkState(ctx, foreign); err == nil {
			t.Fatal("unlink state disclosed a foreign owner/tenant partition")
		}
	}
}
