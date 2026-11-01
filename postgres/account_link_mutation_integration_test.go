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

// This exercises the private identity storage phase, not provider proof,
// command reservation, session admission or the public social-login journey.
func TestAccountLinkMutationStorage(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	change := identity.AccountLinkChange{Mode: identity.AccountLinkExplicit,
		Account:             identity.Account{ID: "new-link", TenantID: "tenant-a", UserID: "owner", Provider: "configured-oidc", Issuer: "https://provider.example", Subject: "synthetic-subject", Version: 1},
		ExpectedUserVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}
	change.Method = &identity.LoginMethod{AccountID: change.Account.ID, Credential: identity.CredentialRef{ID: "new-provider", TenantID: "tenant-a", UserID: "owner", Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, Usable: true}
	open := func(t *testing.T) (Work, pgx.Tx) {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
		t.Cleanup(cancel)
		tx, err := pool.Raw().Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(ctx) })
		w := Work{state: &workState{tx: tx, ctx: bounded, cancel: cancel, binding: identity.CommandBinding{TenantID: "tenant-a", UserID: "owner"}, generation: 1}}
		if err := configureKernelWork(bounded, w); err != nil {
			t.Fatal(err)
		}
		return w, tx
	}
	apply := func(t *testing.T, w Work, selected identity.AccountLinkChange) (identity.AccountLinkMutation, error) {
		t.Helper()
		state, now, err := lockAccountLinkState(ctx, w, selected)
		if err != nil {
			return identity.AccountLinkMutation{}, err
		}
		mutation, err := identity.ApplyAccountLink(state, selected, now)
		if err != nil {
			return identity.AccountLinkMutation{}, w.fail(ctx, err)
		}
		if err := persistAccountLinkMutation(ctx, w, selected, mutation); err != nil {
			return identity.AccountLinkMutation{}, err
		}
		return mutation, nil
	}
	read := func(t *testing.T) identity.AccountLinkState {
		t.Helper()
		state, err := repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: change.Account, Mode: change.Mode})
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	t.Run("all-effects-rollback", func(t *testing.T) {
		w, tx := open(t)
		if _, err := apply(t, w, change); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		s := read(t)
		if s.Access.User.Version != 1 || s.CredentialVersion != 1 || s.RecordVersion != 0 || len(s.Access.Accounts) != 0 || len(s.Access.Methods) != 0 {
			t.Fatal("provisional link leaked after rollback")
		}
	})
	t.Run("atomic-account-credential-and-epochs", func(t *testing.T) {
		w, tx := open(t)
		next, err := apply(t, w, change)
		if err != nil {
			t.Fatal(err)
		}
		if next.Access.User.Version != 2 || next.CredentialVersion != 2 || next.SocialLinkVersion != 2 || !next.AddsCredential {
			t.Fatal("wrong proposed authority transitions")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		s := read(t)
		if s.Access.User.Version != 2 || s.CredentialVersion != 2 || s.RecordVersion != 1 || s.SocialLinkVersion != 2 || len(s.Access.Accounts) != 1 || s.Access.Accounts[0] != change.Account || len(s.Access.Methods) != 1 || s.Access.Methods[0].Credential != change.Method.Credential || s.Access.Methods[0].AccountID != change.Account.ID {
			t.Fatal("link, association or authority increment missing")
		}
		record, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: "tenant-a", UserID: "owner", CredentialID: change.Method.Credential.ID})
		if err != nil || !record.Enabled || record.AuthorityVersion != 2 {
			t.Fatal("linked provider credential not persisted", err)
		}
	})
	t.Run("stale-intent-and-duplicate-deny", func(t *testing.T) {
		w, tx := open(t)
		if _, err := apply(t, w, change); err == nil || w.usable() == nil {
			t.Fatal("stale link admitted or denial ignored")
		}
		_ = tx.Rollback(ctx)
		if s := read(t); s.Access.User.Version != 2 || s.CredentialVersion != 2 || len(s.Access.Accounts) != 1 {
			t.Fatal("denial changed link")
		}
	})
	t.Run("data-only-link-preserves-credential-authority", func(t *testing.T) {
		selected := change
		selected.Account.ID, selected.Account.Subject = "metadata-only", "other-subject"
		selected.ExpectedUserVersion, selected.ExpectedCredentialVersion, selected.Method = 2, 2, nil
		w, tx := open(t)
		next, err := apply(t, w, selected)
		if err != nil {
			t.Fatal(err)
		}
		if next.AddsCredential || next.CredentialVersion != 2 || next.Access.User.Version != 3 {
			t.Fatal("data-only link changed credential epoch")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if s := read(t); s.Access.User.Version != 3 || s.CredentialVersion != 2 || len(s.Access.Methods) != 1 || len(s.Access.Accounts) != 2 {
			t.Fatal("existing credential not conserved")
		}
	})
	t.Run("foreign-owner-collision", func(t *testing.T) {
		selected := change
		selected.Account.ID, selected.Account.UserID = "foreign", "other"
		selected.Method = nil
		w, tx := open(t)
		w.state.binding.UserID = "other"
		_, err := apply(t, w, selected)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || w.usable() == nil {
			t.Fatal("provider subject transferred to another user", err)
		}
		_ = tx.Rollback(ctx)
	})
	t.Run("retired-credential-id-collision-rolls-back-prefix", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','owner','retired-id',1,'identity/password',9,false)`); err != nil {
			t.Fatal(err)
		}
		selected := change
		method := *change.Method
		selected.Account.ID, selected.Account.Subject = "failed-link", "unused-subject"
		selected.ExpectedUserVersion, selected.ExpectedCredentialVersion = 3, 2
		method.AccountID, method.Credential.ID = selected.Account.ID, "retired-id"
		selected.Method = &method
		w, tx := open(t)
		_, err := apply(t, w, selected)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || w.usable() == nil {
			t.Fatal("retired credential identity was resurrected", err)
		}
		_ = tx.Rollback(ctx)
		s := read(t)
		if s.Access.User.Version != 3 || s.CredentialVersion != 2 || len(s.Access.Accounts) != 2 || len(s.Access.Methods) != 1 {
			t.Fatal("credential conflict leaked a partial user/account update")
		}
		var enabled bool
		var version string
		if err := pool.Raw().QueryRow(ctx, `SELECT enabled,version::text FROM identity.credential_references WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='retired-id'`).Scan(&enabled, &version); err != nil || enabled || version != "9" {
			t.Fatal("retired credential changed", err)
		}
	})
	t.Run("exact-tombstone-relink-conserves-old-credential", func(t *testing.T) {
		// This is retained storage setup, not proof of the unlink workflow.
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.accounts SET linked=false,version=2,social_link_version=3 WHERE tenant_id='tenant-a' AND account_id='new-link';
 UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='new-provider';
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 SELECT 'tenant-a','owner','old-provider-'||i::text,3,'identity/oauth',1,false FROM generate_series(1,127) i;
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 SELECT 'tenant-a','owner','old-provider-'||i::text,'new-link' FROM generate_series(1,127) i;
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','owner','resident-password',1,'identity/password',1,true);
 UPDATE identity.users SET version=4,credential_version=3 WHERE tenant_id='tenant-a' AND user_id='owner'`); err != nil {
			t.Fatal(err)
		}
		selected := change
		selected.Account.Version = 3
		selected.ExpectedUserVersion, selected.ExpectedCredentialVersion = 4, 3
		selected.ExpectedAccountVersion, selected.ExpectedSocialLinkVersion = 2, 3
		method := *change.Method
		method.Credential.ID = "new-provider-successor"
		selected.Method = &method
		w, tx := open(t)
		next, err := apply(t, w, selected)
		if err != nil || next.Account.Version != 3 || next.SocialLinkVersion != 4 || next.CredentialVersion != 4 {
			t.Fatal("exact retained link could not advance", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		s := read(t)
		if s.RecordVersion != 3 || s.SocialLinkVersion != 4 || s.Access.User.Version != 5 || s.CredentialVersion != 4 || len(s.Access.Accounts) != 2 {
			t.Fatal("relink reset history or wrong aggregate fence")
		}
		if len(s.Access.Methods) != 2 || s.Access.Methods[0].Credential.ID != "new-provider-successor" || s.Access.Methods[1].Credential.ID != "resident-password" {
			t.Fatal("relink reintroduced retired credential history into current methods")
		}
		var retired int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.credential_references WHERE tenant_id='tenant-a' AND user_id='owner' AND kind=3 AND NOT enabled`).Scan(&retired); err != nil || retired != 128 {
			t.Fatal("relink discarded non-reassignable credential tombstones", err)
		}
		old, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: "tenant-a", UserID: "owner", CredentialID: "new-provider"})
		if err != nil || old.Enabled || old.Credential.Version != 1 {
			t.Fatal("relink revived its previous credential", err)
		}
	})
	t.Run("immutable-tombstone-tuple", func(t *testing.T) {
		selected := change
		selected.Account.Subject = "replacement-subject"
		w, tx := open(t)
		if _, err := apply(t, w, selected); err == nil || w.usable() == nil {
			t.Fatal("stable account ID was reassigned to another provider identity")
		}
		_ = tx.Rollback(ctx)
	})
	t.Run("blocked-user-denies", func(t *testing.T) {
		w, tx := open(t)
		if _, err := w.Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id='tenant-a' AND user_id='owner'`); err != nil {
			t.Fatal(err)
		}
		selected := change
		selected.Account.ID, selected.Account.Subject = "blocked-link", "blocked-subject"
		selected.ExpectedUserVersion, selected.ExpectedCredentialVersion, selected.Method = 5, 4, nil
		_, err := apply(t, w, selected)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || w.usable() == nil {
			t.Fatal("blocked user linked another identity", err)
		}
		_ = tx.Rollback(ctx)
	})
	t.Run("concurrent-subject-ownership-is-unique", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','race-a','active',1),('tenant-a','race-b','active',1)`); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		done := make(chan error, 2)
		for _, user := range []identity.UserID{"race-a", "race-b"} {
			selected := change
			selected.Method = nil
			selected.Account.UserID, selected.Account.ID, selected.Account.Subject = user, identity.AccountID(user), "one-raced-subject"
			go func() {
				<-start
				bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				done <- func() error {
					tx, err := pool.Raw().Begin(bounded)
					if err != nil {
						return err
					}
					defer tx.Rollback(bounded)
					w := Work{state: &workState{tx: tx, ctx: bounded, cancel: cancel, binding: identity.CommandBinding{TenantID: "tenant-a", UserID: user}, generation: 1}}
					if err := configureKernelWork(bounded, w); err != nil {
						return err
					}
					state, now, err := lockAccountLinkState(bounded, w, selected)
					if err != nil {
						return err
					}
					next, err := identity.ApplyAccountLink(state, selected, now)
					if err != nil {
						return err
					}
					if err := persistAccountLinkMutation(bounded, w, selected, next); err != nil {
						return err
					}
					return tx.Commit(bounded)
				}()
			}()
		}
		close(start)
		committed, conflicts := 0, 0
		for range 2 {
			err := <-done
			var conflict identity.ConflictError
			switch {
			case err == nil:
				committed++
			case errors.As(err, &conflict):
				conflicts++
			default:
				t.Error("unexpected raced link failure", err)
			}
		}
		if committed != 1 || conflicts != 1 {
			t.Fatal("racing owners did not produce one link and one conflict")
		}
		var linked, advanced int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.accounts WHERE tenant_id='tenant-a' AND subject='one-raced-subject' AND linked`).Scan(&linked); err != nil || linked != 1 {
			t.Fatal("subject ownership is not unique", err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users WHERE tenant_id='tenant-a' AND user_id IN ('race-a','race-b') AND version=2 AND credential_version=1`).Scan(&advanced); err != nil || advanced != 1 {
			t.Fatal("losing owner was mutated or data-only race changed credentials", err)
		}
	})
}
