//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Use the existing isolated database and real owned migrations. These tests
// prove primary resolution/fencing, not complete public OTP Send composition.
func testRecipientPostgres(t *testing.T, ctx context.Context, pool *database.Pool) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native := &scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}
	plan.Feature.Contributor = native.Descriptor()
	b := spec.Binding
	// Keep this fixture separate from the sibling authority cases, including
	// when the parent test runs its complete subtest set.
	b.UserID = "recipient-user"
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(b.UserID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'recipient-id','email','Canonical@example.test','Display@example.test',true,true,1,2,1,clock_timestamp())`, string(b.TenantID), string(b.UserID)); err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query := RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	original, err := repo.ResolveRecipient(ctx, query)
	if err != nil || original.Suppressed || original.User.ID != b.UserID || original.Identifier.DisplayValue != "Display@example.test" {
		t.Fatal("primary recipient not selected", err)
	}
	t.Run("phone", func(t *testing.T) {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'recipient-phone','phone','+358401234567',true,true,1,2,1,clock_timestamp())`, string(b.TenantID), string(b.UserID)); err != nil {
			t.Fatal(err)
		}
		q := query
		q.Kind, q.CanonicalValue = identity.IdentifierPhone, "+358401234567"
		got, err := repo.ResolveRecipient(ctx, q)
		if err != nil || got.Suppressed || got.Identifier.ID != "recipient-phone" || got.Identifier.Kind != identity.IdentifierPhone || got.Identifier.CanonicalValue != q.CanonicalValue {
			t.Fatal("phone canonical recipient not selected", err)
		}
	})
	for _, mode := range []string{"absent", "foreign-subject", "foreign-tenant", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			q := query
			switch mode {
			case "absent":
				q.CanonicalValue = "absent@example.test"
			case "foreign-subject":
				q.UserID = "another-subject"
			case "foreign-tenant":
				q.TenantID = "another-tenant"
			case "noncanonical":
				q.CanonicalValue = "canonical@example.test"
			}
			got, err := repo.ResolveRecipient(ctx, q)
			if err != nil || !got.Suppressed || got.User.ID != "" || got.Identifier.ID != "" || got.UserAuthorityVersion != 0 {
				t.Fatal("suppression disclosed recipient", err)
			}
		})
	}
	for _, mode := range []string{"exact", "stale-identifier", "stale-user", "foreign-owner", "identifier-lock", "blocked", "removed", "verification-changed", "address-changed", "open-cursor", "anonymous"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			owned, cancel := context.WithCancel(ctx)
			defer cancel()
			w := Work{state: &workState{ctx: owned, cancel: cancel, tx: tx, binding: b, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
			expected := original
			owner := native
			originalBinding := b
			if mode == "anonymous" {
				originalBinding.UserID, originalBinding.AnonymousFlowID = "", "recipient-flow"
				expected.Query.UserID = ""
				registration := *plan.Feature
				registration.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
				owner = &scopeFeatureParticipant{operations: []identity.FeatureOperation{registration.Operation}}
				w.state.binding, w.state.feature, w.state.featureInvocation = originalBinding, &registration, owner
			}
			mutation := ""
			switch mode {
			case "stale-identifier":
				expected.Identifier.Version++
			case "stale-user":
				expected.UserAuthorityVersion++
			case "foreign-owner":
				owner = &scopeFeatureParticipant{operations: native.operations}
			case "blocked":
				mutation = `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`
			case "removed":
				mutation = `DELETE FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2`
			case "verification-changed":
				mutation = `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL,verification_version=verification_version+1 WHERE tenant_id=$1 AND user_id=$2`
			case "address-changed":
				mutation = `UPDATE identity.identifiers SET canonical_value='changed@example.test',version=version+1 WHERE tenant_id=$1 AND user_id=$2`
			}
			if mutation != "" {
				if _, err := tx.Exec(ctx, mutation, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "open-cursor" {
				cursor, queryErr := w.Query(ctx, "SELECT 1")
				if queryErr != nil {
					t.Fatal(queryErr)
				}
				err = w.RequireRecipient(ctx, owner, expected)
				cursor.Close()
			} else {
				err = w.RequireRecipient(ctx, owner, expected)
			}
			if mode == "exact" || mode == "identifier-lock" || mode == "anonymous" {
				if err != nil {
					t.Fatal("original recipient fence denied", err)
				}
				if w.state.binding != originalBinding {
					t.Fatal("recipient retargeted original command")
				}
				if mode == "identifier-lock" {
					// Do not leave a timed-out autocommit writer queued behind
					// the lock: a late server completion could alter later cases.
					writer, err := pool.Raw().Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					bounded, stop := context.WithTimeout(ctx, 30*time.Millisecond)
					_, err = writer.Exec(bounded, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND identifier_id='recipient-id'`, string(b.TenantID))
					stop()
					if rollbackErr := writer.Rollback(ctx); rollbackErr != nil && !writer.Conn().IsClosed() {
						t.Fatal(rollbackErr)
					}
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("identifier fence did not retain lock", err)
					}
				}
			} else {
				if err == nil || w.state.failed == nil {
					t.Fatal("ignored recipient denial did not poison work")
				}
				if _, err := w.Exec(ctx, "SELECT 1"); err == nil {
					t.Fatal("poisoned recipient work permitted effects")
				}
			}
		})
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	for _, mode := range []string{"exact", "identifier-version", "verification-version", "user-epoch", "identifier-epoch", "credential-epoch", "kind", "absent", "reassigned", "removed", "blocked", "verification-revoked", "foreign-owner"} {
		t.Run("verified-identifier/"+mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			owned, stop := context.WithCancel(ctx)
			defer stop()
			w := Work{state: &workState{ctx: owned, cancel: stop, tx: tx, binding: b, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
			expected := VerifiedIdentifierAdmission{IdentifierID: original.Identifier.ID, Kind: original.Identifier.Kind, IdentifierVersion: original.Identifier.Version, VerificationVersion: original.Verification.Version, User: UserAuthorityAdmission{UserAuthorityVersion: original.UserAuthorityVersion, IdentifierAuthorityVersion: original.IdentifierAuthorityVersion, CredentialAuthorityVersion: original.CredentialAuthorityVersion}}
			owner := native
			mutation := ""
			switch mode {
			case "identifier-version":
				expected.IdentifierVersion++
			case "verification-version":
				expected.VerificationVersion++
			case "user-epoch":
				expected.User.UserAuthorityVersion++
			case "identifier-epoch":
				expected.User.IdentifierAuthorityVersion++
			case "credential-epoch":
				expected.User.CredentialAuthorityVersion++
			case "kind":
				expected.Kind = identity.IdentifierPhone
			case "absent":
				expected.IdentifierID = "absent"
			case "foreign-owner":
				owner = &scopeFeatureParticipant{operations: native.operations}
			case "reassigned":
				if _, err := tx.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'other-recipient','active',1)`, string(b.TenantID)); err != nil {
					t.Fatal(err)
				}
				mutation = `UPDATE identity.identifiers SET user_id='other-recipient' WHERE tenant_id=$1 AND user_id=$2`
			case "removed":
				mutation = `DELETE FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2`
			case "blocked":
				mutation = `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`
			case "verification-revoked":
				mutation = `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1 WHERE tenant_id=$1 AND user_id=$2`
			}
			if mutation != "" {
				if _, err := tx.Exec(ctx, mutation, string(b.TenantID), string(b.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			err = w.RequireVerifiedIdentifier(ctx, owner, expected)
			if mode == "exact" {
				if err != nil {
					t.Fatal("original identifier denied", err)
				}
			} else if err == nil || w.state.failed == nil {
				t.Fatal("changed original authority accepted or failed to poison Work")
			}
		})
	}
	got, err := repo.ResolveRecipient(cancelled, query)
	if !errors.Is(err, context.Canceled) || got.Identifier.ID != "" {
		t.Fatal("cancellation became absence or usable recipient", err)
	}
}
