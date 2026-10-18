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

// This storage contract reuses the exact isolated populated-upgrade fixture.
// It proves username discovery and its native invocation fence, not a password
// comparison, verified-email admission or complete public session journey.
func testUsernameLookupPostgres(t *testing.T, ctx context.Context, pool *database.Pool, repository *Repository) {
	q := UsernameQuery{TenantID: "tenant", CanonicalValue: "renamed", NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1}
	original, err := repository.ResolveUsername(ctx, q)
	if err != nil || original.Suppressed || original.User.ID != "new-user" || original.Identifier.ID != "username" || original.Identifier.Verified || original.Verification.State != identity.VerificationPending {
		t.Fatal("original username primary selection failed", err)
	}
	for _, mode := range []string{"absent", "foreign-user", "foreign-tenant", "noncanonical", "foreign-profile", "foreign-version"} {
		t.Run(mode, func(t *testing.T) {
			query := q
			switch mode {
			case "absent":
				query.CanonicalValue = "absent"
			case "foreign-user":
				query.UserID = "old-user"
			case "foreign-tenant":
				query.TenantID = "other-tenant"
			case "noncanonical":
				query.CanonicalValue = "Straße"
			case "foreign-profile":
				query.NormalizationProfile = "identity.username.other-v1"
			case "foreign-version":
				query.NormalizationVersion++
			}
			result, err := repository.ResolveUsername(ctx, query)
			if err != nil || !result.Suppressed || result.User.ID != "" || result.Identifier.ID != "" || result.UserAuthorityVersion != 0 {
				t.Fatal("ineligible lookup disclosed selected identity", err)
			}
		})
	}
	_, command, plan := featurePlanFixture(t)
	feature, _ := command.Feature()
	native := &scopeFeatureParticipant{operations: []identity.FeatureOperation{feature.Operation}}
	plan.Feature.Contributor = native.Descriptor()
	for _, mode := range []string{"exact", "anonymous", "name-change", "binding-change", "unbound", "removed", "blocked", "identifier-epoch", "credential-epoch", "foreign-owner", "open-cursor", "identifier-lock"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			owned, cancel := context.WithCancel(ctx)
			defer cancel()
			b := feature.Binding
			b.TenantID, b.UserID = q.TenantID, original.User.ID
			expected := original
			expected.Query.UserID = b.UserID
			if mode == "anonymous" {
				b.UserID, b.AnonymousFlowID, expected.Query.UserID = "", "username-original-flow", ""
			}
			work := Work{state: &workState{ctx: owned, cancel: cancel, tx: tx, binding: b, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
			owner := native
			mutation := ""
			switch mode {
			case "name-change":
				mutation = `UPDATE identity.identifiers SET canonical_value='changed',version=version+1 WHERE tenant_id='tenant' AND identifier_id='username'`
			case "binding-change":
				mutation = `UPDATE identity.identifiers SET normalization_version=2 WHERE tenant_id='tenant' AND identifier_id='username'`
			case "unbound":
				mutation = `UPDATE identity.identifiers SET normalization_profile='',normalization_version=0 WHERE tenant_id='tenant' AND identifier_id='username'`
			case "removed":
				mutation = `DELETE FROM identity.identifiers WHERE tenant_id='tenant' AND identifier_id='username'`
			case "blocked":
				mutation = `UPDATE identity.users SET status='suspended' WHERE tenant_id='tenant' AND user_id='new-user'`
			case "identifier-epoch":
				mutation = `UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id='tenant' AND user_id='new-user'`
			case "credential-epoch":
				mutation = `UPDATE identity.users SET credential_version=credential_version+1 WHERE tenant_id='tenant' AND user_id='new-user'`
			case "foreign-owner":
				owner = &scopeFeatureParticipant{operations: native.operations}
			}
			if mutation != "" {
				if _, err := tx.Exec(ctx, mutation); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "open-cursor" {
				cursor, queryErr := work.Query(ctx, "SELECT 1")
				if queryErr != nil {
					t.Fatal(queryErr)
				}
				err = work.RequireUsername(ctx, owner, expected)
				cursor.Close()
			} else {
				err = work.RequireUsername(ctx, owner, expected)
			}
			allowed := mode == "exact" || mode == "anonymous" || mode == "identifier-lock"
			if allowed {
				if err != nil || work.state.binding != b {
					t.Fatal("original username fence denied or retargeted command", err)
				}
			} else if err == nil || work.state.failed == nil {
				t.Fatal("changed username or invalid invocation did not poison Work", err)
			}
			if mode == "identifier-lock" {
				writer, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				bounded, stop := context.WithTimeout(ctx, 30*time.Millisecond)
				_, err = writer.Exec(bounded, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id='tenant' AND identifier_id='username'`)
				stop()
				if rollbackErr := writer.Rollback(ctx); rollbackErr != nil && !writer.Conn().IsClosed() {
					t.Fatal("owned contending transaction cleanup", rollbackErr)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("username fence did not retain its identifier lock", err)
				}
			}
		})
	}
}
