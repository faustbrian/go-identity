//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This verifies the sole directory writer in the populated-upgrade fixture.
// It does not replace genuine password proof/session/factor/risk admission or
// claim that a test participant is a usable public rename service.
func testUsernameRenamePostgres(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	q := identity.IdentifierQuery{TenantID: "tenant", UserID: "new-user", MaximumIdentifiers: 128}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=date_trunc('microseconds',clock_timestamp()) WHERE tenant_id='tenant' AND identifier_id='username'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,version,verification_state,verification_version,normalization_profile,normalization_version) VALUES('tenant','old-user','occupied-username','username','occupied','Occupied',1,1,1,'identity.username.latin-v1',1)`); err != nil {
		t.Fatal(err)
	}
	domain, err := NewUsernameRenameDomain(repo, UsernameRenameDomainConfig{NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}, ReuseCooldown: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"display", "canonical-rollback", "collision", "cooldown", "stale", "foreign-profile", "canonical"} {
		t.Run(mode, func(t *testing.T) {
			before, err := repo.GetIdentifierState(ctx, q)
			if err != nil || len(before.Identifiers) != 1 {
				t.Fatal("original username", err)
			}
			i, v := before.Identifiers[0], before.Verifications[0]
			change := identity.IdentifierChange{TenantID: q.TenantID, UserID: q.UserID, ID: i.ID, Action: identity.IdentifierRename, Kind: identity.IdentifierUsername, CanonicalValue: "successor", DisplayValue: "Successor", NormalizationProfile: i.NormalizationProfile, NormalizationVersion: i.NormalizationVersion, ExpectedUserVersion: before.User.Version, ExpectedAuthorityVersion: before.AuthorityVersion, ExpectedIdentifierVersion: i.Version, ExpectedVerificationVersion: v.Version}
			switch mode {
			case "display":
				change.CanonicalValue, change.DisplayValue = i.CanonicalValue, "RENAMED"
			case "collision":
				change.CanonicalValue, change.DisplayValue = "occupied", "Occupied"
			case "cooldown":
				change.CanonicalValue, change.DisplayValue = "strasse", "Straße"
			case "stale":
				change.ExpectedVerificationVersion++
			case "foreign-profile":
				change.NormalizationVersion++
			}
			intent := UsernameRenameIntent{Change: change}
			fields, err := UsernameRenameFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			b := codecBinding()
			op := usernameRenameOperation()
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.TenantID, b.UserID, b.ActorID, b.RecordID = q.TenantID, q.UserID, identity.ActorID(q.UserID), string(i.ID)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			phase := usernameRenameMapperFixture{intent: intent, domain: domain}
			feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}, Operation: op}
			plan := &admittedKernelPlan{binding: b, feature: feature, subjectType: "identifier", lifecycle: &LifecyclePlan{EventType: "identifier.updated.v1", BeforeVersion: i.Version, AfterVersion: i.Version + 1}, audits: []AuditPlan{{Required: true, RetentionClass: "protected"}}, contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}, {descriptor: feature.Contributor, contributor: phase}}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: b, generation: 1, feature: feature, subjectType: "identifier", lifecycle: &workLifecycle{plan: *plan.lifecycle}, execution: &domainExecution{reservation: &reservationState{plan: plan}}}}
			defer invalidateWork(w)
			err = prepareUsernameRename(bounded, w, command)
			denied := mode == "collision" || mode == "cooldown" || mode == "stale" || mode == "foreign-profile"
			if denied {
				if err == nil || w.state.failed == nil {
					t.Fatal("unsafe rename did not poison Work")
				}
			} else {
				if err != nil {
					t.Fatal("prepare rename", err)
				}
				if err := applyUsernameRename(bounded, w); err != nil {
					t.Fatal("apply rename", err)
				}
			}
			commit := mode == "display" || mode == "canonical"
			if commit {
				err = tx.Commit(ctx)
			} else {
				err = tx.Rollback(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := repo.GetIdentifierState(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			if !commit {
				if !reflect.DeepEqual(before, after) {
					t.Fatal("denial/rollback retained partial rename")
				}
				return
			}
			if after.User.Version != before.User.Version+1 || after.AuthorityVersion != before.AuthorityVersion+1 || len(after.Identifiers) != 1 || after.Identifiers[0].ID != i.ID || after.Identifiers[0].Version != i.Version+1 || after.Identifiers[0].CanonicalValue != change.CanonicalValue || after.Identifiers[0].DisplayValue != change.DisplayValue || after.Identifiers[0].NormalizationProfile != i.NormalizationProfile || after.Identifiers[0].NormalizationVersion != i.NormalizationVersion {
				t.Fatal("rename lost exact ownership/CAS/comparison identity")
			}
			var retirements int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifier_retirements WHERE command_id=$1`, string(b.CommandID)).Scan(&retirements); err != nil {
				t.Fatal(err)
			}
			if mode == "display" {
				if !after.Identifiers[0].Verified || after.Verifications[0] != v || retirements != 0 {
					t.Fatal("display-only edit revoked possession or retired the unchanged name")
				}
			} else {
				if after.Identifiers[0].Verified || after.Verifications[0].State != identity.VerificationPending || after.Verifications[0].Version != v.Version+1 || retirements != 1 {
					t.Fatal("canonical rename did not reset possession/retire predecessor")
				}
				var cooldown bool
				if err := pool.Raw().QueryRow(ctx, `SELECT extract(epoch FROM reuse_until-retired_at)=2592000 FROM identity.identifier_retirements WHERE command_id=$1`, string(b.CommandID)).Scan(&cooldown); err != nil || !cooldown {
					t.Fatal("old canonical cooldown not conserved", err)
				}
			}
		})
	}
	for _, name := range []string{"successor", "occupied", "strasse", "renamed", "available"} {
		query := UsernameQuery{TenantID: q.TenantID, CanonicalValue: name, NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1}
		available, err := domain.UsernameAvailable(ctx, query)
		if err != nil || available != (name == "available") {
			t.Fatal("advisory read ignored canonical occupancy or original cooldown", name, err)
		}
	}
	query := UsernameQuery{TenantID: q.TenantID, CanonicalValue: "available", NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1}
	for _, mode := range []string{"subject-override", "foreign-profile", "missing-key", "canceled"} {
		request, reader := query, domain
		requestCtx := ctx
		switch mode {
		case "subject-override":
			request.UserID = q.UserID
		case "foreign-profile":
			request.NormalizationVersion++
		case "missing-key":
			reader, err = NewUsernameRenameDomain(repo, UsernameRenameDomainConfig{NormalizationProfile: query.NormalizationProfile, NormalizationVersion: 1, CurrentIdentifierKeyVersion: 2, RetainedIdentifierKeys: map[uint32][32]byte{2: {2}}})
			if err != nil {
				t.Fatal(err)
			}
		case "canceled":
			var cancel context.CancelFunc
			requestCtx, cancel = context.WithCancel(ctx)
			cancel()
		}
		if available, err := reader.UsernameAvailable(requestCtx, request); err == nil || available {
			t.Fatal("advisory read promised availability with unavailable authority", mode)
		}
	}
}
