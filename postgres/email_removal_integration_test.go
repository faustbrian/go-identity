//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This is the directory owner's SQL boundary, deliberately not a proof of
// public password/factor/capability/session admission. Those real owners belong
// in the composed consumer journey. No fixture participant writes kernel rows.
func testNativeEmailRemovalStorage(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, policy identifierMutationPolicy) {
	t.Helper()
	for _, mode := range []string{"preserve-primary", "last-verified", "stale", "rollback", "cascade-policy-conflict", "commit"} {
		t.Run(mode, func(t *testing.T) {
			user, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a',$1,'active',1)`, string(user)); err != nil {
				t.Fatal(err)
			}
			if mode == "commit" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=7 WHERE tenant_id='tenant-a' AND user_id=$1`, string(user)); err != nil {
					t.Fatal(err)
				}
			}
			for index, id := range []string{"remove-" + string(user), "keep-" + string(user)} {
				verified := index == 0 || mode != "last-verified"
				state := 1
				var at any
				if verified {
					state, at = 2, time.Now().UTC().Truncate(time.Microsecond)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('tenant-a',$1,$2,'email',$3,$4,$5,2,$6,3,$7)`, string(user), id, id+"@example.test", verified, index == 0, state, at); err != nil {
					t.Fatal(err)
				}
			}
			before, err := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: "tenant-a", UserID: identity.UserID(user), MaximumIdentifiers: 128})
			if err != nil {
				t.Fatal(err)
			}
			b := codecBinding()
			op := emailRemovalOperation()
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.TenantID, b.UserID, b.ActorID, b.RecordID = "tenant-a", identity.UserID(user), identity.ActorID(user), "remove-"+string(user)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			i := EmailRemovalIntent{Change: identity.IdentifierChange{
				TenantID: b.TenantID, UserID: b.UserID, ID: identity.IdentifierID(b.RecordID), Action: identity.IdentifierRemove,
				ExpectedUserVersion: before.User.Version, ExpectedAuthorityVersion: before.AuthorityVersion,
				ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3,
			}, ComparisonProfile: "email-v1", Reason: "user-requested", LeavePrimaryUnassigned: mode != "preserve-primary"}
			if mode == "stale" {
				i.Change.ExpectedVerificationVersion++
			}
			fields, err := EmailRemovalFields(i)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			cascade, err := freezeIdentifierRemovalCascade(removalCascadeConfig())
			if err != nil {
				t.Fatal(err)
			}
			phase := emailRemovalMapperFixture{intent: i, domain: &EmailRemovalDomain{directory: &EmailAttachmentDomain{repository: repo, comparison: "email-v1", reuse: policy}, cascade: cascade}}
			feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: op}
			plan := &admittedKernelPlan{binding: b, feature: feature, subjectType: "identifier", lifecycle: &LifecyclePlan{EventType: "identifier.removed.v1", BeforeVersion: 2, AfterVersion: 3}, audits: []AuditPlan{{Required: true, RetentionClass: "protected"}}, contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}, {descriptor: feature.Contributor, contributor: phase}}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: b, generation: 1, feature: feature, subjectType: "identifier", lifecycle: &workLifecycle{plan: *plan.lifecycle}, execution: &domainExecution{reservation: &reservationState{plan: plan}}}}
			defer invalidateWork(w)
			err = prepareEmailRemoval(bounded, w, command)
			denied := mode == "last-verified" || mode == "stale" || mode == "preserve-primary"
			if denied {
				if err == nil || w.usable() == nil {
					t.Fatal("unsafe removal did not poison Work")
				}
			} else {
				if err != nil {
					t.Fatal("prepare removal", err)
				}
				if err := applyEmailRemoval(bounded, w); err != nil {
					t.Fatal("apply removal", err)
				}
				// The coordinator creates these claims in real execution. This
				// storage-level fixture only supplies original FK ownership; it
				// does not stand in for native proof or a complete consumer journey.
				key, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Exec(bounded, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, key, string(b.TenantID), b.OperationID, make([]byte, 32), []byte{1}); err != nil {
					t.Fatal(err)
				}
				if _, err := w.Exec(bounded, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, key, string(b.TenantID), b.OperationID); err != nil {
					t.Fatal(err)
				}
				now, err := w.DatabaseTime(bounded)
				if err != nil || w.StageLifecycle(0, now) != nil {
					t.Fatal("original lifecycle staging", err)
				}
				if mode == "cascade-policy-conflict" {
					if _, err := w.Exec(bounded, `INSERT INTO identity.status_policies(tenant_id,policy_version,definition) VALUES($1,101,$2)`, string(b.TenantID), []byte{1}); err != nil {
						t.Fatal(err)
					}
				}
				err = admitIdentifierRemovalCascade(bounded, w)
				if mode == "cascade-policy-conflict" {
					if err == nil || w.usable() == nil {
						t.Fatal("changed retained cascade policy admitted")
					}
				} else if err != nil {
					t.Fatal("cascade admission", err)
				}
			}
			if mode == "commit" {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "commit" {
				if after.User.Version != before.User.Version+1 || after.AuthorityVersion != before.AuthorityVersion+1 || len(after.Identifiers) != 1 || string(after.Identifiers[0].ID) != "keep-"+string(user) || after.Identifiers[0].Primary || !after.Identifiers[0].Verified || after.Identifiers[0].Version != 2 || after.Verifications[0].Version != 3 {
					t.Fatal("removal changed surviving identity or lost authority invalidation")
				}
				var removed bool
				var version, verification string
				if err := pool.Raw().QueryRow(ctx, `SELECT removed,record_version::text,verification_version::text FROM identity.identifier_retirements WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND command_id=$4`, string(b.TenantID), string(b.UserID), b.RecordID, string(b.CommandID)).Scan(&removed, &version, &verification); err != nil || !removed || version != "3" || verification != "4" {
					t.Fatal("missing exact privacy-safe retired successor", err)
				}
				var id, kind, dimension, target, state, holdVersion string
				var held bool
				var consumers int
				if err := pool.Raw().QueryRow(ctx, `SELECT c.cascade_id,c.cascade_kind,c.authority_dimension,c.identifier_id,c.state,c.legal_hold,c.legal_hold_version::text,(SELECT count(*) FROM identity.status_consumers s WHERE s.tenant_id=c.tenant_id AND s.cascade_id=c.cascade_id AND s.state='pending') FROM identity.status_cascades c WHERE c.command_id=$1`, string(b.CommandID)).Scan(&id, &kind, &dimension, &target, &state, &held, &holdVersion, &consumers); err != nil || id != string(w.state.emailRemoval.cascade.CascadeID) || kind != "lifecycle.cascade.identifier_remove" || dimension != "identifier" || target != b.RecordID || state != "pending" || !held || holdVersion != "7" || consumers != 10 {
					t.Fatal("cascade lost exact scope, hold or pending consumer manifest", err)
				}
				if w.state.lifecycle.record.CascadeID != w.state.emailRemoval.cascade.CascadeID || w.state.lifecycle.record.CascadeGeneration != 1 {
					t.Fatal("trigger did not bind the actual admission")
				}
			} else if after.User != before.User || after.AuthorityVersion != before.AuthorityVersion || len(after.Identifiers) != 2 {
				t.Fatal("denial/rollback left a removal prefix")
			}
			if mode != "commit" {
				var cascades, consumers, retirements int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.status_cascades WHERE command_id=$1),(SELECT count(*) FROM identity.status_consumers WHERE cascade_id IN (SELECT cascade_id FROM identity.status_cascades WHERE command_id=$1)),(SELECT count(*) FROM identity.identifier_retirements WHERE command_id=$1)`, string(b.CommandID)).Scan(&cascades, &consumers, &retirements); err != nil || cascades != 0 || consumers != 0 || retirements != 0 {
					t.Fatal("denial/rollback retained cascade or retirement prefix", err)
				}
			}
		})
	}
}
