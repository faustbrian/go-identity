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

// This exercises the real pending-phone CAS writer, not genuine authentication,
// OTP/delivery orchestration or public workflow admission. The complete phone
// consumer must prove those separate owners through their real public APIs.
func testPhoneEnrollmentPostgres(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant','phone-user','active',1),('tenant','phone-other','active',1);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,version,verification_state,verification_version,normalization_profile,normalization_version) VALUES('tenant','phone-other','occupied-phone','phone','+12025550124','',1,1,1,'identity.phone.e164-ascii-v1.metadata-v9.0.40',1)`); err != nil {
		t.Fatal(err)
	}
	domain, err := NewPhoneEnrollmentDomain(repo, PhoneEnrollmentDomainConfig{
		NormalizationProfile: phoneEnrollmentIntent().Change.NormalizationProfile, NormalizationVersion: 1,
		CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}, ReuseCooldown: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	query := identity.IdentifierQuery{TenantID: "tenant", UserID: "phone-user", MaximumIdentifiers: 128}
	for _, mode := range []string{"rollback", "collision", "stale-user", "stale-authority", "foreign-profile", "foreign-repository", "candidate-swap", "double-apply", "post-apply", "commit"} {
		t.Run(mode, func(t *testing.T) {
			before, err := repo.GetIdentifierState(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			intent := phoneEnrollmentIntent()
			intent.Change.TenantID, intent.Change.UserID = "tenant", "phone-user"
			intent.Change.ExpectedUserVersion, intent.Change.ExpectedAuthorityVersion = before.User.Version, before.AuthorityVersion
			intent.Change.CanonicalValue, intent.Change.DisplayValue = "+12025550123", ""
			selected := domain
			switch mode {
			case "collision":
				intent.Change.CanonicalValue = "+12025550124"
			case "stale-user":
				intent.Change.ExpectedUserVersion++
			case "stale-authority":
				intent.Change.ExpectedAuthorityVersion++
			case "foreign-profile":
				intent.Change.NormalizationVersion++
			case "foreign-repository":
				copy := *domain
				copy.repository = &Repository{}
				selected = &copy
			}
			fields, err := PhoneEnrollmentFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			binding := codecBinding()
			op := phoneEnrollmentOperation()
			binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			binding.TenantID, binding.UserID, binding.ActorID, binding.RecordID = "tenant", "phone-user", "phone-user", string(intent.Change.ID)
			binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			phase := phoneEnrollmentMapperFixture{intent: intent, domain: selected}
			feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}
			plan := &admittedKernelPlan{binding: binding, fingerprint: [32]byte{1}, feature: feature, subjectType: "identifier", lifecycle: &LifecyclePlan{EventType: "identifier.attached.v1", AfterVersion: 1}, audits: []AuditPlan{{Required: true, RetentionClass: "protected"}}, contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}, {descriptor: feature.Contributor, contributor: phase}}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: binding, generation: 1, feature: feature, subjectType: "identifier", lifecycle: &workLifecycle{plan: *plan.lifecycle}, execution: &domainExecution{reservation: &reservationState{plan: plan, journal: journalReservation{generation: 1}}}}}
			defer invalidateWork(w)
			err = preparePhoneEnrollment(bounded, w, command)
			denied := mode == "collision" || mode == "stale-user" || mode == "stale-authority" || mode == "foreign-profile" || mode == "foreign-repository"
			if denied {
				if err == nil || w.state.failed == nil {
					t.Fatal("unsafe phone candidate failed to poison Work")
				}
			} else {
				if err != nil {
					t.Fatal("prepare phone", err)
				}
				w.state.featureInvocation, w.state.featureApplying, w.state.featureApplyCommand = phase, true, &command
				expected := intent
				if mode == "candidate-swap" {
					expected.Change.CanonicalValue = "+12025550125"
				}
				guardErr := w.RequirePhoneEnrollmentCandidate(bounded, phase, command, expected)
				if mode == "candidate-swap" {
					if guardErr == nil || w.state.failed == nil {
						t.Fatal("swapped SMS destination admitted")
					}
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
					after, err := repo.GetIdentifierState(ctx, query)
					if err != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("candidate denial retained phone effects", err)
					}
					return
				}
				if guardErr != nil {
					t.Fatal("original pending candidate denied", guardErr)
				}
				// Preparing must not persist an identifier or bump epochs before the
				// native owner consumes the original proof and stages OTP/delivery.
				var pending int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id='tenant' AND user_id='phone-user'`).Scan(&pending); err != nil || pending != 0 {
					t.Fatal("prepare wrote phone prematurely", err)
				}
				if err := applyPhoneEnrollment(bounded, w); err != nil {
					t.Fatal("apply phone", err)
				}
				if mode == "double-apply" {
					if err := applyPhoneEnrollment(bounded, w); err == nil || w.state.failed == nil {
						t.Fatal("phone mutation applied twice")
					}
				}
				if mode == "post-apply" {
					if err := w.RequirePhoneEnrollmentCandidate(bounded, phase, command, intent); err == nil || w.state.failed == nil {
						t.Fatal("candidate authority reused after kernel mutation")
					}
				}
			}
			if mode == "commit" {
				err = tx.Commit(ctx)
			} else {
				err = tx.Rollback(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := repo.GetIdentifierState(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "commit" {
				if !reflect.DeepEqual(before, after) {
					t.Fatal("denial or rollback retained partial phone/epoch effects")
				}
				return
			}
			if len(after.Identifiers) != 1 || len(after.Verifications) != 1 || after.User.Version != before.User.Version+1 || after.AuthorityVersion != before.AuthorityVersion+1 {
				t.Fatal("phone attachment lost directory CAS")
			}
			i, v := after.Identifiers[0], after.Verifications[0]
			if i.ID != intent.Change.ID || i.Kind != identity.IdentifierPhone || i.CanonicalValue != "+12025550123" || i.Version != 1 || i.Verified || i.Primary || i.NormalizationProfile != intent.Change.NormalizationProfile || i.NormalizationVersion != 1 || v.Version != 1 || v.State != identity.VerificationPending || !v.VerifiedAt.IsZero() {
				t.Fatal("attachment changed identity or fabricated possession")
			}
		})
	}
	// Kernel evidence never reconstructs a committed receipt from today's
	// identifier. Even another subject occupying the original tenant/record ID
	// prevents a negative vote. Another tenant's record cannot affect this one.
	for _, c := range []struct {
		name, record, tenant string
		want                 RecoveryStatus
	}{
		{"absent", "never-attached", "tenant", RecoveryNotCommitted},
		{"original-present", "pending-phone", "tenant", RecoveryUnknown},
		{"foreign-subject-present", "occupied-phone", "tenant", RecoveryUnknown},
		{"foreign-tenant-only", "pending-phone", "other-tenant", RecoveryNotCommitted},
	} {
		t.Run("recovery-"+c.name, func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			binding := codecBinding()
			binding.TenantID, binding.UserID, binding.ActorID, binding.RecordID = identity.TenantID(c.tenant), "phone-user", "phone-user", c.record
			op := phoneEnrollmentOperation()
			binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: binding, generation: 1}}
			defer invalidateWork(w)
			recovery := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{descriptor: repo.Descriptor(), contributor: repo}, plan: &admittedKernelPlan{binding: binding, feature: feature}, active: true}}
			got, err := repo.RecoverParticipant(bounded, recovery)
			if err != nil || got != c.want {
				t.Fatal("kernel phone recovery changed evidence ownership", got, err)
			}
			recovery.state.active = false
			if got, err := repo.RecoverParticipant(bounded, recovery); err == nil || got != RecoveryUnknown {
				t.Fatal("returned recovery invocation remained usable")
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
