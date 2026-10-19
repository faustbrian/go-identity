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

// This synthetic OTP admission checks storage ordering only. It is deliberately
// not proof of code possession, authentication or native phone orchestration.
type phoneChangeStorageOTPProbe struct {
	otpExecutionProbe
	intent PhoneChangeIntent
	checks int
	deny   bool
}

func (p *phoneChangeStorageOTPProbe) CheckOTP(ctx context.Context, w OTPApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	p.checks++
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND kind='phone' AND verified AND canonical_value=$4 AND version=$5::numeric AND verification_version=$6::numeric)`, string(b.Command.TenantID), string(b.Command.UserID), b.Command.RecordID, p.intent.PreviousNumber, p.intent.Change.ExpectedIdentifierVersion, p.intent.Change.ExpectedVerificationVersion)
	if err != nil {
		return err
	}
	defer rows.Close()
	var original bool
	if !rows.Next() || rows.Scan(&original) != nil || rows.Next() || rows.Err() != nil || !original || p.deny {
		return identity.ForbiddenError{}
	}
	return nil
}

// Exercise the real CAS, retirement and lifecycle-cascade writer. Complete
// native/HTTP consumer tests must independently prove the genuine OTP, action
// proof, session/recovery admission and orchestration in the enclosing Work.
func testPhoneChangePostgres(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	query := identity.IdentifierQuery{TenantID: "tenant", UserID: "phone-user", MaximumIdentifiers: 128}
	before, err := repo.GetIdentifierState(ctx, query)
	if err != nil || len(before.Identifiers) != 1 || !before.Identifiers[0].Verified {
		t.Fatal("verified predecessor fixture missing", err)
	}
	domain, err := NewPhoneChangeDomain(repo, PhoneChangeDomainConfig{Directory: PhoneEnrollmentDomainConfig{
		NormalizationProfile: before.Identifiers[0].NormalizationProfile, NormalizationVersion: 1,
		CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}, ReuseCooldown: 30 * 24 * time.Hour,
	}, Cascade: removalCascadeConfig()})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stale", "foreign-number", "occupied-number", "foreign-repository", "foreign-input-invocation", "missing-otp", "otp-denial", "rollback", "cascade-policy-conflict", "commit"} {
		t.Run(mode, func(t *testing.T) {
			i := phoneChangeIntent()
			i.Change.TenantID, i.Change.UserID, i.Change.ID = query.TenantID, query.UserID, before.Identifiers[0].ID
			i.Change.ExpectedUserVersion, i.Change.ExpectedAuthorityVersion = before.User.Version, before.AuthorityVersion
			i.Change.ExpectedIdentifierVersion, i.Change.ExpectedVerificationVersion = before.Identifiers[0].Version, before.Verifications[0].Version
			i.Change.NormalizationProfile, i.Change.NormalizationVersion = before.Identifiers[0].NormalizationProfile, before.Identifiers[0].NormalizationVersion
			i.PreviousNumber, i.PreviousNormalizationProfile = before.Identifiers[0].CanonicalValue, i.Change.NormalizationProfile
			i.Change.CanonicalValue, i.Change.DisplayValue = "+12025550125", "+12025550125"
			switch mode {
			case "stale":
				i.Change.ExpectedVerificationVersion++
			case "foreign-number":
				i.PreviousNumber = "+12025550126"
			case "occupied-number":
				i.Change.CanonicalValue = "+12025550124"
			}
			fields, err := PhoneChangeFields(i)
			if err != nil {
				t.Fatal(err)
			}
			b, op := codecBinding(), phoneChangeOperation()
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.TenantID, b.UserID, b.ActorID, b.RecordID = query.TenantID, query.UserID, identity.ActorID(query.UserID), string(i.Change.ID)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			code, _ := auth.NewOneTimeCode("123456")
			command, err := identity.NewFeatureOneTimeCodeSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			owner := &phoneChangeMapperFixture{intent: i, domain: domain}
			if mode == "foreign-repository" {
				copy := *domain.state().directory
				copy.repository = &Repository{}
				state := &phoneChangeDomain{directory: &copy, cascade: domain.state().cascade}
				owner.domain = &PhoneChangeDomain{read: func() *phoneChangeDomain { return state }}
			}
			probe := &phoneChangeStorageOTPProbe{intent: i, deny: mode == "otp-denial"}
			feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}
			registry := &ContributorRegistry{state: &contributorRegistryState{}}
			coordinator := &Coordinator{registry: registry}
			plan := &admittedKernelPlan{registry: registry.state, binding: b, fingerprint: [32]byte{1}, feature: feature, subjectType: "identifier",
				lifecycle:    &LifecyclePlan{EventType: "identifier.changed.v1", BeforeVersion: i.Change.ExpectedIdentifierVersion, AfterVersion: i.Change.ExpectedIdentifierVersion + 1},
				otp:          &OTPAttemptPlan{Mode: OTPConsume, ChallengeID: string(i.SendCommandID)},
				delivery:     &DeliveryPlan{Intents: []DeliveryIntentPlan{{Purpose: "identity.phone.change-notification", SubjectID: string(b.UserID)}}},
				audits:       []AuditPlan{{EventType: "identity.identifier.change", Required: true, RetentionClass: "standard"}},
				contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}, {descriptor: feature.Contributor, contributor: owner}, {descriptor: probe.Descriptor(), contributor: probe}}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, registry: registry.state, binding: b, generation: 1, feature: feature, subjectType: "identifier",
				lifecycle: &workLifecycle{plan: *plan.lifecycle}, otpCommand: &command,
				execution: &domainExecution{coordinator: coordinator, reservation: &reservationState{plan: plan}}}}
			defer invalidateWork(w)
			w.state.featureInvocation, w.state.featurePreparationCommand, w.state.featurePreparationPlan = owner, &command, plan
			if mode == "foreign-input-invocation" {
				other, err := identity.NewFeatureOneTimeCodeSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
				if err != nil {
					t.Fatal(err)
				}
				w.state.featurePreparationCommand = &other
			}
			err = w.RequirePhoneChangeTarget(bounded, owner, command)
			w.state.featureInvocation, w.state.featurePreparationCommand, w.state.featurePreparationPlan = nil, nil, nil
			if err == nil {
				err = preparePhoneChange(bounded, w, command)
			}
			denied := mode == "stale" || mode == "foreign-number" || mode == "occupied-number" || mode == "foreign-repository" || mode == "foreign-input-invocation"
			if denied {
				if err == nil || w.state.failed == nil {
					t.Fatal("unsafe replacement preparation admitted")
				}
			} else {
				if err != nil {
					t.Fatal("prepare replacement", err)
				}
				current, err := repo.GetIdentifierState(ctx, query)
				if err != nil || !reflect.DeepEqual(current, before) {
					t.Fatal("prepare published unproven new possession", err)
				}
				if mode == "missing-otp" {
					w.state.otpCommand = nil
				}
				err = applyPhoneChange(bounded, w)
				if mode == "missing-otp" || mode == "otp-denial" {
					if err == nil || w.state.failed == nil || w.state.phoneChange.applied {
						t.Fatal("missing/denying OTP retained replacement effects")
					}
				} else {
					if err != nil || probe.checks != 1 || !w.state.phoneChange.applied {
						t.Fatal("replacement skipped current OTP fence or persistence", err)
					}
					// Only FK ownership for the storage seam, not a fabricated
					// coordinator outcome or genuine authentication credential.
					key, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
					if _, err := w.Exec(bounded, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, key, string(b.TenantID), b.OperationID, make([]byte, 32), []byte{1}); err != nil {
						t.Fatal(err)
					}
					if _, err := w.Exec(bounded, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, key, string(b.TenantID), b.OperationID); err != nil {
						t.Fatal(err)
					}
					now, err := w.DatabaseTime(bounded)
					if err != nil || w.StageLifecycle(0, now) != nil {
						t.Fatal("replacement lifecycle staging", err)
					}
					if mode == "cascade-policy-conflict" {
						if _, err := w.Exec(bounded, `INSERT INTO identity.status_policies(tenant_id,policy_version,definition) VALUES($1,101,$2)`, string(b.TenantID), []byte{1}); err != nil {
							t.Fatal(err)
						}
					}
					err = admitIdentifierRemovalCascade(bounded, w)
					if mode == "cascade-policy-conflict" {
						if err == nil || w.state.failed == nil {
							t.Fatal("changed cascade definition admitted")
						}
					} else if err != nil || w.state.phoneChange.cascade == nil || w.state.phoneChange.cascade.Kind != identity.IdentifierChangeCascade {
						t.Fatal("replacement lacks own pending change cascade", err)
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
			if mode != "commit" && !reflect.DeepEqual(before, after) {
				t.Fatal("replacement denial/rollback left partial directory effects")
			}
			var retirements, cascades, pending int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifier_retirements WHERE command_id=$1),(SELECT count(*) FROM identity.status_cascades WHERE command_id=$1 AND cascade_kind='lifecycle.cascade.identifier_change' AND trigger_event_type='identifier.changed.v1' AND state='pending'),(SELECT count(*) FROM identity.status_consumers WHERE cascade_id IN (SELECT cascade_id FROM identity.status_cascades WHERE command_id=$1) AND state='pending')`, string(b.CommandID)).Scan(&retirements, &cascades, &pending); err != nil {
				t.Fatal(err)
			}
			if mode == "commit" {
				if after.User.Version != before.User.Version+1 || after.AuthorityVersion != before.AuthorityVersion+1 || len(after.Identifiers) != 1 || after.Identifiers[0].CanonicalValue != i.Change.CanonicalValue || !after.Identifiers[0].Verified || after.Identifiers[0].Version != before.Identifiers[0].Version+1 || after.Verifications[0].Version != before.Verifications[0].Version+1 || retirements != 1 || cascades != 1 || pending != 10 {
					t.Fatal("committed replacement lost exact successor, retirement or pending cascade")
				}
				for _, target := range []struct {
					number     string
					suppressed bool
				}{{i.PreviousNumber, true}, {i.Change.CanonicalValue, false}} {
					recipient, err := repo.ResolveRecipient(ctx, RecipientQuery{TenantID: query.TenantID, UserID: query.UserID, Kind: identity.IdentifierPhone, CanonicalValue: target.number, Eligibility: RecipientVerified, NormalizationProfile: i.Change.NormalizationProfile, NormalizationVersion: i.Change.NormalizationVersion})
					if err != nil || recipient.Suppressed != target.suppressed || !target.suppressed && (recipient.Identifier.ID != i.Change.ID || recipient.IdentifierAuthorityVersion != after.AuthorityVersion) {
						t.Fatal("replacement discovery admitted old or suppressed new number", err)
					}
				}
			} else if retirements != 0 || cascades != 0 || pending != 0 {
				t.Fatal("replacement denial/rollback retained retirement or cascade prefix")
			}
		})
	}
	// A later original change can be proved not committed while its exact
	// predecessor is still current. Earlier non-removal value history must not
	// make every subsequent command permanently ambiguous. Today's successor
	// still cannot prove historical success of the already committed command.
	for _, test := range []struct {
		name    string
		tenant  identity.TenantID
		user    identity.UserID
		record  string
		version uint64
		want    RecoveryStatus
	}{
		{"new-original-after-replacement", query.TenantID, query.UserID, string(before.Identifiers[0].ID), before.Identifiers[0].Version + 1, RecoveryNotCommitted},
		{"committed-successor-is-not-receipt", query.TenantID, query.UserID, string(before.Identifiers[0].ID), before.Identifiers[0].Version, RecoveryUnknown},
		{"future-version", query.TenantID, query.UserID, string(before.Identifiers[0].ID), before.Identifiers[0].Version + 2, RecoveryUnknown},
		{"foreign-user", query.TenantID, "phone-other", string(before.Identifiers[0].ID), before.Identifiers[0].Version + 1, RecoveryUnknown},
		{"foreign-tenant", "other-tenant", query.UserID, string(before.Identifiers[0].ID), before.Identifiers[0].Version + 1, RecoveryUnknown},
	} {
		t.Run("recovery-"+test.name, func(t *testing.T) {
			b, op := codecBinding(), phoneChangeOperation()
			b.TenantID, b.UserID, b.ActorID, b.RecordID = test.tenant, test.user, identity.ActorID(test.user), test.record
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: b, generation: 1}}
			defer invalidateWork(w)
			h := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{descriptor: repo.Descriptor(), contributor: repo},
				plan: &admittedKernelPlan{binding: b, feature: &FeatureRegistration{Operation: op}, lifecycle: &LifecyclePlan{BeforeVersion: test.version, AfterVersion: test.version + 1}}, active: true}}
			got, err := repo.RecoverParticipant(bounded, h)
			if err != nil || got != test.want {
				t.Fatal("replacement recovery lost exact negative evidence or invented success", got, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
