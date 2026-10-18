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

// Synthetic admitted OTP participant: proves coordinator callback ordering and
// storage atomicity, not production code comparison or phone authentication.
type phoneStorageOTPProbe struct {
	otpExecutionProbe
	checks int
	deny   bool
}

func (p *phoneStorageOTPProbe) CheckOTP(ctx context.Context, w OTPApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	p.checks++
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND kind='phone' AND NOT verified AND version=1 AND verification_version=1)`, string(b.Command.TenantID), string(b.Command.UserID), b.Command.RecordID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var pending bool
	if !rows.Next() || rows.Scan(&pending) != nil || rows.Next() || rows.Err() != nil || !pending || p.deny {
		return identity.ForbiddenError{}
	}
	return nil
}

// Storage-phase proof only: the OTP comparison/consumption and genuine caller
// must still be exercised by the complete native phone consumer.
func testPhoneVerificationPostgres(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	domain, err := NewPhoneEnrollmentDomain(repo, PhoneEnrollmentDomainConfig{
		NormalizationProfile: phoneEnrollmentIntent().Change.NormalizationProfile, NormalizationVersion: 1,
		CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}, ReuseCooldown: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	q := identity.IdentifierQuery{TenantID: "tenant", UserID: "phone-user", MaximumIdentifiers: 128}
	before, err := repo.GetIdentifierState(ctx, q)
	if err != nil || len(before.Identifiers) != 1 {
		t.Fatal("pending phone fixture", err)
	}
	for _, mode := range []string{"prepare-rollback", "stale-user", "stale-epoch", "foreign-number", "foreign-profile", "foreign-repository", "missing-session", "foreign-input-invocation"} {
		t.Run(mode, func(t *testing.T) {
			owner, spec, rawPlan := phoneVerificationFixture(t)
			owner.domain = domain
			i := owner.intent
			i.Change.TenantID, i.Change.UserID = q.TenantID, q.UserID
			i.Change.ExpectedUserVersion, i.Change.ExpectedAuthorityVersion = before.User.Version, before.AuthorityVersion
			i.CanonicalNumber = before.Identifiers[0].CanonicalValue
			switch mode {
			case "stale-user":
				i.Change.ExpectedUserVersion++
			case "stale-epoch":
				i.Change.ExpectedAuthorityVersion++
			case "foreign-number":
				i.CanonicalNumber = "+12025550125"
			case "foreign-profile":
				i.NormalizationVersion++
			case "foreign-repository":
				copy := *domain
				copy.repository = &Repository{}
				owner.domain = &copy
			}
			owner.intent = i
			b := spec.Binding
			b.TenantID, b.UserID, b.ActorID = q.TenantID, q.UserID, identity.ActorID(q.UserID)
			fields, err := PhoneVerificationFields(i)
			if err != nil {
				t.Fatal(err)
			}
			spec.Binding, spec.Fields = b, fields
			var command identity.Command
			if mode == "missing-session" {
				command, err = identity.NewFeatureCommand(spec)
			} else {
				command, err = identity.NewFeatureSessionCommand(spec, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			}
			if err != nil {
				t.Fatal(err)
			}
			plan := &admittedKernelPlan{binding: b, fingerprint: [32]byte{1}, feature: rawPlan.Feature, subjectType: "identifier",
				lifecycle: rawPlan.Lifecycle, audits: rawPlan.Audits, otp: rawPlan.OTP,
				contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}, {descriptor: rawPlan.Feature.Contributor, contributor: &owner}}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: b, generation: 1, feature: rawPlan.Feature,
				lifecycle: &workLifecycle{plan: *rawPlan.Lifecycle}, execution: &domainExecution{reservation: &reservationState{plan: plan}}}}
			defer invalidateWork(w)
			w.state.featureInvocation, w.state.featurePreparationCommand, w.state.featurePreparationPlan = &owner, &command, plan
			if mode == "foreign-input-invocation" {
				copy, err := identity.NewFeatureSessionCommand(spec, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
				if err != nil {
					t.Fatal(err)
				}
				w.state.featurePreparationCommand = &copy
			}
			err = w.RequirePhoneVerificationTarget(bounded, &owner, command)
			if mode == "prepare-rollback" {
				if err != nil {
					t.Fatal("original target admission", err)
				}
				w.state.featureInvocation, w.state.featurePreparationCommand, w.state.featurePreparationPlan = nil, nil, nil
				if err := preparePhoneVerification(bounded, w, command); err != nil {
					t.Fatal("kernel verification prepare", err)
				}
				p := w.state.phoneVerification
				if p == nil || p.applied || !p.mutation.State.Identifiers[0].Verified || p.mutation.State.Identifiers[0].Version != 2 ||
					p.mutation.State.Verifications[0].State != identity.VerificationVerified || p.mutation.State.User.Version != before.User.Version+1 || p.mutation.State.AuthorityVersion != before.AuthorityVersion+1 {
					t.Fatal("kernel lost exact verification successor")
				}
				var verified bool
				if err := tx.QueryRow(ctx, `SELECT verified FROM identity.identifiers WHERE tenant_id='tenant' AND user_id='phone-user' AND identifier_id='pending-phone'`).Scan(&verified); err != nil || verified {
					t.Fatal("prepare persisted possession before OTP consumption", err)
				}
				if err := applyPhoneVerification(bounded, w); err == nil || w.state.failed == nil {
					t.Fatal("missing actual OTP invocation fabricated verification")
				}
			} else if err == nil || w.state.failed == nil {
				t.Fatal("unsafe pending-phone admission did not poison Work")
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := repo.GetIdentifierState(ctx, q)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("denial/prepare retained phone effects", err)
			}
		})
	}
	// Pending rows may establish only noncommit, never success. Recovery's other
	// owners must independently agree before the coordinator releases anything.
	recovery := func(t *testing.T, tenant identity.TenantID, user identity.UserID, record string, want RecoveryStatus, retired bool) {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if retired {
			_, err = tx.Exec(ctx, `INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until) VALUES('tenant','phone-user','pending-phone','phone',1,1,true,'BwcHBwcHBwcHBwcHBwcHBw',1,decode(repeat('01',32),'hex'),clock_timestamp(),clock_timestamp()+interval '30 days')`)
			if err != nil {
				t.Fatal(err)
			}
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		b := codecBinding()
		op := phoneVerificationOperation()
		b.TenantID, b.UserID, b.ActorID, b.RecordID = tenant, user, identity.ActorID(user), record
		b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
		feature := &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}
		w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: b, generation: 1}}
		defer invalidateWork(w)
		h := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{descriptor: repo.Descriptor(), contributor: repo}, plan: &admittedKernelPlan{binding: b, feature: feature}, active: true}}
		got, err := repo.RecoverParticipant(bounded, h)
		if err != nil || got != want {
			t.Fatal("phone recovery invented historical evidence", got, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("recovery-pending", func(t *testing.T) { recovery(t, "tenant", "phone-user", "pending-phone", RecoveryNotCommitted, false) })
	t.Run("recovery-retired", func(t *testing.T) { recovery(t, "tenant", "phone-user", "pending-phone", RecoveryUnknown, true) })
	t.Run("recovery-absent", func(t *testing.T) { recovery(t, "tenant", "phone-user", "absent", RecoveryUnknown, false) })
	t.Run("recovery-foreign-user", func(t *testing.T) { recovery(t, "tenant", "phone-other", "pending-phone", RecoveryUnknown, false) })
	t.Run("recovery-foreign-tenant", func(t *testing.T) { recovery(t, "other-tenant", "phone-user", "pending-phone", RecoveryUnknown, false) })
	for _, mode := range []string{"otp-denied", "post-otp-rollback", "post-otp-commit"} {
		t.Run(mode, func(t *testing.T) {
			owner, spec, rawPlan := phoneVerificationFixture(t)
			owner.domain = domain
			owner.intent.Change.TenantID, owner.intent.Change.UserID = q.TenantID, q.UserID
			owner.intent.Change.ExpectedUserVersion, owner.intent.Change.ExpectedAuthorityVersion = before.User.Version, before.AuthorityVersion
			owner.intent.CanonicalNumber = before.Identifiers[0].CanonicalValue
			spec.Binding.TenantID, spec.Binding.UserID, spec.Binding.ActorID = q.TenantID, q.UserID, identity.ActorID(q.UserID)
			spec.Fields, err = PhoneVerificationFields(owner.intent)
			if err != nil {
				t.Fatal(err)
			}
			code, _ := auth.NewOneTimeCode("123456")
			command, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			probe := &phoneStorageOTPProbe{deny: mode == "otp-denied"}
			registry := &ContributorRegistry{state: &contributorRegistryState{}}
			coordinator := &Coordinator{registry: registry}
			plan := &admittedKernelPlan{registry: registry.state, binding: spec.Binding, fingerprint: [32]byte{1}, feature: rawPlan.Feature,
				lifecycle: rawPlan.Lifecycle, audits: rawPlan.Audits, subjectType: "identifier", otp: rawPlan.OTP,
				contributors: []registeredContributor{{descriptor: repo.Descriptor(), contributor: repo}, {descriptor: rawPlan.Feature.Contributor, contributor: &owner}, {descriptor: probe.Descriptor(), contributor: probe}}}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, registry: registry.state, binding: spec.Binding, generation: 1,
				feature: rawPlan.Feature, lifecycle: &workLifecycle{plan: *rawPlan.Lifecycle}, otpCommand: &command,
				execution: &domainExecution{coordinator: coordinator, reservation: &reservationState{plan: plan}}}}
			defer invalidateWork(w)
			if err := preparePhoneVerification(ctx, w, command); err != nil {
				t.Fatal(err)
			}
			err = applyPhoneVerification(ctx, w)
			if probe.checks != 1 {
				t.Fatal("kernel skipped OTP current admission")
			}
			if mode == "otp-denied" {
				if err == nil || w.state.phoneVerification.applied || w.state.failed == nil {
					t.Fatal("OTP denial retained verification authority")
				}
			} else {
				if err != nil || !w.state.phoneVerification.applied {
					t.Fatal("admitted OTP did not apply verification", err)
				}
				var verified bool
				var version, verification, aggregate, authority string
				err = tx.QueryRow(ctx, `SELECT i.verified,i.version::text,i.verification_version::text,u.version::text,u.identifier_version::text FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id='tenant' AND i.user_id='phone-user' AND i.identifier_id='pending-phone'`).Scan(&verified, &version, &verification, &aggregate, &authority)
				if err != nil || !verified || version != "2" || verification != "2" || aggregate != "3" || authority != "3" {
					t.Fatal("phone persistence lost exact 2/2 and aggregate/epoch successor", err)
				}
			}
			if mode == "post-otp-commit" {
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
			if mode != "post-otp-commit" && !reflect.DeepEqual(before, after) {
				t.Fatal("OTP denial/rollback left phone effects")
			}
			if mode == "post-otp-commit" && (!after.Identifiers[0].Verified || after.Verifications[0].State != identity.VerificationVerified || after.Verifications[0].VerifiedAt.IsZero()) {
				t.Fatal("verification did not survive commit")
			}
		})
	}
	t.Run("recovery-verified", func(t *testing.T) { recovery(t, "tenant", "phone-user", "pending-phone", RecoveryUnknown, false) })
}
