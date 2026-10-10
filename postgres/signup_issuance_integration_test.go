//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This exercises the kernel's selected-subject transaction boundary, not the
// capability adapter's signing policy or a complete email/password workflow.
func testSignupCapabilityIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, domain *PasswordRegistrationDomain) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_issuance(command_id text UNIQUE NOT NULL,capability_id text PRIMARY KEY,proof_fingerprint bytea NOT NULL,replay_digest bytea NOT NULL,generation numeric NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-registration", "foreign-target", "wrong-subject", "wrong-tenant", "issuer-failure", "later-failure", "disconnect-before", "disconnect-after"} {
		t.Run(mode, func(t *testing.T) {
			pool, repo, domain := pool, repo, domain
			var fault *registrationCommitFault
			if strings.HasPrefix(mode, "disconnect-") {
				fault = &registrationCommitFault{before: mode == "disconnect-before"}
				name := pool.Raw().Config().ConnConfig.Database
				var err error
				pool, err = database.Connect(ctx, database.Config{DSN: os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = name
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if pool.Close(bounded) != nil {
						t.Error("fault pool cleanup")
					}
				}()
				repo, err = NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{storageSchema()}})
				if err != nil {
					t.Fatal(err)
				}
				domain, err = NewPasswordRegistrationDomain(repo, PasswordRegistrationDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			b := codecBinding()
			b.CommandID, _ = identity.NewCommandID()
			u, _ := identity.NewSubjectID()
			b.UserID, b.SchemaID = identity.UserID(u), "fields"
			intent := PasswordRegistrationIntent{Creation: identity.CreateUserCommand{Binding: b, Status: identity.StatusActive, Attributes: storageValues()}, Identifier: identity.Identifier{ID: identity.IdentifierID(u), UserID: identity.UserID(u), Kind: identity.IdentifierEmail, CanonicalValue: string(u) + "@example.test", Version: 1}, Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: identity.UserID(u), Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
			fields, err := PasswordRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, "$synthetic$signup-verifier", auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))))
			if err != nil {
				t.Fatal(err)
			}
			issuer := &issuanceSQLPhase{}
			if mode == "issuer-failure" {
				issuer.mode = "error"
			}
			phase := &registrationTestPhase{domain: domain, expected: command, intent: intent, issuer: issuer, skip: mode == "missing-registration"}
			audits, lifecycle := &recoveryAuditPhase{}, &recoveryLifecyclePhase{fail: mode == "later-failure"}
			registry, err := NewContributorRegistry([]Contributor{repo, audits, lifecycle, phase, issuer})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: 500 * time.Millisecond, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			payload := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: string(u), Resource: "identifier-verification", Operation: "identity.identifier.verify", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), ID: string(b.CommandID), Tenant: string(b.TenantID), MaxUses: 1}
			if mode == "wrong-subject" {
				payload.Subject = "foreign-subject"
			}
			if mode == "wrong-tenant" {
				payload.Tenant = "foreign-tenant"
			}
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, err := capability.NewHMACSHA256Signer("test-key", key)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(key)
			if err != nil {
				t.Fatal(err)
			}
			token, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			phase.grant, err = capability.Verify(ctx, token, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
				return capability.ResolvedKey{Verifier: verifier}, nil
			}), capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.SubjectType, plan.Feature = registry.Descriptors(), "user", &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}
			plan.Lifecycle = &LifecyclePlan{EventType: "user.created.v1"}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
			seed, err := securityMutationAudit(ctx, b, 0, 0, now, "committed", op.OperationID, "user", b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, "user", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan.CapabilityIssuance = issuanceTestPlan()
			plan.CapabilityIssuance.RegistrationUserID = identity.UserID(u)
			if mode == "foreign-target" {
				plan.CapabilityIssuance.RegistrationUserID = "foreign-target"
			}
			g := &plan.CapabilityIssuance.Grants[0]
			g.CapabilityID, g.ExpiresAt, g.ProofFingerprint = payload.ID, payload.ExpiresAt, sha256.Sum256([]byte(token))
			plan, err = c.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("selected signup plan", err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil || reservation.state == nil {
				t.Fatal("reservation", err)
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, err := c.ApplyFeature(ctx, w, command)
			if err == nil {
				result, err = c.Commit(w, result)
			} else {
				_, _ = c.Abort(w, err)
			}
			want := 0
			if fault != nil {
				if err == nil || !fault.hit.Load() || result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("transport failure fabricated an outcome", err)
				}
				expected := identity.CommitOutcomeNotCommitted
				if mode == "disconnect-after" {
					expected, want = identity.CommitOutcomeCommitted, 1
				}
				query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
				bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					history, e := c.recoverCommandReceipt(bounded, query)
					if history.Outcome == expected {
						if want == 1 && (e != nil || history.Binding != b) {
							t.Fatal("committed anonymous issuance recovery lost", e)
						}
						break
					}
					select {
					case <-bounded.Done():
						t.Fatal("signup issuance ambiguity unresolved", e)
					case <-ticker.C:
					}
				}
			}
			if mode == "commit" {
				want = 1
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != b {
					t.Fatal("anonymous signup issuance failed", err)
				}
				if issuer.invocations != 1 {
					t.Fatal("issuance was not persisted")
				}
				if issuer.binding.Command != b || issuer.binding.Plan.RegistrationUserID != identity.UserID(u) {
					t.Fatal("issuer retargeted original anonymous command")
				}
				_, history, e := c.ReserveCommand(ctx, b, command, plan)
				if e != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != b {
					t.Fatal("original anonymous replay lost", e)
				}
				changed := plan
				changed.CapabilityIssuance = cloneCapabilityIssuancePlan(plan.CapabilityIssuance)
				changed.CapabilityIssuance.RegistrationUserID = "different-user"
				changed, e = c.PrepareCommandPlan(b, command, changed)
				if e != nil {
					t.Fatal(e)
				}
				_, conflict, e := c.ReserveCommand(ctx, b, command, changed)
				var conflictError identity.ConflictError
				if !errors.As(e, &conflictError) || conflict.Outcome != identity.CommitOutcomeConflict {
					t.Fatal("changed target replayed original signup", e)
				}
			} else if err == nil {
				t.Fatal("invalid signup issuance committed")
			}
			// Denial auditing survives proved rollback; it is not a committed
			// registration effect. This fixture stores one row per command.
			var users, issued, registrations, identifiers, credentials, material, auditsCount, lifecycleCount int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.identity_test_issuance WHERE command_id=$3),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND NOT verified),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.identity_test_registration_material WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.TenantID), string(u), string(b.CommandID)).Scan(&users, &issued, &registrations, &identifiers, &credentials, &material, &auditsCount, &lifecycleCount); e != nil || users != want || issued != want || registrations != want || identifiers != want || credentials != want || material != want || auditsCount != 1 || lifecycleCount != want {
				t.Fatalf("signup issuance counts %d/%d/%d/%d/%d/%d/%d/%d, want domain=%d: %v", users, issued, registrations, identifiers, credentials, material, auditsCount, lifecycleCount, want, e)
			}
		})
	}
}
