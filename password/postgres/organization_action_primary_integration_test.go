//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This controlled domain participant proves the actual password owner's
// authenticated one-use lifecycle proof/Work boundary, not organization policy.
// The genuine organization lifecycle consumer separately proves business effects.
type organizationPrimaryWorkFixture struct {
	primary  ActionPrimaryAdmission
	op       identity.FeatureOperation
	command  identity.Command
	rollback bool
	consumed bool
}

func (*organizationPrimaryWorkFixture) Descriptor() kernel.ContributorDescriptor {
	return actionPrimaryDescriptor("identity.organization.archive")
}
func (p *organizationPrimaryWorkFixture) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (p *organizationPrimaryWorkFixture) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *organizationPrimaryWorkFixture) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := p.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.consumed = true
	if p.rollback {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.op, AfterVersion: 1}, nil
}
func (p *organizationPrimaryWorkFixture) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.primary.Check(ctx, w, p, c)
}
func (*organizationPrimaryWorkFixture) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func TestNativeOrganizationLifecycleActionPrimary(t *testing.T) {
	testNativeSigninPhaseIntegration(t, "organization lifecycle password owner", func(t *testing.T, ctx context.Context, pool *database.Pool, _ *SignupService, signup SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		testNativePhoneEnrollment(t, ctx, pool, nil, signup, keys, fresh, session.CredentialBearer, "normal", func(c SigninConfig, _ *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
			signin, err := NewSigninService(pool, c)
			if err != nil {
				t.Fatal(err)
			}
			r, _, _, _ := nativeSigninFlow(t)
			r.TenantID = registration.TenantID
			r.Caller.Request.Tenant = authorization.TenantID(r.TenantID)
			r.Identifier = identifier.Input(registration.Email)
			r.Password = registration.Password
			r.Device = "organization-lifecycle-browser"
			if err := r.Validate(); err != nil {
				t.Fatal("genuine lifecycle signin input", err)
			}
			r.PreAuthID, _ = identity.NewPreAuthTransactionID()
			at := time.Now().UTC().Truncate(time.Microsecond)
			b := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{225}, Remember: r.Remember, PolicyID: c.PolicyID, PolicyVersion: 3}, IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}
			token, _ := session.ParseToken(r.Cookie.Token())
			digest, err := token.PreAuthDigest(c.FlowKeys[0], b)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
			if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, c.Session, flow) != nil {
				t.Fatal("genuine lifecycle browser", err)
			}
			authenticated, err := signin.Signin(ctx, r)
			if err != nil || authenticated.State != auth.SignInStateAuthenticated {
				t.Fatal("genuine lifecycle session", err)
			}
			wire, err := authenticated.Issuance.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			signing, err := NewReauthenticationSigningKey("organization-lifecycle", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{226}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			keyID, public := signing.public()
			base := PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71}
			suffix, err := (OrganizationLifecycleReauthenticationMigrationSource{Base: base, Version: 120}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Raw().Exec(ctx, suffix[len(suffix)-1].UpSQL()); err != nil {
				t.Fatal("lifecycle proof history", err)
			}
			for _, action := range []string{"identity.organization.archive", "identity.organization.restore"} {
				t.Run(action, func(t *testing.T) {
					target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: action, Audience: "organization-lifecycle"}
					owner, err := NewReauthenticationService(pool, ReauthenticationConfig{Repository: c.Repository, Verifier: c.Verifier, Session: c.Session, Profile: c.Profile, LookupKeys: []session.DigestKey{c.Issuance.LookupKey}, Risk: c.Risk, Coordinator: c.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{keyID: public}, Issuer: c.Issuer, Environment: c.Environment, Targets: []ReauthenticationTarget{target}, TTL: time.Minute, IdentifierKey: bytes.Repeat([]byte{227}, 32)})
					if err != nil {
						t.Fatal(err)
					}
					caller := authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: authorization.TenantID(r.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
					proof, err := owner.Verify(ctx, ReauthenticationRequest{TenantID: r.TenantID, Session: auth.NewBearerCredential(wire), Password: registration.Password, Target: target, Caller: caller, Network: "192.0.2.13", Device: "lifecycle-browser"})
					if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("actual lifecycle action proof", err)
					}
					primary, err := NewActionPrimarySource(owner, ActionPrimaryConfig{Action: action, Audience: target.Audience, MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer})
					if err != nil {
						t.Fatal(err)
					}
					var retained []byte
					if err = pool.Raw().QueryRow(ctx, `SELECT record FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(proof.Proof.Proof.ID)).Scan(&retained); err != nil {
						t.Fatal(err)
					}
					defer clear(retained)
					for _, rollback := range []bool{true, false} {
						id, _ := identity.NewCommandID()
						request := ActionPrimaryRequest{TenantID: r.TenantID, CommandID: id, RecordID: "lifecycle-organization", Session: auth.NewBearerCredential(wire), Proof: proof.Proof, Caller: caller}
						a, err := primary.Prepare(ctx, request)
						if err != nil {
							t.Fatal("actual lifecycle preparation", err)
						}
						op := actionPrimaryOperation(action)
						binding := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, RecordID: request.RecordID, OperationID: action, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "lifecycle-test", PolicyVersion: 3, CorrelationID: string(id)}
						command, err := a.Command(binding, nil)
						if err != nil {
							t.Fatal(err)
						}
						p := &organizationPrimaryWorkFixture{primary: a, op: op, command: command, rollback: rollback}
						domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
						if err != nil {
							t.Fatal(err)
						}
						audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
						if err != nil {
							t.Fatal(err)
						}
						outbox, err := lifecyclepg.NewContributor()
						if err != nil {
							t.Fatal(err)
						}
						registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audit, outbox, p})
						if err != nil {
							t.Fatal(err)
						}
						coordinator, err := kernel.NewCoordinator(pool, registry, c.Coordinator)
						if err != nil {
							t.Fatal(err)
						}
						plan, err := resetServiceAuditDeclaration(binding, op, registry.Descriptors(), "organization", 0, 1, time.Now().UTC())
						if err != nil {
							t.Fatal(err)
						}
						plan.Feature.Contributor = p.Descriptor()
						plan.Lifecycle.EventType = "organization.archived.v1"
						if action == "identity.organization.restore" {
							plan.Lifecycle.EventType = "organization.restored.v1"
						}
						plan, err = coordinator.PrepareCommandPlan(binding, command, plan)
						if err != nil {
							t.Fatal("lifecycle owner declaration", err)
						}
						reservation, result, err := coordinator.ReserveCommand(ctx, binding, command, plan)
						if err != nil || reservation == (kernel.Reservation{}) {
							t.Fatal("actual lifecycle reservation", err)
						}
						work, err := coordinator.Begin(ctx, reservation)
						if err != nil {
							t.Fatal(err)
						}
						result, err = coordinator.ApplyFeature(ctx, work, command)
						if err != nil {
							result, err = coordinator.Abort(work, err)
						} else {
							result, err = coordinator.Commit(work, result)
						}
						if rollback {
							if !p.consumed {
								t.Fatal("rollback test never reached successful protected consumption", err)
							}
							if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
								t.Fatal("failed participant consumed proof")
							}
						} else if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
							t.Fatal("actual lifecycle proof consumption", err)
						}
						var consumed bool
						var purpose string
						var original []byte
						if err = pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL,coalesce(consumed_purpose,''),record FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(proof.Proof.Proof.ID)).Scan(&consumed, &purpose, &original); err != nil {
							t.Fatal(err)
						}
						if consumed == rollback || !bytes.Equal(original, retained) || !rollback && purpose != action {
							t.Fatal("proof consumption/rollback changed original signed custody")
						}
						clear(original)
					}
				})
			}
		})
	})
}
