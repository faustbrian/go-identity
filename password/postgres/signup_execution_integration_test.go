//go:build integration

package passwordpostgres

import (
	"context"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This fixture supplies only the invocation wiring not yet provided by the
// public SignupService. The existing journal drives actual native generation,
// restoration, account/material/flow mutation, issuance and delivery owners.
type signupExecutionFixture struct {
	input       signupExecutionPreparation
	repository  *Repository
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	admission   risk.AuthenticationAdmission
	execution   *signupExecution
	generations int
	rollback    bool
}

func (*signupExecutionFixture) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*signupExecutionFixture) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordSignupOperation()}
}
func (p *signupExecutionFixture) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c == p.input.original || p.execution != nil && c == p.execution.command {
		return nil
	}
	return password.ErrPasswordWork
}
func (p *signupExecutionFixture) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *signupExecutionFixture) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.input.original {
		return password.ErrPasswordWork
	}
	return sessionpg.RequirePreAuth(ctx, w, p.input.storage, p.input.flow)
}
func (p *signupExecutionFixture) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.generations++
	return p.repository.generateSignupOutput(ctx, c, p.input.selected, p.input.flow, p.input.at, p.admission, generation, p.input.generation)
}
func (p *signupExecutionFixture) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.input.original {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	var err error
	p.execution, err = p.repository.restoreSignupExecution(ctx, p.input, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := signupExecutionPlan(p.coordinator, p.registry, p, p.execution.command, p.input.at, p.execution.issuancePlan, p.execution.deliveryPlan)
	return p.execution.command, plan, err
}
func (p *signupExecutionFixture) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	result, err := p.execution.apply(ctx, w, c)
	if err == nil && p.rollback {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return result, err
}
func (p *signupExecutionFixture) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.execution.checkCommit(ctx, w, c)
}
func (*signupExecutionFixture) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, password.ErrPasswordWork
}

func installNativeSignupExecutionHistory(t *testing.T, ctx context.Context, pool *database.Pool, base kernel.DirectoryAuthorityMigrationSource) {
	t.Helper()
	registration := kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.PasswordRegistrationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: base, Version: 16}, Version: 17}, Version: 18}
	preparation := kernel.PreparationMigrationSource{Base: registration, Version: 19}
	history, err := preparation.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var registrationInstalled bool
	if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.registration_bindings') IS NOT NULL`).Scan(&registrationInstalled); err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() >= 19 || m.Version() >= 16 && !registrationInstalled {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("signup journal migration", err)
			}
		}
	}
	entries, err := fs.ReadDir(issuerpg.Migrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(issuerpg.Migrations(), entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		// Use only the owned forward migration body; downgrade is unsupported.
		up := strings.Split(string(wire), "-- +migrations Down")[0]
		if _, err = pool.Raw().Exec(ctx, up); err != nil {
			t.Fatal("issuance migration", err)
		}
	}
	deliveryHistory, err := (deliverypg.MigrationSource{Base: preparation, Version: 20}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range deliveryHistory {
		if m.Version() >= 20 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("delivery migration", err)
			}
		}
	}
}

func testNativeSignupGeneratedExecution(t *testing.T, ctx context.Context, pool *database.Pool, repository *Repository, directory *kernel.Repository, request password.SignupRequest, selected kernel.PasswordRegistrationIntent, flow session.PreAuthTransaction, flowKey session.DigestKey, storage sessionpg.Config, at time.Time, generation signupGenerationPreparation, riskConfig risk.AuthenticationAdmissionCustodyConfig, base kernel.DirectoryAuthorityMigrationSource) {
	t.Helper()
	installNativeSignupExecutionHistory(t, ctx, pool, base)
	for _, mode := range []string{"commit", "neutral", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			r := request
			f, _ := flow.Bindings()
			f.Binding.ID, _ = identity.NewPreAuthTransactionID()
			r.PreAuthID = f.Binding.ID
			token, _ := session.ParseToken(r.Cookie.Token())
			f.Cookie, _ = token.PreAuthDigest(flowKey, f.Binding)
			originalFlow, err := session.NewPreAuthTransaction(f)
			if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, originalFlow) != nil {
				t.Fatal("original execution flow")
			}
			id, _ := identity.NewCommandID()
			user, _ := identity.NewSubjectID()
			intent := selected
			b := selected.Creation.Binding
			b.CommandID, b.CorrelationID, b.AnonymousFlowID, b.UserID = id, string(id), string(r.PreAuthID), ""
			b.OperationID, b.SchemaID, b.SchemaVersion = "identity.password.signup", "password-signup", 1
			intent.Creation.Binding.CommandID, intent.Creation.Binding.CorrelationID, intent.Creation.Binding.UserID = id, string(id), identity.UserID(user)
			intent.Identifier.ID, intent.Identifier.UserID = identity.IdentifierID(user), identity.UserID(user)
			intent.Credential.UserID = identity.UserID(user)
			if mode == "rollback" {
				intent.Identifier.CanonicalValue = string(user) + "@example.test"
			}
			fields, err := kernel.PasswordRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeaturePasswordSignupInputCommand(identity.FeatureCommandSpec{Binding: b, Operation: passwordSignupOperation(), Fields: fields}, r.Password, r.Cookie)
			if err != nil {
				t.Fatal(err)
			}
			domain, err := kernel.NewPasswordRegistrationDomain(directory, kernel.PasswordRegistrationDomainConfig{ComparisonProfile: intent.ComparisonProfile, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			config := generation
			hashes, screens := 0, 0
			config.screening.Primitive, err = primitive.New(repository.policy, primitive.WithObserver(signupHashObservation(func(o primitive.Observation) {
				if o.Operation == primitive.OperationHash {
					hashes++
					if screens != 1 {
						t.Error("hash before screening")
					}
				}
			})))
			if err != nil {
				t.Fatal(err)
			}
			config.screening.Collect = func(ctx context.Context, scope risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
				screens++
				fact, err := config.screening.Policy.PasswordSignal(ctx, scope, risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)})
				return []risk.Signal{fact}, err
			}
			p := &signupExecutionFixture{repository: repository, rollback: mode == "rollback"}
			p.input = signupExecutionPreparation{owner: p, original: command, selected: intent, flow: originalFlow, flowKey: flowKey, storage: storage, at: at, request: r, domain: domain, generation: config, risk: riskConfig, subject: risk.Subject{Network: "192.0.2.1", Device: "synthetic-device", IdentifierDigest: strings.Repeat("a", 64)}}
			p.admission = signinTestAdmissionWithConfig(t, ctx, b, riskConfig)
			audits, _ := auditpg.NewIdentityContributor(auditpg.Config{})
			outbox, _ := lifecyclepg.NewContributor()
			p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{directory, audits, outbox, generation.verification.issuer, generation.delivery.owner, p})
			if err != nil {
				t.Fatal(err)
			}
			p.coordinator, err = kernel.NewCoordinator(pool, p.registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {4}}})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := signupExecutionPlan(p.coordinator, p.registry, p, command, at, kernel.CapabilityIssuancePlan{}, kernel.DeliveryPlan{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := p.coordinator.ExecutePreparedFeature(ctx, command, plan)
			if mode == "rollback" {
				if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("native generated rollback", err)
				}
			} else if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("native generated signup commit", err)
			}
			if hashes != 1 || screens != 1 || p.generations != 1 {
				t.Fatal("original generation did not run exactly once")
			}
			if mode != "rollback" {
				again, err := p.coordinator.ExecutePreparedFeature(ctx, command, plan)
				if err != nil || again.Outcome != identity.CommitOutcomeCommitted || again.Binding != result.Binding || hashes != 1 || screens != 1 || p.generations != 1 {
					t.Fatal("terminal replay regenerated effects", err)
				}
			}
			var users, materials, grants, messages int
			commandID, _ := base64.RawURLEncoding.DecodeString(string(id))
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$4),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$3)`, string(b.TenantID), string(user), commandID, string(id)).Scan(&users, &materials, &grants, &messages); err != nil {
				t.Fatal("native effect inspection", err)
			}
			want := 0
			if mode == "commit" {
				want = 1
			}
			if users != want || materials != want || grants != want || messages != want {
				t.Fatal("native generation effects not atomic")
			}
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if mode == "rollback" && state != "issued" || mode != "rollback" && state != "consumed" {
				t.Fatal("flow and generation effects diverged")
			}
		})
	}
}
