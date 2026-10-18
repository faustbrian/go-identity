//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	username "github.com/faustbrian/go-identity/username"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// SU01/05/07/08: public methods, real journal and all effect owners; callbacks
// replace only provider observations and canonical ID selection, never stores.
func testNativePublicSignup(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, original signupKeyPreparation, schema identity.AttributeSchema, keys *keyring.Provider, generation signupGenerationPreparation, riskConfig risk.AuthenticationAdmissionCustodyConfig, request password.SignupRequest, withUsername bool) {
	t.Helper()
	history, err := (kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 21}, Version: 22}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if m.Version() == 22 {
			if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	decision := signinPublicPolicy{}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: original.policyVersion, Authorization: decision}
	requestKeys, err := kernel.NewRequestKeyConfig("public-signup", [32]byte{91}, query)
	if err != nil {
		t.Fatal(err)
	}
	primitiveService, _ := primitive.New(policy)
	generation.screening.Primitive = primitiveService
	var screens atomic.Int32
	generation.screening.Collect = func(ctx context.Context, scope risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
		screens.Add(1)
		fact, err := generation.screening.Policy.PasswordSignal(ctx, scope, risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)})
		return []risk.Signal{fact}, err
	}
	c := SignupConfig{Repository: Config{MaximumDuration: 3 * time.Second, HashPolicy: policy}, Registration: password.RegistrationPolicy{Enabled: true, RequireVerifiedEmail: true, MinimumBytes: 8, MaximumBytes: 128}, ConfigurationID: "public-signup-v1", PolicyID: original.policyID, Fields: original.fields, FieldSchema: schema, Address: original.address, SelectUser: original.selectUser, Session: original.flowStorage, FlowKeys: original.flowKeys, Origins: original.origins, CallbackURLs: original.callbacks, RegistrationDomain: kernel.PasswordRegistrationDomainConfig{ComparisonProfile: original.comparison, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}}, RequestKeys: requestKeys, IntentKey: [32]byte{92}, ActiveEnvelopeKeyID: "input", Screening: generation.screening, Risk: riskConfig, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {4}}, QueryPolicy: &query, AdmissionPolicy: &query}, Verification: SignupVerificationConfig{Policy: generation.verification.policy, Issuer: generation.verification.issuer, Codec: generation.codec, Lifetime: generation.verification.lifetime}, Delivery: SignupDeliveryConfig{Owner: generation.delivery.owner, Renderer: generation.delivery.renderer, Resolver: generation.delivery.resolver, Endpoint: generation.delivery.endpoint, TemplateID: generation.delivery.template, TemplateVersion: generation.delivery.templateVersion, ProviderVersion: generation.delivery.providerVersion, Locales: generation.delivery.locales, ScopeKey: generation.delivery.scopeKey, Timeout: generation.delivery.timeout}}
	c.SelectUser = func(context.Context) (identity.UserID, error) {
		id, err := identity.NewSubjectID()
		return identity.UserID(id), err
	}
	if withUsername {
		c.Username, err = username.NewPolicy(username.ReferencePolicySpec())
		if err != nil {
			t.Fatal(err)
		}
		c.ConfigurationID = "public-username-signup-v1"
		c.AuthorizationNamespace = "users"
	}
	service, err := NewSignupService(pool, c, keys)
	if err != nil {
		t.Fatal("public signup composition", err)
	}
	var public password.SignupService = service
	fresh := func(address string, marker byte) password.SignupRequest {
		r := request
		r.Device = "synthetic-device"
		r.Email = password.SignupAddressInput(address)
		r.IdempotencyKey, _ = identity.NewIdempotencyKey(bytes.Repeat([]byte{marker}, 32))
		_, f, _, _ := nativeSignupFlow(t)
		s, _ := f.Bindings()
		s.Binding.ID, _ = identity.NewPreAuthTransactionID()
		s.Binding.Intent.TenantID = r.TenantID
		if withUsername {
			r.Username = "Straße"
			r.Caller.Request.Action, r.Caller.Request.Resource.ID = "identity.username.signup", "identity.username.signup"
			s.Binding.Intent.Action = "identity.username.signup"
		}
		s.Binding.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
		s.Binding.ExpiresAt = s.Binding.IssuedAt.Add(5 * time.Minute)
		r.PreAuthID = s.Binding.ID
		token, _ := session.ParseToken(r.Cookie.Token())
		s.Cookie, _ = token.PreAuthDigest(original.flowKeys[0], s.Binding)
		f, _ = session.NewPreAuthTransaction(s)
		if err := sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, original.flowStorage, f); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if withUsername {
		testPublicUsernameRegistration(t, ctx, pool, service, c, keys, fresh)
		return
	}
	t.Run("http", func(t *testing.T) {
		testNativeSignupHTTP(t, ctx, service, c, keys, fresh, &screens)
	})
	// The direct-service partition below has its own generation observation.
	screens.Store(0)
	r := fresh("public-signup@example.test", 'S')
	for range 3 {
		canonical, err := service.SignupRateSource(ctx, "public-signup@EXAMPLE.test")
		if err != nil || canonical != string(r.Email) || screens.Load() != 0 {
			t.Fatal("signup source differs from native creation or performed password work")
		}
	}
	var beforeAccounts, beforeCommands int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.registration_bindings)`).Scan(&beforeAccounts, &beforeCommands); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignupRateSource(ctx, "public-signup@EXAMPLE.test"); err != nil {
		t.Fatal(err)
	}
	var afterAccounts, afterCommands int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.registration_bindings)`).Scan(&afterAccounts, &afterCommands); err != nil || beforeAccounts != afterAccounts || beforeCommands != afterCommands {
		t.Fatal("signup source persisted registration effects", err)
	}
	result, err := public.Signup(ctx, r)
	if err != nil || result.Validate() != nil || result.Outcome != identity.CommitOutcomeCommitted || !result.VerificationRequired || result.SubjectID != "" || result.SessionID != "" {
		t.Fatal("public verification signup", err)
	}
	q, _, _ := result.Recovery.Bindings()
	command, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	var accounts, credentials, messages, grants int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id IN (SELECT user_id FROM identity.registration_bindings WHERE command_id=$2)),(SELECT count(*) FROM identity_password.credentials WHERE tenant_id=$1 AND user_id IN (SELECT user_id FROM identity.registration_bindings WHERE command_id=$2)),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$2),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$3)`, string(r.TenantID), command, string(q.CommandID)).Scan(&accounts, &credentials, &messages, &grants); err != nil || accounts != 1 || credentials != 1 || messages != 1 || grants != 1 {
		t.Fatal("public effects diverged", err)
	}
	again, err := public.Signup(ctx, r)
	if err != nil || again.Outcome != identity.CommitOutcomeCommitted || !again.Replayed || again.Recovery != result.Recovery || screens.Load() != 1 {
		t.Fatal("public replay renewed generation", err)
	}
	changed := r
	changed.Email = "changed-public@example.test"
	_, err = public.Signup(ctx, changed)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatal("public changed intent replaced original")
	}
	// Recovery must still work after the original live flow is deleted, without
	// password/key/address or provider calls; authenticated retained input owns it.
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)); err != nil {
		t.Fatal(err)
	}
	t.Run("registration-verification-origin", func(t *testing.T) {
		testPublicSignupVerificationOrigin(t, ctx, service, c, r, q.CommandID, keys)
	})
	restarted, err := NewSignupService(pool, c, keys)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := restarted.SignupRateSource(ctx, "public-signup@EXAMPLE.test")
	if err != nil || canonical != string(r.Email) || screens.Load() != 1 {
		t.Fatal("source required deleted live flow or repeated screening", err)
	}
	keyedReplay, err := restarted.Signup(ctx, r)
	if err != nil || !keyedReplay.Replayed || keyedReplay.Outcome != identity.CommitOutcomeCommitted || keyedReplay.Recovery != result.Recovery || screens.Load() != 1 {
		t.Fatal("normalization broke original keyed retry after deleted flow", err)
	}
	recovery := password.SignupRecoveryRequest{Recovery: result.Recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
	got, err := restarted.RecoverSignup(ctx, recovery)
	if err != nil || got.Validate() != nil || got.Outcome != identity.CommitOutcomeCommitted || !got.Replayed || !got.VerificationRequired || got.Recovery != result.Recovery || screens.Load() != 1 {
		t.Fatal("public password-free original recovery", err)
	}
	recovery.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32)))
	if _, err := restarted.RecoverSignup(ctx, recovery); err == nil {
		t.Fatal("wrong original cookie disclosed recovery")
	}
	occupied := fresh("public-signup@example.test", 'T')
	neutral, err := public.Signup(ctx, occupied)
	if err != nil || neutral.Validate() != nil || neutral.Outcome != result.Outcome || neutral.VerificationRequired != result.VerificationRequired || neutral.SubjectID != "" || neutral.SessionID != "" {
		t.Fatal("occupied public signup enumerated", err)
	}
	nq, _, _ := neutral.Recovery.Bindings()
	nid, _ := base64.RawURLEncoding.DecodeString(string(nq.CommandID))
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, nid, string(nq.CommandID)).Scan(&messages, &grants); err != nil || messages != 0 || grants != 0 {
		t.Fatal("neutral public signup issued credentials", err)
	}
	// SU02/03: denied configuration and field input cannot reach provider/hash
	// generation. The actual registration processor owns field permission.
	before := screens.Load()
	disabledConfig := c
	disabledConfig.Registration.Enabled = false
	disabled, err := NewSignupService(pool, disabledConfig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.Signup(ctx, fresh("disabled@example.test", 'D')); !errors.Is(err, password.ErrRegistrationDisabled) {
		t.Fatal("disabled public signup admitted")
	}
	invalid := fresh("invalid-fields@example.test", 'I')
	invalid.AllowedFields = []identity.AttributeUpdate{{Name: "unknown", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "test"}}}}
	if _, err := public.Signup(ctx, invalid); err == nil {
		t.Fatal("unknown signup field admitted")
	}
	if screens.Load() != before {
		t.Fatal("denied signup generated material")
	}
	// SU05: simultaneous public calls independently own equal password bytes.
	// The real journal, not fixture serialization, limits original generation.
	concurrent := fresh("concurrent-public@example.test", 'C')
	var wait sync.WaitGroup
	start := make(chan struct{})
	results := make([]password.SignupResult, 2)
	failures := make([]error, 2)
	for n := range results {
		r := concurrent
		if err := concurrent.Password.Use(func(raw []byte) error { var err error; r.Password, err = primitive.NewSecret(raw); return err }); err != nil {
			t.Fatal(err)
		}
		wait.Add(1)
		go func(n int, r password.SignupRequest) {
			defer wait.Done()
			defer r.Password.Destroy()
			<-start
			results[n], failures[n] = public.Signup(ctx, r)
		}(n, r)
	}
	close(start)
	wait.Wait()
	for n, result := range results {
		var uncertain identity.UnknownCommitError
		unknown := result.Outcome == identity.CommitOutcomeUnknown && errors.As(failures[n], &uncertain)
		if failures[n] != nil && !unknown || result.Validate() != nil || result.Outcome != identity.CommitOutcomeCommitted && result.Outcome != identity.CommitOutcomeInProgress && !unknown {
			t.Fatal("concurrent public original failed", failures[n])
		}
	}
	terminal, err := public.Signup(ctx, concurrent)
	if err != nil || terminal.Outcome != identity.CommitOutcomeCommitted || screens.Load() != before+1 {
		t.Fatal("concurrent public calls regenerated", err)
	}
	q, _, _ = terminal.Recovery.Bindings()
	command, _ = base64.RawURLEncoding.DecodeString(string(q.CommandID))
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.registration_bindings WHERE command_id=$1),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, command, string(q.CommandID)).Scan(&accounts, &messages, &grants); err != nil || accounts != 1 || messages != 1 || grants != 1 {
		t.Fatal("concurrent public effects duplicated", err)
	}
	// SU03/06/08: a provider failure after the acknowledged original start is
	// ambiguous history, not permission to regenerate on retry or recovery.
	failureConfig := c
	failureConfig.ConfigurationID = "public-provider-outage-v1"
	var failuresSeen atomic.Int32
	failureConfig.Screening.Collect = func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
		failuresSeen.Add(1)
		return nil, errors.New("synthetic private provider failure")
	}
	failing, err := NewSignupService(pool, failureConfig, keys)
	if err != nil {
		t.Fatal(err)
	}
	failed := fresh("failed-public@example.test", 'F')
	failedResult, err := failing.Signup(ctx, failed)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || failedResult.Validate() != nil || failedResult.Outcome != identity.CommitOutcomeUnknown || failuresSeen.Load() != 1 {
		t.Fatal("provider failure inferred rollback", err)
	}
	retry, retryErr := failing.Signup(ctx, failed)
	if retryErr != nil || retry.Validate() != nil || retry.Outcome != identity.CommitOutcomeInProgress || failuresSeen.Load() != 1 {
		t.Fatal("failed original regenerated on retry", retryErr)
	}
	observed, recoverErr := failing.RecoverSignup(ctx, password.SignupRecoveryRequest{Recovery: failedResult.Recovery, Cookie: failed.Cookie, Caller: failed.Caller, Origin: failed.Origin, Network: failed.Network, Device: failed.Device})
	if observed.Outcome != identity.CommitOutcomeUnknown && observed.Outcome != identity.CommitOutcomeInProgress || observed.Validate() != nil || observed.VerificationRequired || failuresSeen.Load() != 1 {
		t.Fatal("incomplete generation guessed outcome or regenerated", recoverErr)
	}
	fq, _, _ := failedResult.Recovery.Bindings()
	fid, _ := base64.RawURLEncoding.DecodeString(string(fq.CommandID))
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.registration_bindings WHERE command_id=$1),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, fid, string(fq.CommandID)).Scan(&accounts, &messages, &grants); err != nil || accounts != 0 || messages != 0 || grants != 0 {
		t.Fatal("failed public attempt retained partial effects", err)
	}
	// SU06/08: fail actual audit persistence after final-plan attachment. No
	// fabricated terminal receipt or recovery contributor stands in for an owner.
	// Expire only this attempt's lease to exercise reconciliation without waiting
	// a minute; this tests an interrupted-state partition, not a lost network ACK.
	for _, mode := range []string{"absent", "existing-material"} {
		t.Run("expired-final-plan-"+mode, func(t *testing.T) {
			configuration := c
			configuration.ConfigurationID = "public-expired-" + mode
			if mode == "existing-material" {
				var existing string
				if err := pool.Raw().QueryRow(ctx, `SELECT user_id FROM identity.registration_bindings WHERE tenant_id=$1 AND command_id=$2`, string(r.TenantID), base64Command(t, result.Recovery)).Scan(&existing); err != nil {
					t.Fatal(err)
				}
				// A selected ID collision must not let this attempt adopt existing
				// password material as evidence that its own mutation rolled back.
				configuration.SelectUser = func(context.Context) (identity.UserID, error) { return identity.UserID(existing), nil }
			}
			native, err := NewSignupService(pool, configuration, keys)
			if err != nil {
				t.Fatal(err)
			}
			attempt := fresh("expired-"+mode+"@example.test", byte(70+len(mode)))
			if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT signup_recovery_test_stop CHECK(false) NOT VALID`); err != nil {
				t.Fatal(err)
			}
			before := screens.Load()
			pending, executionErr := native.Signup(ctx, attempt)
			if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings DROP CONSTRAINT signup_recovery_test_stop`); err != nil {
				t.Fatal(err)
			}
			var uncertain identity.UnknownCommitError
			if !errors.As(executionErr, &uncertain) || pending.Validate() != nil || pending.Outcome != identity.CommitOutcomeUnknown || screens.Load() != before+1 {
				t.Fatal("audit failure did not retain original uncertainty", executionErr)
			}
			id := base64Command(t, pending.Recovery)
			var state string
			var hasPlan bool
			if err := pool.Raw().QueryRow(ctx, `SELECT state, command_plan IS NOT NULL FROM identity.commands WHERE command_id=$1`, id).Scan(&state, &hasPlan); err != nil || state != "pending" || !hasPlan {
				t.Fatal("failed attempt lacks pending final plan", err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewSignupService(pool, configuration, keys)
			if err != nil {
				t.Fatal(err)
			}
			request := password.SignupRecoveryRequest{Recovery: pending.Recovery, Cookie: attempt.Cookie, Caller: attempt.Caller, Origin: attempt.Origin, Network: attempt.Network, Device: attempt.Device}
			recovered, recoveryErr := restarted.RecoverSignup(ctx, request)
			if recovered.Validate() != nil || !recovered.Replayed || recovered.VerificationRequired || recovered.SubjectID != "" || recovered.SessionID != "" || screens.Load() != before+1 {
				t.Fatal("reconciliation regenerated or disclosed authority", recoveryErr)
			}
			// Issuance owns positive original receipts, not negative evidence.
			// Missing grants cannot certify rollback even when other owners agree.
			if recovered.Outcome != identity.CommitOutcomeUnknown && recovered.Outcome != identity.CommitOutcomeInProgress || recoveryErr == nil {
				t.Fatal("missing issuance evidence certified rollback", recoveryErr)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, id).Scan(&state); err != nil || state != "pending" {
				t.Fatal("uncertain original command was finalized", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.registration_bindings WHERE command_id=$1),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM capability_identity_one_use WHERE origin_command_id=$2)`, id, string(uncertain.CommandID)).Scan(&accounts, &messages, &grants); err != nil || accounts != 0 || messages != 0 || grants != 0 {
				t.Fatal("recovery executed original effects", err)
			}
			testSignupPasswordOwnerRecovery(t, ctx, pool, restarted, request, mode == "absent")
		})
	}
	t.Run("selected-authorization-epoch", func(t *testing.T) {
		configuration := c
		configuration.AuthorizationNamespace = "signup-users"
		owner, err := NewSignupService(pool, configuration, keys)
		if err != nil || owner.profile == service.profile {
			t.Fatal("selected authority not bound to original preparation", err)
		}
		invalid := configuration
		invalid.AuthorizationNamespace = "signup users"
		if owner, err := NewSignupService(pool, invalid, keys); err == nil || owner != nil {
			t.Fatal("invalid policy namespace admitted")
		}
		attempt := fresh("authority-public@example.test", 'A')
		created, err := owner.Signup(ctx, attempt)
		if err != nil || created.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("authority-bearing signup", err)
		}
		var user, epoch string
		id := base64Command(t, created.Recovery)
		if err := pool.Raw().QueryRow(ctx, `SELECT b.user_id,a.version::text FROM identity.registration_bindings b JOIN authorization_subject_authorities a ON a.tenant_id=b.tenant_id AND a.subject_id=b.user_id AND a.policy_namespace='signup-users' WHERE b.command_id=$1`, id).Scan(&user, &epoch); err != nil || epoch != "1" {
			t.Fatal("created account lacks owned initial authorization epoch", err)
		}
		// A later lifecycle epoch is not creation state. Neutral acknowledgement
		// of an occupied address must not overwrite it or create another account.
		if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id=$1 AND subject_id=$2 AND policy_namespace='signup-users'`, string(attempt.TenantID), user); err != nil {
			t.Fatal(err)
		}
		occupied := fresh("authority-public@example.test", 'B')
		neutral, err := owner.Signup(ctx, occupied)
		if err != nil || neutral.Outcome != identity.CommitOutcomeCommitted || neutral.SubjectID != "" || neutral.SessionID != "" {
			t.Fatal("occupied authority-bearing signup enumerated", err)
		}
		var authorities int
		if err := pool.Raw().QueryRow(ctx, `SELECT version::text,(SELECT count(*) FROM authorization_subject_authorities WHERE policy_namespace='signup-users') FROM authorization_subject_authorities WHERE tenant_id=$1 AND subject_id=$2 AND policy_namespace='signup-users'`, string(attempt.TenantID), user).Scan(&epoch, &authorities); err != nil || epoch != "2" || authorities != 1 {
			t.Fatal("occupied signup reset or duplicated authority", err)
		}
		configuration.AuthorizationNamespace = "different-users"
		changed, err := NewSignupService(pool, configuration, keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := changed.Signup(ctx, attempt); err == nil {
			t.Fatal("different namespace adopted original keyed preparation")
		}
	})
}

// SU08: isolate the password owner's recovery contract using actual kernel,
// directory, audit and outbox owners. This reservation has no issuance/delivery
// declaration and is never executed; it is not a public verification workflow.
// Public recovery above must still respect every owner in its own frozen plan.
func testSignupPasswordOwnerRecovery(t *testing.T, ctx context.Context, pool *database.Pool, service *SignupService, request password.SignupRecoveryRequest, absent bool) {
	t.Helper()
	p := &signupPhase{service: service}
	reader, _, err := service.coordinator(p)
	if err != nil {
		t.Fatal(err)
	}
	q, _, _ := request.Recovery.Bindings()
	caller := request.Caller.Clone()
	c := service.config()
	caller.PolicyRevision = authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	k, wire, err := reader.QueryRequestPreparation(ctx, q, caller, p.registration(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	b, selected, _, _, err := service.repository.recoverSignupInput(ctx, service.crypto, k, service.profile, wire)
	if err != nil {
		t.Fatal(err)
	}
	b.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	fields, err := kernel.PasswordRegistrationFields(selected)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: b, Operation: passwordSignupOperation(), Fields: fields}, c.Screening.DummyHash.String(), request.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	p.original, p.input.selected = command, selected
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{service.directory, audits, outbox, p})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, c.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := signupExecutionPlan(coordinator, registry, p, command, time.Now().UTC(), kernel.CapabilityIssuancePlan{}, kernel.DeliveryPlan{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.ReserveCommand(ctx, b, command, plan); err != nil {
		t.Fatal(err)
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	result, recoveryErr := coordinator.RecoverFeatureCommand(ctx, signupQuery(b), caller)
	var state string
	if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if absent {
		if result.Outcome != identity.CommitOutcomeNotCommitted || state != "aborted" {
			t.Fatal("password owner could not prove absent material", recoveryErr)
		}
	} else if result.Outcome != identity.CommitOutcomeUnknown && result.Outcome != identity.CommitOutcomeInProgress || recoveryErr == nil || state != "pending" {
		t.Fatal("password owner treated contradictory material as rollback", recoveryErr)
	}
}

func base64Command(t *testing.T, recovery password.SignupRecovery) []byte {
	t.Helper()
	q, _, err := recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(q.CommandID))
	if err != nil || len(id) != 16 {
		t.Fatal("invalid original recovery correlation", err)
	}
	return id
}
