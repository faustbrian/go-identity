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

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// SU01/05/07/08: public methods, real journal and all effect owners; callbacks
// replace only provider observations and canonical ID selection, never stores.
func testNativePublicSignup(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, original signupKeyPreparation, schema identity.AttributeSchema, keys *keyring.Provider, generation signupGenerationPreparation, riskConfig risk.AuthenticationAdmissionCustodyConfig, request password.SignupRequest) {
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
	r := fresh("public-signup@example.test", 'S')
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
	restarted, err := NewSignupService(pool, c, keys)
	if err != nil {
		t.Fatal(err)
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
}
