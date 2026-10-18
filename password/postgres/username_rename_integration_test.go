//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-identity/username"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Continue the genuinely registered/verified account. Password proof issuance,
// sessions, counters, identifier mutation and audit/outbox all use native owners.
// Only normalized external status observations use the declared policy seam.
func testNativeUsernameRename(t *testing.T, ctx context.Context, pool *database.Pool, signup SignupConfig, keys *keyring.Provider, original password.SignupRequest) {
	t.Helper()
	installLast := func(source migrations.Source) {
		t.Helper()
		h, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, h[len(h)-1].UpSQL()); err != nil {
			t.Fatal("rename native forward history", err)
		}
	}
	installLast(kernel.CounterPreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 30})
	// The ordinary password schema already contains the original proof table.
	// Keep installed signin purposes and add only the action consumption suffix.
	installLast(ActionReauthenticationMigrationSource{Base: UsernameSigninMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 10}, Version: 11})
	riskHistory := riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "username_rename_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}
	h, err := riskHistory.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range h {
		if _, err = pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("rename risk history", err)
		}
	}
	installLast(riskpg.VerificationCounterMigrationSource{Schema: "username_rename_risk", Version: 6})
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status"}},
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Profiles: profiles, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{101}, 32))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{102}, 32), bytes.Repeat([]byte{103}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counterConfig := riskpg.Config{Schema: "username_rename_risk", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"wrap": bytes.Repeat([]byte{104}, 32)}, CurrentEnvelopeKey: "wrap", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "status", Version: "rename-policy-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, nil
	}}, {Name: "velocity", Version: "native-counter-only", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
		return risk.Signal{}, errors.New("provider must not supply protected velocity")
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "signin-deployment", PolicyNamespace: signup.AuthorizationNamespace, Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	_, signinConfig := publicSigninFixture(t, pool, signup.Repository.HashPolicy, signup.Screening.Primitive, signup.Screening.DummyHash, signup.Session, profile)
	signinConfig.Username = signup.Username
	signin, err := NewSigninService(pool, signinConfig)
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(name string) password.SigninResult {
		t.Helper()
		request, _, _, _ := nativeSigninFlow(t)
		request.TenantID, request.Caller.Request.Tenant = original.TenantID, original.Caller.Request.Tenant
		request.Caller.Request.Action, request.Caller.Request.Resource.ID = "identity.username.signin", "identity.username.signin"
		request.Identifier, request.Password, request.Device = identifier.Input(name), original.Password, "rename-browser"
		request.PreAuthID, err = identity.NewPreAuthTransactionID()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		binding := session.PreAuthBinding{ID: request.PreAuthID, Intent: session.PreAuthIntent{TenantID: request.TenantID, Action: "identity.username.signin", Origin: request.Origin, CallbackURL: request.CallbackURL, Nonce: [32]byte{13}, Remember: request.Remember, PolicyID: signinConfig.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
		token, _ := session.ParseToken(request.Cookie.Token())
		d, e := token.PreAuthDigest(signinConfig.FlowKeys[0], binding)
		if e != nil {
			t.Fatal(e)
		}
		flow, e := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: d, Version: 1})
		if e != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, signinConfig.Session, flow) != nil {
			t.Fatal("rename genuine browser", e)
		}
		out, e := signin.Signin(ctx, request)
		if e != nil {
			t.Fatal("rename genuine signin", e)
		}
		return out
	}
	signed := signIn("STRASSE")
	if signed.State != auth.SignInStateAuthenticated {
		t.Fatal("rename fixture lacks genuine signin")
	}
	wire, err := signed.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := signed.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.username.update", Audience: "username-rename"}
	signing, err := NewReauthenticationSigningKey("username-rename", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{105}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	id, public := signing.public()
	reauthConfig := ReauthenticationConfig{Repository: signinConfig.Repository, Verifier: signinConfig.Verifier, Session: signup.Session, Profile: profile, LookupKeys: []session.DigestKey{signinConfig.Issuance.LookupKey}, Risk: signinConfig.Risk, Coordinator: signinConfig.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{id: public}, Issuer: signinConfig.Issuer, Environment: signinConfig.Environment, Targets: []ReauthenticationTarget{target}, TTL: time.Minute, IdentifierKey: bytes.Repeat([]byte{106}, 32)}
	source, err := NewReauthenticationService(pool, reauthConfig)
	if err != nil {
		t.Fatal("rename proof owner", err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: authorization.TenantID(original.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(bindings.UserID)}, Action: "identity.username.update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(bindings.UserID)}}}
	proofRequest := ReauthenticationRequest{TenantID: original.TenantID, Session: auth.NewBearerCredential(wire), Password: original.Password, Target: target, Caller: caller, Network: "192.0.2.10", Device: "rename-browser"}
	issued, err := source.Verify(ctx, proofRequest)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("rename actual fresh proof", err)
	}
	primary, err := NewActionPrimarySource(source, ActionPrimaryConfig{Action: target.Action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("username-rename", [32]byte{107}, *signinConfig.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	c := UsernameRenameConfig{PolicyID: "username-rename", ConfigurationID: "username-rename-v1", MaximumDuration: 5 * time.Second, Domain: kernel.UsernameRenameDomainConfig{NormalizationProfile: string(username.ProfileID), NormalizationVersion: username.ProfileVersion, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}, ReuseCooldown: 30 * 24 * time.Hour}, RequestKeys: requestKeys, IntentKey: [32]byte{108}, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "username-rename-v1", Keys: []risk.EvidenceKey{evidence}}, Counters: counterConfig, ActiveEnvelopeKeyID: signup.ActiveEnvelopeKeyID}
	var validatorCalls atomic.Int32
	var veto atomic.Bool
	var hook atomic.Pointer[func()]
	var raceMode atomic.Bool
	var arrivals atomic.Int32
	var raceGate chan struct{}
	spec := username.ReferencePolicySpec()
	spec.Validators = []username.Validator{func(ctx context.Context, _ username.Name) error {
		validatorCalls.Add(1)
		if raceMode.Load() {
			if arrivals.Add(1) == 2 {
				close(raceGate)
			}
			select {
			case <-raceGate:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if callback := hook.Swap(nil); callback != nil {
			(*callback)()
		}
		if veto.Load() {
			return username.ErrValidation
		}
		return nil
	}}
	selectedPolicy, err := username.NewPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	withoutLockouts := counterConfig
	withoutLockouts.EnforceLockouts = false
	badConfig := c
	badConfig.Counters = withoutLockouts
	if bad, e := NewUsernameRenameService(primary, selectedPolicy, badConfig, keys); e == nil || bad != nil {
		t.Fatal("rename accepted counter-only owner without current lockout enforcement")
	}
	service, err := NewUsernameRenameService(primary, selectedPolicy, c, keys)
	if err != nil {
		t.Fatal("rename native startup", err)
	}
	request := username.RenameRequest{TenantID: original.TenantID, Username: "renamed-name", Session: auth.NewBearerCredential(wire), Proof: issued.Proof, Caller: caller, Network: "192.0.2.10"}
	if err = pool.Raw().QueryRow(ctx, `SELECT identifier_id,version::bigint,verification_version::bigint FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='username'`, string(original.TenantID), string(bindings.UserID)).Scan(&request.IdentifierID, &request.ExpectedIdentifierVersion, &request.ExpectedVerificationVersion); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("original-native-rename"))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: signinConfig.Session, Profile: signinConfig.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: signinConfig.Profile.Audience, Clock: signinConfig.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{signinConfig.Issuance.LookupKey}}})
	if err != nil {
		t.Fatal(err)
	}
	assertSession := func(wire string, want bool) {
		t.Helper()
		token, e := session.ParseToken(wire)
		if e != nil {
			t.Fatal(e)
		}
		credential, e := session.NewCredential(session.CredentialBearer, token)
		if e != nil {
			t.Fatal(e)
		}
		current, e := reader.Get(ctx, session.GetRequest{TenantID: request.TenantID, Credential: credential})
		if current.Authenticated != want || want && e != nil {
			t.Fatal("rename session authority effect", e)
		}
	}
	assertSession(wire, true)
	assertUnchanged := func() {
		t.Helper()
		var current string
		var used bool
		if e := pool.Raw().QueryRow(ctx, `SELECT canonical_value,(SELECT consumed_command_id IS NOT NULL FROM identity_password.reauthentication_records WHERE proof_id=$3) FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2`, string(request.TenantID), string(request.IdentifierID), string(request.Proof.Proof.ID)).Scan(&current, &used); e != nil || current != "strasse" || used {
			t.Fatal("denial changed name or consumed proof", e)
		}
	}
	for index, mutate := range []func(*username.RenameRequest){
		func(r *username.RenameRequest) { r.Proof.Proof.Audience = "foreign" },
		func(r *username.RenameRequest) { r.Proof.Action = "identity.password.change" },
		func(r *username.RenameRequest) { r.Proof.SessionVersion++ },
		func(r *username.RenameRequest) { r.ExpectedIdentifierVersion++ },
		func(r *username.RenameRequest) { r.ExpectedVerificationVersion++ },
		func(r *username.RenameRequest) { r.IdentifierID = "absent-username" },
		func(r *username.RenameRequest) { r.Username = "admin" },
		func(r *username.RenameRequest) { r.Username = "invalid name" },
	} {
		bad := request
		key, e := identity.NewIdempotencyKey([]byte(fmt.Sprintf("denied-rename-%d", index)))
		if e != nil {
			t.Fatal(e)
		}
		bad.IdempotencyKey = key
		mutate(&bad)
		if result, e := service.Rename(ctx, bad); e == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("wrong original rename admitted", index)
		}
		assertUnchanged()
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, e := service.Rename(canceled, request); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled rename continued", e)
	}
	assertUnchanged()
	activation := func() {
		if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(bindings.UserID)); e != nil {
			t.Fatal(e)
		}
	}
	hook.Store(&activation)
	if result, e := service.Rename(ctx, request); e == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("factor activation after frozen observation admitted rename")
	}
	assertUnchanged()
	if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(bindings.UserID)); e != nil {
		t.Fatal(e)
	}
	// The original denied keyed preparation cannot acquire a fresh generation.
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("rollback-native-rename"))
	if err != nil {
		t.Fatal(err)
	}
	if _, e := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings ADD CONSTRAINT username_rename_fault CHECK(false) NOT VALID`); e != nil {
		t.Fatal(e)
	}
	failed, renameErr := service.Rename(ctx, request)
	if _, e := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings DROP CONSTRAINT username_rename_fault`); e != nil {
		t.Fatal("restore owned outbox failure", e)
	}
	if renameErr == nil || failed.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("required outbox failure committed rename")
	}
	assertUnchanged()
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("display-native-rename"))
	if err != nil {
		t.Fatal(err)
	}
	request.Username = "STRASSE"
	// Force both preparations past original user/name/factor reads before either
	// can execute. Each goroutine owns its bounded request; the parent drains both
	// buffered results before changing policy or leaving this fixture.
	raceGate = make(chan struct{})
	raceMode.Store(true)
	type renameAttempt struct {
		request username.RenameRequest
		result  identity.CommandResult
		err     error
	}
	attempts := make(chan renameAttempt, 2)
	for index := range 2 {
		r := request
		r.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(fmt.Sprintf("contended-native-rename-%d", index)))
		if err != nil {
			t.Fatal(err)
		}
		go func(r username.RenameRequest) { out, e := service.Rename(ctx, r); attempts <- renameAttempt{r, out, e} }(r)
	}
	var result identity.CommandResult
	winners := 0
	for range 2 {
		a := <-attempts
		if a.err == nil && a.result.Outcome == identity.CommitOutcomeCommitted {
			winners++
			request, result = a.request, a.result
		}
	}
	raceMode.Store(false)
	if winners != 1 || arrivals.Load() != 2 {
		t.Fatal("contended original proof did not have exactly one rename winner")
	}
	assertSession(wire, false)
	var display string
	var displayVersion, verificationVersion uint64
	var retirementCount int
	if err = pool.Raw().QueryRow(ctx, `SELECT display_value,version::bigint,verification_version::bigint,(SELECT count(*) FROM identity.identifier_retirements WHERE tenant_id=$1 AND kind='username') FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2`, string(request.TenantID), string(request.IdentifierID)).Scan(&display, &displayVersion, &verificationVersion, &retirementCount); err != nil || display != "STRASSE" || displayVersion != request.ExpectedIdentifierVersion+1 || verificationVersion != request.ExpectedVerificationVersion || retirementCount != 0 {
		t.Fatal("display-only rename changed canonical verification or retired name", err)
	}
	calls := validatorCalls.Load()
	veto.Store(true)
	restarted, err := NewUsernameRenameService(primary, selectedPolicy, c, keys)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		again, e := restarted.Rename(ctx, request)
		if e != nil || again.Outcome != identity.CommitOutcomeCommitted || again.Binding != result.Binding || validatorCalls.Load() != calls {
			t.Fatal("committed retry reran current enrollment or original proof", e)
		}
	}
	veto.Store(false)
	// A canonical change uses a new real session and independently issued proof;
	// display mutation already invalidated every identifier-bound old session.
	signed = signIn("STRASSE")
	if signed.State != auth.SignInStateAuthenticated {
		t.Fatal("display username cannot sign in")
	}
	wire, err = signed.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err = signed.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	proofRequest.Session = auth.NewBearerCredential(wire)
	issued, err = source.Verify(ctx, proofRequest)
	if err != nil {
		t.Fatal("fresh canonical rename proof", err)
	}
	request.Session, request.Proof = proofRequest.Session, issued.Proof
	request.ExpectedIdentifierVersion = displayVersion
	request.Username = "renamed-name"
	// Use the second actual mutation for explicit cookie transport; the
	// preceding rollback and two contenders retain their protected charges.
	// This keeps the real five-attempt reference limit, not a test-only quota.
	cookiePrimaryConfig := ActionPrimaryConfig{Action: target.Action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: []session.CSRFKey{signinConfig.CSRFKey}}
	cookiePrimary, e := NewActionPrimarySource(source, cookiePrimaryConfig)
	if e != nil {
		t.Fatal(e)
	}
	cookieConfig := c
	cookieConfig.ConfigurationID = "username-rename-cookie-v1"
	cookieConfig.RequestKeys, e = kernel.NewRequestKeyConfig("username-rename-cookie", [32]byte{109}, *signinConfig.Coordinator.QueryPolicy)
	if e != nil {
		t.Fatal(e)
	}
	service, err = NewUsernameRenameService(cookiePrimary, selectedPolicy, cookieConfig, keys)
	if err != nil {
		t.Fatal(err)
	}
	request.CSRFToken = signed.CSRFToken
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("canonical-native-rename"))
	if err != nil {
		t.Fatal(err)
	}
	assertSession(wire, true)
	missingCSRF := request
	missingCSRF.CSRFToken = session.CSRFToken{}
	if out, e := service.Rename(ctx, missingCSRF); e == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("cookie rename bypassed synchronizer")
	}
	// Drop only the final protected COMMIT acknowledgement, not any preparation
	// commit. The existing loopback fault transport leaves actual SQL/owners real.
	fault := &signinCommitFault{marker: "UPDATE identity.identifiers SET kind="}
	faulted, e := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
	if e != nil {
		t.Fatal("rename commit fault connection unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if faulted.Close(cleanup) != nil {
			t.Error("rename fault pool cleanup")
		}
	}()
	faultSource, e := NewReauthenticationService(faulted, reauthConfig)
	if e != nil {
		t.Fatal(e)
	}
	faultPrimary, e := NewActionPrimarySource(faultSource, cookiePrimaryConfig)
	if e != nil {
		t.Fatal(e)
	}
	faultService, e := NewUsernameRenameService(faultPrimary, selectedPolicy, cookieConfig, keys)
	if e != nil {
		t.Fatal(e)
	}
	unknown, e := faultService.Rename(ctx, request)
	if e == nil || !fault.hit.Load() || unknown.Outcome != identity.CommitOutcomeUnknown || unknown.Binding.OperationID != "identity.username.update" {
		t.Fatal("rename interruption fabricated acknowledgement or lost original scope", e)
	}
	result, err = service.Rename(ctx, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != unknown.Binding {
		t.Fatal("native username rename did not recover its original commit", err)
	}
	assertSession(wire, false)
	var canonical string
	var version, authority uint64
	var retired, consumed int
	vector, vectorErr := bindings.Authority.Bindings()
	if err = pool.Raw().QueryRow(ctx, `SELECT i.canonical_value,i.version::bigint,u.identifier_version::bigint,(SELECT count(*) FROM identity.identifier_retirements WHERE tenant_id=i.tenant_id AND kind='username'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE proof_id=$3 AND consumed_purpose='identity.username.update') FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id=$1 AND i.identifier_id=$2`, string(request.TenantID), string(request.IdentifierID), string(request.Proof.Proof.ID)).Scan(&canonical, &version, &authority, &retired, &consumed); err != nil || vectorErr != nil || canonical != request.Username || version != request.ExpectedIdentifierVersion+1 || authority != vector.Identifier.Version+1 || retired != 1 || consumed != 1 {
		t.Fatal("rename/proof/retirement effects not atomic", err)
	}
	for range 2 {
		again, e := service.Rename(ctx, request)
		if e != nil || again.Outcome != identity.CommitOutcomeCommitted || again.Binding != result.Binding {
			t.Fatal("exact rename retry lost original outcome", e)
		}
	}
	for _, candidate := range []string{"different-name", "RENAMED-NAME"} {
		changed := request
		changed.Username = candidate
		if _, err = service.Rename(ctx, changed); err == nil {
			t.Fatal("same rename key remapped raw input")
		}
	}
	if old := signIn("STRASSE"); old.State != auth.SignInStateRejected {
		t.Fatal("old username still authenticates")
	}
	next := signIn("renamed-name")
	if next.State != auth.SignInStateAuthenticated {
		t.Fatal("new username cannot authenticate")
	}
	wire, err = next.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	assertSession(wire, true)
	proofRequest.Session = auth.NewBearerCredential(wire)
	issued, err = source.Verify(ctx, proofRequest)
	if err != nil {
		t.Fatal(err)
	}
	returning := request
	returning.Session, returning.Proof, returning.Username = proofRequest.Session, issued.Proof, "STRASSE"
	returning.CSRFToken = next.CSRFToken
	returning.ExpectedIdentifierVersion = version
	if err = pool.Raw().QueryRow(ctx, `SELECT verification_version::bigint FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2`, string(request.TenantID), string(request.IdentifierID)).Scan(&returning.ExpectedVerificationVersion); err != nil {
		t.Fatal(err)
	}
	returning.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("retired-name-reuse"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome, e := service.Rename(ctx, returning); e == nil || outcome.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("retired name reused during cooldown")
	}
	var used bool
	if e := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(returning.Proof.Proof.ID)).Scan(&used); e != nil || used {
		t.Fatal("cooldown denial consumed fresh proof", e)
	}
	assertSession(wire, true)
	b := result.Binding
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	history, e := service.RenameRecover(ctx, query, caller)
	if e != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != b {
		t.Fatal("native rename metadata recovery lost original scope", e)
	}
	foreign := query
	foreign.UserID = "other-user"
	if _, e := service.RenameRecover(ctx, foreign, caller); e == nil {
		t.Fatal("foreign username outcome disclosed")
	}
	last := signIn("renamed-name")
	if last.State != auth.SignInStateAuthenticated {
		t.Fatal("cookie-renamed username cannot sign in")
	}
	lastWire, e := last.Issuance.Token.Reveal()
	if e != nil {
		t.Fatal(e)
	}
	assertSession(lastWire, true)
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{signinConfig.Issuance.LookupKey}}
	logout, e := sessionpg.NewSignOutService(pool, sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: signinConfig.Session, Profile: sessionpg.IssueAdmissionConfig(profile), Coordinator: signinConfig.Coordinator, Authorization: signinConfig.Coordinator.QueryPolicy.Authorization, Clock: signinConfig.Issuance.Clock, PolicyID: signinConfig.PolicyID, PolicyVersion: 3, AuditRetentionVersion: 1}, Validation: validation, Cookie: signinConfig.Issuance.Cookie, MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	lastToken, e := session.ParseToken(lastWire)
	if e != nil {
		t.Fatal(e)
	}
	credential, e := session.NewCredential(session.CredentialBearer, lastToken)
	if e != nil {
		t.Fatal(e)
	}
	logoutID, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	left, e := logout.SignOut(ctx, session.SignOutRequest{TenantID: request.TenantID, CommandID: logoutID, CorrelationID: string(logoutID), Transport: session.CredentialBearer, Credential: credential})
	if e != nil || !left.SignedOut || left.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("renamed username session cannot log out", e)
	}
	assertSession(lastWire, false)
}
