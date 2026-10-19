//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func emailRemovalReplacesPrimary(mode string) bool { return strings.HasPrefix(mode, "removal-replace") }
func emailRemovalCreatesPrimary(mode string) bool {
	return mode == "removal-primary" || emailRemovalReplacesPrimary(mode)
}

func TestReferencePostgresEmailRemovalReplacementPrimary(t *testing.T) {
	for _, mode := range []string{"removal-replace", "removal-replace-http", "removal-replace-rollback", "removal-replace-contention", "removal-replace-unknown"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: mode, completionCommitFault: mode == "removal-replace-unknown"})
		})
	}
}

func TestReferencePostgresEmailRemovalKeepsVerifiedSigninReset(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal"})
}

func TestReferencePostgresEmailRemovalRetiresPendingLink(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-pending"})
}

func TestReferencePostgresEmailRemovalDenialsAndRollback(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-rollback"})
}

func TestReferencePostgresEmailRemovalHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-http"})
}

func TestReferencePostgresEmailRemovalIndependentRateMigrations(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-only-http"})
}

// Install and exercise the removal limiter before any other HTTP selector can
// contribute its atomic migration. No identity authority is fabricated: the
// synthetic user below scopes only this generic rate-admission probe. The full
// original HTTPS journey then creates and authenticates its real account.
func proveIndependentRemovalRateMigrations(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, d reference.ReferenceDependencies, workers []deliverypg.WorkerConfig, modules []reference.ModuleID) {
	t.Helper()
	c.HTTPRegistrationVerification, c.HTTPPasswordReset, c.HTTPPasswordVerification, c.HTTPPasswordChange, c.HTTPMagicLink = nil, nil, nil, nil, nil
	c.HTTPPhoneVerification, c.HTTPEmailOTPVerification, c.HTTPUsername = nil, nil, nil
	operation, path := "identity.email.address-remove", "/v1/email/address-remove"
	if c.HTTPPhoneRemoval != nil {
		c.HTTPEmailRequests = nil
		operation, path = "identity.phone.remove", "/v1/phone/remove"
	}
	stores, err := reference.ComposeStores(c, d)
	if err != nil {
		t.Fatal("independent removal stores", err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error("independent removal graph cleanup", err)
		}
	}()
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workerSet, err := reference.ComposeWorkers(stores, providers, workers...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reference.ComposeFeatures(stores, providers, workerSet); err != nil {
		t.Fatal(err)
	}
	request := applyRequest(t, ctx, stores, modules)
	request.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("independent-removal-operator-plan"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores.ReferenceMigrationApply(ctx, request); err != nil {
		t.Fatal("independent removal operator migration", err)
	}
	r := c.HTTPRate
	backend, err := ratepg.NewStrict(f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: r.Timeout, LockTimeout: r.LockTimeout, Clock: ratepg.ServerClock}, RollbackTimeout: r.RollbackTimeout})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: r.Namespace, Key: r.IdentifierKey, Now: time.Now, MaximumDuration: r.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	defer limiter.Close()
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}})
	if err != nil {
		t.Fatal(err)
	}
	probe := httptest.NewRequest(http.MethodPost, path, nil)
	probe.Host, probe.RemoteAddr = "127.0.0.1", "127.0.0.1:1234"
	facts, err := network.Resolve(probe)
	if err != nil {
		t.Fatal("independent rate transport facts", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("independent-removal-migration"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := limiter.Admit(ctx, facts, identityhttp.KeyedSecretRateRequest{OperationID: operation, UserID: "synthetic-rate-subject", IdempotencyKey: key}); err != nil || !out.Allowed {
		t.Fatal("independent removal migration omitted usable atomic rate admission", err)
	}
}

func TestReferencePostgresEmailRemovalPrimaryDisposition(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-primary"})
}

func TestReferencePostgresEmailRemovalCommitUnknown(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-unknown", completionCommitFault: true})
}

func TestReferencePostgresEmailRemovalConcurrentAttempts(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-contention"})
}

func TestReferencePostgresEmailRemovalPopulatedUpgrade(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailRemoval: true, emailChangeCase: "removal-upgrade"})
}

func configureReferenceEmailRemovalPrimary(c *reference.StoreConfiguration) {
	selected := *c.Email.Verification
	selected.Native.Change = &email.ChangeProfile{CurrentAddress: email.PrimaryOrSoleVerifiedAddress, Sessions: email.InvalidateIdentifierSessions}
	selected.Native.ChangeNotification = &passwordpg.EmailChangeNotificationConfig{TemplateID: "email-change-notice", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{214}, Timeout: time.Second}
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "email-change-notice", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: emailChangeNotice, ContentType: "text/plain", MaxRenderedBytes: 4096})
	c.Email.Change = &selected
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.email.change-request", Audience: "reference-managed-email"})
}

func configureReferenceEmailRemoval(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	// Newly issued verification grants must retain their signed target; legacy
	// unclassified live grants intentionally deny removal instead of guessing.
	c.Email.Verification.Native.Issuer.RetainEmailVerificationTargets = true
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.email.address-remove", Audience: "reference-managed-email"})
	keys, err := kernel.NewRequestKeyConfig("reference-email-removal", [32]byte{231}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := passwordpg.NewKeyedEmailManagementConfig(keys, [32]byte{232})
	if err != nil {
		t.Fatal(err)
	}
	n := c.Email.Verification.Native
	cascade := kernel.IdentifierRemovalCascadeConfig{PolicyVersion: 101, Reasons: []string{"user-requested"}, MaximumDuration: time.Hour, ConsumerContracts: map[string]kernel.StatusConsumerContract{}}
	for _, id := range identity.IdentifierRemovalConsumers() {
		// Synthetic contract identities configure this test's pending manifest;
		// no absent adapter is asserted applied or not-applicable.
		cascade.ConsumerContracts[id] = kernel.StatusConsumerContract{Version: 1, Fingerprint: sha256.Sum256([]byte("synthetic-removal-contract-v1:" + id))}
	}
	c.Email.Removal = &reference.EmailRemovalConfiguration{Native: passwordpg.EmailRemovalConfig{PolicyID: "email-removal", ConfigurationID: "reference-email-removal", MaximumDuration: c.OTP.Timeout, Domain: kernel.EmailRemovalDomainConfig{Directory: n.Domain, ReuseCooldown: time.Hour, Cascade: cascade}, Keyed: keyed, Risk: risk.ProtectedProviderAdmissionCustodyConfig{ConfigurationID: "reference-email-removal"}, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID}, Primary: passwordpg.EmailPrimaryConfig{Audience: "reference-managed-email", MaximumAge: 2 * time.Minute, Transport: c.Email.Verification.Primary.Transport}, Counters: c.PasswordSignup.Counters}
}

func proveReferenceEmailRemoval(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, user identity.UserID, token capability.Proof, pending identity.IdentifierID, source passwordpg.EmailManagementRequest, cookies []*http.Cookie, originalCSRF string, readSession func([]*http.Cookie) bool, freshLogin func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	owner, err := features.EmailRemoval()
	if err != nil {
		t.Fatal("selected native removal unavailable", err)
	}
	var cascadeSchema bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT FROM information_schema.columns WHERE table_schema='identity' AND table_name='status_cascades' AND column_name='identifier_id')`).Scan(&cascadeSchema); err != nil || !cascadeSchema {
		t.Fatal("selected removal bootstrap omitted native cascade migration", err)
	}
	target, remaining := "registered@example.invalid", "additional@example.invalid"
	if emailRemovalCreatesPrimary(f.emailRemovalMode) {
		target, remaining = "primary@example.invalid", "registered@example.invalid"
	}
	if f.emailRemovalMode == "removal-pending" {
		target, remaining = remaining, target
	}
	var address string
	var versionText, verificationText string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version::text,verification_version::text FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND canonical_value=$3`, otpTenant, string(user), target).Scan(&address, &versionText, &verificationText); err != nil {
		t.Fatal(err)
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := strconv.ParseUint(verificationText, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	disposition := email.LeavePrimaryUnassigned
	if f.emailRemovalMode == "removal-pending" {
		disposition = email.PreserveRemainingPrimary
	}
	key, _ := identity.NewIdempotencyKey([]byte("original-email-removal"))
	r := email.AddressRemoveRequest{TenantID: otpTenant, AddressID: identity.IdentifierID(address), ExpectedIdentifierVersion: version, ExpectedVerificationVersion: verification, Reason: "user-requested", PrimaryDisposition: disposition, RecoveryDisposition: email.PreserveVerifiedEmailRecovery, IdempotencyKey: key, Primary: email.RequestPrimary{Session: source.Primary.Session, Proof: source.Primary.Proof, CSRFToken: source.Primary.CSRFToken}, Caller: source.Primary.Caller, Network: "127.0.0.1"}
	actor, actorCookies, actorCSRF := user, cookies, originalCSRF
	var requireActorUnchanged func()
	if strings.HasPrefix(f.emailRemovalMode, "removal-admin") {
		r.Primary, actor, actorCookies, actorCSRF, requireActorUnchanged = prepareAdministrativeEmailRemoval(t, ctx, f, features, workers, client, base, origin, messages, user, readSession)
		r.TargetSubjectID = user
		r.Caller = authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: "identity.email.address-remove", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
		if out, err := owner.AddressRemove(ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted || !readSession(cookies) {
			t.Fatal("authenticated administrator without exact grant removed target", err)
		}
		f.adminEmailGrant.mu.Lock()
		f.adminEmailGrant.actor, f.adminEmailGrant.target = actor, user
		f.adminEmailGrant.mu.Unlock()
	}
	var replacementAt time.Time
	var previousUser, previousAuthority uint64
	if emailRemovalReplacesPrimary(f.emailRemovalMode) {
		var id, iv, vv, uv, av string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT i.identifier_id,i.version::text,i.verification_version::text,i.verified_at,u.version::text,u.identifier_version::text FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.canonical_value=$3 AND i.verified AND NOT i.is_primary`, otpTenant, string(user), remaining).Scan(&id, &iv, &vv, &replacementAt, &uv, &av); err != nil {
			t.Fatal("actual versioned replacement unavailable", err)
		}
		r.PrimaryDisposition = email.ReplacePrimaryWithVerifiedEmail
		r.ReplacementPrimary.ID = identity.IdentifierID(id)
		r.ReplacementPrimary.ExpectedIdentifierVersion, _ = strconv.ParseUint(iv, 10, 64)
		r.ReplacementPrimary.ExpectedVerificationVersion, _ = strconv.ParseUint(vv, 10, 64)
		previousUser, _ = strconv.ParseUint(uv, 10, 64)
		previousAuthority, _ = strconv.ParseUint(av, 10, 64)
	}
	if emailRemovalCreatesPrimary(f.emailRemovalMode) {
		var primary bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT is_primary FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), address).Scan(&primary); err != nil || !primary {
			t.Fatal("primary removal fixture never designated actual primary", err)
		}
		denied := r
		denied.PrimaryDisposition = email.PreserveRemainingPrimary
		denied.ReplacementPrimary = identity.IdentifierPrimarySelection{}
		denied.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("primary-removal-without-disposition"))
		if out, err := owner.AddressRemove(ctx, denied); err == nil || out.Outcome == identity.CommitOutcomeCommitted || !readSession(cookies) {
			t.Fatal("removed primary without explicit disposition", err)
		}
	}
	if actual, err := owner.AddressRemoveRateSource(ctx, r); err != nil || actual != actor {
		t.Fatal("removal lacks authenticated original rate scope", err)
	}
	snapshot := func() string {
		t.Helper()
		var metadata string
		err := f.pool.Raw().QueryRow(ctx, `SELECT ROW(u.version,u.identifier_version,
(SELECT count(*) FROM identity.identifiers WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT count(*) FROM identity.identifier_retirements WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT count(*) FROM identity.status_cascades WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT COALESCE(jsonb_agg(jsonb_build_array(identifier_id,version,verification_version,is_primary) ORDER BY identifier_id),'[]') FROM identity.identifiers WHERE tenant_id=u.tenant_id AND user_id=u.user_id),
(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use WHERE tenant_id=u.tenant_id AND subject_id=u.user_id),
(SELECT count(*) FROM capability_identity_one_use WHERE tenant_id=u.tenant_id AND subject_id=u.user_id AND state='revoked'))::text
FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)).Scan(&metadata)
		if err != nil {
			t.Fatal("removal effect snapshot unavailable", err)
		}
		return metadata
	}
	before := snapshot()
	proofConsumed := func() bool {
		t.Helper()
		var consumed bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3`, otpTenant, string(actor), string(r.Primary.Proof.Proof.ID)).Scan(&consumed); err != nil {
			t.Fatal("original actor proof observation", err)
		}
		return consumed
	}
	if proofConsumed() {
		t.Fatal("rate or source admission consumed original proof")
	}
	if f.emailRemovalMode == "removal-admin-rollback" {
		// Rate-source admission above has retained the genuine original request.
		// Withdraw only A's exact grant to B; A's general authority epoch and
		// session remain unchanged and cannot substitute for target permission.
		f.adminEmailGrant.mu.Lock()
		f.adminEmailGrant.deny = true
		f.adminEmailGrant.mu.Unlock()
		out, denied := owner.AddressRemove(ctx, r)
		f.adminEmailGrant.mu.Lock()
		f.adminEmailGrant.deny = false
		f.adminEmailGrant.mu.Unlock()
		if denied == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || proofConsumed() || !readSession(cookies) {
			t.Fatal("retained administrative request bypassed withdrawn target permission", denied)
		}
		// Denied preparation retains its own original journal, not rollback
		// proof. A later independent request uses a new explicit key.
		r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("administrative-removal-after-restored-permission"))
	}
	if f.emailRemovalMode == "removal-admin-rollback" {
		// Negative storage injection only: neither this count nor absence stands
		// in for a genuine enrolled factor or authorizes a successful operation.
		// Both identities were created with authoritative known-empty MFA by
		// registration; restore only those exact original rows after each denial.
		for _, subject := range []identity.UserID{actor, user} {
			if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id=$1 AND user_id=$2 AND active_factors=0`, otpTenant, string(subject)); err != nil {
				t.Fatal(err)
			}
			out, denied := owner.AddressRemove(ctx, r)
			if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0 WHERE tenant_id=$1 AND user_id=$2 AND active_factors=1`, otpTenant, string(subject)); err != nil {
				t.Fatal("original empty-factor authority restore", err)
			}
			if denied == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) {
				t.Fatal("nonempty actor or target factors downgraded to password-only", denied)
			}
		}
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE identity_mfa.factor_authorities RENAME TO unavailable_factor_authorities`); err != nil {
			t.Fatal(err)
		}
		out, denied := owner.AddressRemove(ctx, r)
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE identity_mfa.unavailable_factor_authorities RENAME TO factor_authorities`); err != nil {
			t.Fatal("original factor authority restoration", err)
		}
		if denied == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) {
			t.Fatal("unavailable factor authority inferred empty MFA", denied)
		}
	}
	if emailRemovalReplacesPrimary(f.emailRemovalMode) {
		for _, mode := range []string{"self", "absent", "identifier-version", "verification-version", "old-disposition"} {
			bad := r
			bad.Caller = r.Caller.Clone()
			bad.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("replacement-denied-" + mode))
			switch mode {
			case "self":
				bad.ReplacementPrimary.ID = r.AddressID
			case "absent":
				bad.ReplacementPrimary.ID = "absent-address"
			case "identifier-version":
				bad.ReplacementPrimary.ExpectedIdentifierVersion++
			case "verification-version":
				bad.ReplacementPrimary.ExpectedVerificationVersion++
			case "old-disposition":
				bad.PrimaryDisposition = email.LeavePrimaryUnassigned
			}
			if out, err := owner.AddressRemove(ctx, bad); err == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) {
				t.Fatal("invalid replacement changed protected state", mode, err)
			}
		}
	}
	if f.emailRemovalMode == "removal-rollback" || f.emailRemovalMode == "removal-replace-rollback" || f.emailRemovalMode == "removal-admin-rollback" {
		denials := []string{"tenant", "actor", "stale-address", "stale-verification", "proof-action", "primary", "cancel"}
		if r.TargetSubjectID != "" {
			denials = append(denials, "target", "foreign-target", "actor-session", "actor-proof", "actor-csrf", "stale-proof")
		}
		for _, mode := range denials {
			invalid := r
			invalid.Caller = r.Caller.Clone()
			invalid.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("removal-denied-" + mode))
			callContext := ctx
			switch mode {
			case "tenant":
				invalid.TenantID = "foreign"
			case "actor":
				invalid.Caller.Request.Subject.ID = "AAAAAAAAAAAAAAAAAAAAAw"
			case "stale-address":
				invalid.ExpectedIdentifierVersion++
			case "stale-verification":
				invalid.ExpectedVerificationVersion++
			case "proof-action":
				invalid.Primary.Proof.Action = "identity.email.change-request"
			case "target":
				invalid.TargetSubjectID = actor
			case "foreign-target":
				invalid.TargetSubjectID = "absent-target"
				invalid.Caller.Request.Resource.ID = "absent-target"
			case "actor-session":
				invalid.Primary.Session = source.Primary.Session
			case "actor-proof":
				invalid.Primary.Proof = source.Primary.Proof
			case "actor-csrf":
				invalid.Primary.CSRFToken = source.Primary.CSRFToken
			case "stale-proof":
				invalid.Primary.Proof.SessionVersion++
			case "primary":
				invalid.PrimaryDisposition = 0
			case "cancel":
				cancelled, stop := context.WithCancel(ctx)
				stop()
				callContext = cancelled
			}
			out, err := owner.AddressRemove(callContext, invalid)
			if err == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) {
				t.Fatal("denied removal changed protected state", mode, err)
			}
		}
		// Force failure after directory mutation at the final manifest row. The
		// database and transactions are real; only this late failure is injected.
		_, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.fail_removal_manifest() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.ordinal=9 THEN RAISE EXCEPTION 'synthetic late removal failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER fail_removal_manifest BEFORE INSERT ON identity.status_consumers FOR EACH ROW EXECUTE FUNCTION public.fail_removal_manifest()`)
		if err != nil {
			t.Fatal(err)
		}
		out, failed := owner.AddressRemove(ctx, r)
		if failed == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !readSession(cookies) || proofConsumed() {
			t.Fatal("late removal failure leaked protected effects", failed)
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER fail_removal_manifest ON identity.status_consumers; DROP FUNCTION public.fail_removal_manifest()`); err != nil {
			t.Fatal(err)
		}
		if r.TargetSubjectID != "" {
			// A known final rollback is terminal historical metadata, not an
			// unfinished request. Withdrawing mutation permission must not turn
			// its exact replay into another execution or change the outcome.
			originalOutcome := out.Outcome
			f.adminEmailGrant.mu.Lock()
			f.adminEmailGrant.deny = true
			f.adminEmailGrant.mu.Unlock()
			out, denied := owner.AddressRemove(ctx, r)
			f.adminEmailGrant.mu.Lock()
			f.adminEmailGrant.deny = false
			f.adminEmailGrant.mu.Unlock()
			if denied != nil || out.Outcome != originalOutcome || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || proofConsumed() || !readSession(cookies) {
				t.Fatal("withdrawn grant changed terminal rollback receipt", out.Outcome, originalOutcome, denied)
			}
		}
		r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("new-attempt-after-proven-rollback"))
	}
	var originalHTTP []byte
	invokeHTTP := func() []byte {
		t.Helper()
		primary := "preserve-primary"
		if r.PrimaryDisposition == email.LeavePrimaryUnassigned {
			primary = "leave-unassigned"
		}
		fields := map[string]string{"proofID": string(r.Primary.Proof.Proof.ID), "addressID": string(r.AddressID), "expectedIdentifierVersion": strconv.FormatUint(r.ExpectedIdentifierVersion, 10), "expectedVerificationVersion": strconv.FormatUint(r.ExpectedVerificationVersion, 10), "reason": string(r.Reason), "primaryDisposition": primary, "recoveryDisposition": "preserve-verified-email"}
		if r.TargetSubjectID != "" {
			fields["targetSubjectID"] = string(r.TargetSubjectID)
		}
		if r.PrimaryDisposition == email.ReplacePrimaryWithVerifiedEmail {
			fields["primaryDisposition"] = "replace-primary"
			fields["replacementAddressID"] = string(r.ReplacementPrimary.ID)
			fields["expectedReplacementIdentifierVersion"] = strconv.FormatUint(r.ReplacementPrimary.ExpectedIdentifierVersion, 10)
			fields["expectedReplacementVerificationVersion"] = strconv.FormatUint(r.ReplacementPrimary.ExpectedVerificationVersion, 10)
		}
		body, _ := json.Marshal(fields)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/email/address-remove", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", actorCSRF)
		request.Header.Set("Idempotency-Key", "original-email-removal")
		for _, cookie := range actorCookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("removal HTTP unavailable", err)
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(wire) > 16384 || response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("protected removal HTTP response", response.StatusCode)
		}
		var out emailhttp.RemovalResponse
		if json.Unmarshal(wire, &out) != nil || !out.Removed || out.CommitOutcome != "committed" || out.CascadeID == "" || out.CascadeGeneration != 1 || out.CascadeStatus != "pending" {
			t.Fatal("HTTP removal lacks pending admission")
		}
		return wire
	}
	if f.emailRemovalMode == "removal-http" || f.emailRemovalMode == "removal-only-http" || f.emailRemovalMode == "removal-replace-http" || f.emailRemovalMode == "removal-admin-http" {
		originalHTTP = invokeHTTP()
	}
	var result identity.CommandResult
	if f.emailRemovalMode == "removal-contention" || f.emailRemovalMode == "removal-replace-contention" || f.emailRemovalMode == "removal-admin-contention" {
		type attempt struct {
			request email.AddressRemoveRequest
			result  identity.CommandResult
			err     error
		}
		start := make(chan struct{})
		done := make(chan attempt, 2)
		for n := range 2 {
			candidate := r
			candidate.Caller = r.Caller.Clone()
			candidate.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("concurrent-removal-" + strconv.Itoa(n)))
			go func() { <-start; out, e := owner.AddressRemove(ctx, candidate); done <- attempt{candidate, out, e} }()
		}
		close(start)
		committed := 0
		for range 2 {
			out := <-done
			if out.result.Outcome == identity.CommitOutcomeCommitted {
				if out.err != nil {
					t.Fatal("committed contender has error")
				}
				committed++
				r, result = out.request, out.result
			}
		}
		if committed != 1 {
			t.Fatal("concurrent target/proof removal did not have exactly one winner", committed)
		}
	} else {
		if f.completionFault != nil {
			f.completionFault.armed.Store(true)
		}
		result, err = owner.AddressRemove(ctx, r)
		if f.completionFault != nil {
			f.completionFault.armed.Store(false)
			if err == nil || result.Outcome != identity.CommitOutcomeUnknown || result.Cascade != nil || !f.completionFault.hit.Load() {
				t.Fatal("lost removal acknowledgement claimed success or rollback", err)
			}
			if f.emailRemovalMode == "removal-admin-output-unknown" {
				var pending int
				if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.email.address-remove' AND state='pending' AND preparation_ciphertext IS NOT NULL AND command_plan IS NULL`, otpTenant).Scan(&pending); err != nil || pending != 1 || snapshot() != before || proofConsumed() {
					t.Fatal("lost output acknowledgement did not retain genuine unfinished preparation", pending, err)
				}
				wait(ctx, t, 2*time.Second)
				f.adminEmailGrant.mu.Lock()
				f.adminEmailGrant.deny = true
				f.adminEmailGrant.mu.Unlock()
				denied, denyErr := owner.AddressRemove(ctx, r)
				f.adminEmailGrant.mu.Lock()
				f.adminEmailGrant.deny = false
				f.adminEmailGrant.mu.Unlock()
				if denyErr == nil || denied.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || proofConsumed() {
					t.Fatal("unfinished restored output bypassed withdrawn target permission", denied.Outcome, denyErr)
				}
				wait(ctx, t, 2*time.Second)
				result, err = owner.AddressRemove(ctx, r)
			} else {
				q := identity.RecoveryQuery{CommandID: result.Binding.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: "identity.email.address-remove", RecordID: address}
				result, err = owner.AddressRemoveRecover(ctx, q, r.Caller)
			}
		}
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Validate() != nil || result.Cascade == nil || result.Cascade.Status != identity.RevocationPending || len(result.Cascade.Owners) != 10 {
		t.Fatal("actual protected removal", result.Outcome, err)
	}
	if result.Binding.UserID != user || result.Binding.ActorID != identity.ActorID(actor) || result.Cascade.UserID != user {
		t.Fatal("administrative actor substituted for target effects")
	}
	if !proofConsumed() {
		t.Fatal("committed removal did not consume original actor proof")
	}
	if requireActorUnchanged != nil {
		requireActorUnchanged()
	}
	if emailRemovalReplacesPrimary(f.emailRemovalMode) {
		var iv, vv, uv, av string
		var at time.Time
		var primary bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT i.version::text,i.verification_version::text,i.verified_at,i.is_primary,u.version::text,u.identifier_version::text FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3`, otpTenant, string(user), string(r.ReplacementPrimary.ID)).Scan(&iv, &vv, &at, &primary, &uv, &av); err != nil || !primary || iv != strconv.FormatUint(r.ReplacementPrimary.ExpectedIdentifierVersion+1, 10) || vv != strconv.FormatUint(r.ReplacementPrimary.ExpectedVerificationVersion, 10) || !at.Equal(replacementAt) || uv != strconv.FormatUint(previousUser+1, 10) || av != strconv.FormatUint(previousAuthority+1, 10) {
			t.Fatal("removal/promotion lost one atomic generation or renewed verification", err)
		}
	}
	var publishedCascade, publishedGeneration string
	var published int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*),COALESCE(min(convert_from(payload,'UTF8')::jsonb->>'cascade_id'),''),COALESCE(min(convert_from(payload,'UTF8')::jsonb->>'cascade_generation'),'')
FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1 AND topic='identifier.removed.v1'`, string(result.Binding.CommandID)).Scan(&published, &publishedCascade, &publishedGeneration); err != nil || published != 1 || publishedCascade != string(result.Cascade.CascadeID) || publishedGeneration != strconv.FormatUint(result.Cascade.Generation, 10) {
		t.Fatal("published removal lost original cascade correlation", err)
	}
	if readSession(cookies) {
		t.Fatal("identifier removal retained old session authority")
	}
	if actual, err := owner.AddressRemoveRateSource(ctx, r); err != nil || actual != actor {
		t.Fatal("rate scope renewed or lost original retry custody", err)
	}
	replay, err := owner.AddressRemove(ctx, r)
	if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Cascade == nil || replay.Cascade.CascadeID != result.Cascade.CascadeID || replay.Feature == nil || *replay.Feature != *result.Feature {
		t.Fatal("spent-proof retry lost original admission", err)
	}
	if r.TargetSubjectID != "" {
		f.adminEmailGrant.mu.Lock()
		f.adminEmailGrant.deny = true
		f.adminEmailGrant.mu.Unlock()
		historical, historicalErr := owner.AddressRemove(ctx, r)
		f.adminEmailGrant.mu.Lock()
		f.adminEmailGrant.deny = false
		f.adminEmailGrant.mu.Unlock()
		if historicalErr != nil || historical.Outcome != identity.CommitOutcomeCommitted || historical.Cascade == nil || historical.Cascade.CascadeID != result.Cascade.CascadeID || historical.Binding != result.Binding {
			t.Fatal("withdrawn mutation grant altered terminal original receipt", historicalErr)
		}
	}
	if originalHTTP != nil {
		if again := invokeHTTP(); !bytes.Equal(originalHTTP, again) {
			t.Fatal("HTTP spent-session retry changed original result")
		}
		var out emailhttp.RemovalResponse
		_ = json.Unmarshal(originalHTTP, &out)
		if out.CommandID != result.Binding.CommandID || out.CascadeID != result.Cascade.CascadeID {
			t.Fatal("HTTP/native retry detached original admission")
		}
	}
	q := identity.RecoveryQuery{CommandID: result.Binding.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: "identity.email.address-remove", RecordID: address}
	recovered, err := owner.AddressRemoveRecover(ctx, q, r.Caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Cascade == nil || recovered.Cascade.CascadeID != result.Cascade.CascadeID {
		t.Fatal("removal recovery repeated or lost original admission", err)
	}
	changed := r
	changed.ExpectedIdentifierVersion++
	if emailRemovalReplacesPrimary(f.emailRemovalMode) {
		changed = r
		changed.ReplacementPrimary.ExpectedIdentifierVersion++
	}
	if out, err := owner.AddressRemove(ctx, changed); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("same-key changed input reused removal outcome")
	}
	foreign := q
	foreign.TenantID = "foreign"
	if out, err := owner.AddressRemoveRecover(ctx, foreign, r.Caller); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign scope disclosed removal outcome")
	}
	if f.emailRemovalMode == "removal-pending" {
		var retired int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND subject_id=$2 AND verification_identifier_id=$3 AND state='revoked' AND uses=0`, otpTenant, string(user), string(pending)).Scan(&retired); err != nil || retired != 1 {
			t.Fatal("actual unused target link not retired", err)
		}
		verificationOwner, err := features.EmailVerification()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := identity.NewCommandID()
		callback, _ := url.Parse(origin + "/login")
		caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.verification-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
		if out, err := verificationOwner.VerificationConfirm(ctx, email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: token, Callback: *callback, Caller: caller, Network: "127.0.0.1"}); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("retired target link restored removed identity")
		}
	}
	old, _ := referencePasswordLogin(t, ctx, f, client, base, origin, cookies, f.removalSignin, "synthetic-registration-password", target)
	if old.SignedIn {
		t.Fatal("removed email still signs in")
	}
	current, csrfWire := freshLogin(remaining)
	if !readSession(current) {
		t.Fatal("remaining verified address lost actual signin")
	}
	if f.emailRemovalMode == "removal-rollback" {
		// Obtain another genuine proof for the remaining sole verified address;
		// no fixture edits directory/factor authority to manufacture this denial.
		proofOwner, err := features.CookiePasswordVerification()
		if err != nil {
			t.Fatal(err)
		}
		secret, _ := primitive.NewSecret([]byte("synthetic-registration-password"))
		defer secret.Destroy()
		csrf, _ := session.ParseCSRFToken(csrfWire)
		caller := r.Caller.Clone()
		caller.Request.Action = "identity.password.verify"
		caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}
		bearer := auth.NewBearerCredential(current[0].Value)
		verified, err := proofOwner.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: bearer, Password: secret, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.email.address-remove", Audience: "reference-managed-email"}, Caller: caller, Network: "127.0.0.1", Device: "managed-consumer"}, CSRFToken: csrf})
		if err != nil {
			t.Fatal("fresh last-path denial proof unavailable", err)
		}
		var remainingID string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version::text,verification_version::text FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND canonical_value=$3`, otpTenant, string(user), remaining).Scan(&remainingID, &versionText, &verificationText); err != nil {
			t.Fatal(err)
		}
		last := r
		last.AddressID = identity.IdentifierID(remainingID)
		last.ExpectedIdentifierVersion, _ = strconv.ParseUint(versionText, 10, 64)
		last.ExpectedVerificationVersion, _ = strconv.ParseUint(verificationText, 10, 64)
		last.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("last-remaining-verified-email"))
		last.Primary = email.RequestPrimary{Session: bearer, Proof: verified.Proof, CSRFToken: csrf}
		prior := snapshot()
		if out, err := owner.AddressRemove(ctx, last); err == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != prior || !readSession(current) {
			t.Fatal("removed last actual signin/reset path", err)
		}
	}
	proveReferenceEmailResetAfterRemoval(t, ctx, f, features, workers, client, base, origin, current, messages, user, remaining)
	if requireActorUnchanged != nil {
		requireActorUnchanged()
	}
}
