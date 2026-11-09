//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The existing public signup/verification/password-signin fixture creates the
// actual user and session. Only the external OIDC provider is controlled here;
// no session, account, link, policy epoch or token-vault row is seeded by SQL.
func TestReferencePostgresConfiguredOIDCSigninSelectionFailsClosed(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "browser"
		if persistent {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCPersistent: persistent, socialOIDCRejectSignin: true}, true)
		})
	}
}

func TestReferencePostgresConfiguredOIDCLink(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkPersistentSession(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCPersistent: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkCounterRotation(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCRotateCounters: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkCollision(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCCollision: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkStartupSnapshot(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCStartupSnapshot: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkConcurrentCallbacks(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCConcurrent: true}, true)
}

type referenceSocialExchangeGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type socialOIDCFailure uint8

const (
	socialVaultRollback socialOIDCFailure = iota + 1
	socialExchangeUnknown
	socialProviderDenial
	socialProviderDenialRollback
	socialCredentialEpochRace
	socialLinkErasureRollback
	socialExpiredCleanup
	socialAttachedProofExpiry
	socialAttachedRPExpiry
	socialTokenRefusal
)

func TestReferencePostgresConfiguredOIDCLinkAttachmentExpiryRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCFailure: socialAttachedProofExpiry, completionCommitFault: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkExpiredRPRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCFailure: socialAttachedRPExpiry, completionCommitFault: true}, true)
}

func TestReferencePostgresConfiguredOIDCLinkTokenEndpointRefusal(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCFailure: socialTokenRefusal}, true)
}

func awaitReferenceSocialRPExpiry(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, transaction string) {
	t.Helper()
	var until, now time.Time
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT expires_at,clock_timestamp() FROM identity_social.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND version=1 AND secrets_erased_at IS NULL`, otpTenant, transaction).Scan(&until, &now); err != nil || !until.After(now) || until.Sub(now) > time.Minute {
		t.Fatal("original attached RP did not retain its configured expiry", err)
	}
	timer := time.NewTimer(until.Sub(now) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("waiting for actual RP expiry", ctx.Err())
	}
}

func TestReferencePostgresConfiguredOIDCLinkCredentialEpochRace(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCFailure: socialCredentialEpochRace}, true)
}

func TestReferencePostgresConfiguredOIDCLinkFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode socialOIDCFailure
	}{{"vault-rollback", socialVaultRollback}, {"exchange-unknown", socialExchangeUnknown}, {"provider-denial", socialProviderDenial}, {"provider-denial-rollback", socialProviderDenialRollback}, {"terminal-erasure-rollback", socialLinkErasureRollback}, {"expired-cleanup", socialExpiredCleanup}} {
		t.Run(tc.name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCFailure: tc.mode}, true)
		})
	}
}

func awaitReferenceSocialCallbackLease(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, purpose string) {
	t.Helper()
	var until, now time.Time
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT lease_until,clock_timestamp() FROM identity.commands WHERE tenant_id=$1 AND purpose=$2 AND state='pending'`, otpTenant, purpose).Scan(&until, &now); err != nil || until.Sub(now) > 4*time.Second {
		t.Fatal("unknown exchange did not retain its bounded original lease")
	}
	if remaining := until.Sub(now); remaining > 0 {
		timer := time.NewTimer(remaining + 10*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("waiting for original callback lease", ctx.Err())
		}
	}
	var expired bool
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT clock_timestamp()>=lease_until FROM identity.commands WHERE tenant_id=$1 AND purpose=$2 AND state='pending'`, otpTenant, purpose).Scan(&expired); err != nil || !expired {
		t.Fatal("callback lease did not expire before takeover retry")
	}
}

func awaitReferenceSocialAttachmentExpiry(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies) {
	t.Helper()
	var until, now time.Time
	query := `SELECT GREATEST((SELECT lease_until FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.account.link-token' AND state='pending' AND command_plan IS NOT NULL),(SELECT expires_at FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.account.link-token')),clock_timestamp()`
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, query, otpTenant).Scan(&until, &now); err != nil || !until.After(now) || until.Sub(now) > 25*time.Second {
		t.Fatal("lost attachment acknowledgement did not retain bounded original authority", err)
	}
	timer := time.NewTimer(until.Sub(now) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("waiting for actual attached proof expiry", ctx.Err())
	}
	var expired bool
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT clock_timestamp()>=$1`, until).Scan(&expired); err != nil || !expired {
		t.Fatal("attached original authority did not expire before recovery")
	}
}

func proveReferenceSocialFailureStorage(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, mode socialOIDCFailure) {
	t.Helper()
	if mode == socialCredentialEpochRace {
		var linked, vaults int
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.accounts WHERE provider='reference-oidc'),(SELECT count(*) FROM identity_social.token_sets)`).Scan(&linked, &vaults); err != nil || linked != 1 || vaults != 1 {
			t.Fatal("stale initiating session added another provider credential or token vault")
		}
		return
	}
	var vaults, linked, erased int
	wantErased := 0
	if mode == socialProviderDenial || mode == socialProviderDenialRollback || mode == socialVaultRollback || mode == socialExpiredCleanup || mode == socialAttachedProofExpiry || mode == socialAttachedRPExpiry || mode == socialTokenRefusal {
		wantErased = 1
	}
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_social.token_sets),(SELECT count(*) FROM identity.accounts WHERE provider='reference-oidc'),(SELECT count(*) FROM identity_social.transactions WHERE secrets_erased_at IS NOT NULL)`).Scan(&vaults, &linked, &erased); err != nil || vaults != 0 || linked != 0 || erased != wantErased {
		t.Fatal("failed linking left a partial account, token vault or success erasure")
	}
	if mode == socialProviderDenial || mode == socialProviderDenialRollback {
		var committed, consumed int
		state, proofState, uses := "committed", "finalized", 1
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.oauth.callback' AND state=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.oauth.callback' AND state=$3 AND uses=$4)`, otpTenant, state, proofState, uses).Scan(&committed, &consumed); err != nil || committed != 1 || consumed != 1 {
			t.Fatal("provider denial did not retain one terminal original callback")
		}
		rows, err := deps.PostgreSQL.Raw().Query(ctx, `SELECT canonical_record FROM audit.records WHERE tenant_id=$1 AND action='identity.oauth.handle_callback'`, otpTenant)
		if err != nil {
			t.Fatal("read callback audit")
		}
		defer rows.Close()
		var wire []byte
		if !rows.Next() || rows.Scan(&wire) != nil || rows.Next() || rows.Err() != nil {
			t.Fatal("provider denial did not persist exactly one audit")
		}
		record, err := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
		outcome, reason, after := audit.OutcomeDenied, "provider_denied", "2"
		if err != nil || record.Outcome() != outcome || record.ReasonCode() != reason || record.Attributes()["retention.class"] != "standard" || record.Attributes()["aggregate.before_version"] != "1" || record.Attributes()["aggregate.after_version"] != after {
			t.Fatal("terminal callback misreported authentication or exchange-secret erasure")
		}
		return
	}
	var state string
	var generation, started string
	wantGeneration := "1"
	if mode == socialAttachedProofExpiry || mode == socialAttachedRPExpiry {
		wantGeneration = "2"
	}
	if mode == socialTokenRefusal {
		var released, invented int
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.oauth.callback' AND state='released' AND uses=0),(SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.account.link-token')`, otpTenant).Scan(&released, &invented); err != nil || released != 1 || invented != 0 {
			t.Fatal("definitive token refusal retained state or invented a final grant")
		}
	}
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT state,generation::text,preparation_started_generation::text FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.account.link-token'`, otpTenant).Scan(&state, &generation, &started); err != nil || generation != wantGeneration || started != "1" {
		t.Fatal("callback failure lost original acknowledged exchange ownership")
	}
	want := "aborted"
	if mode == socialExchangeUnknown || mode == socialLinkErasureRollback {
		want = "pending"
	}
	if state != want {
		t.Fatal("known rollback and exchange uncertainty were not distinguished", state)
	}
	if mode == socialExpiredCleanup {
		var released int
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.account.link-token' AND state='released' AND uses=0 AND expires_at<$2`, otpTenant, time.Now().Add(time.Hour)).Scan(&released); err != nil || released != 1 {
			t.Fatal("expired execution authority prevented proven rollback release")
		}
	}
	if mode == socialAttachedProofExpiry || mode == socialAttachedRPExpiry {
		var released int
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose IN('identity.oauth.callback','identity.account.link-token') AND state='released' AND uses=0`, otpTenant).Scan(&released); err != nil || released != 2 {
			t.Fatal("expired attachment recovery did not permanently release both original inputs")
		}
	}
}

// Read the actual audit owner's canonical records after callback replay. Each
// terminal account-link command must retain its complete, non-synonymous event
// set once; a successful domain audit cannot stand in for callback handling.
func proveReferenceSocialLinkAudits(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, collision bool, mode socialOIDCFailure) {
	t.Helper()
	var temporaryTerminalCopies int
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.account.link-token' AND state IN('committed','aborted') AND (preparation_ciphertext IS NOT NULL OR preparation_ciphertext_generation IS NOT NULL)`, otpTenant).Scan(&temporaryTerminalCopies); err != nil || temporaryTerminalCopies != 0 {
		t.Fatal("terminal linking retained temporary provider-response or issuance custody", err)
	}
	if mode == socialLinkErasureRollback {
		var pendingCopies int
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.account.link-token' AND state='pending' AND preparation_ciphertext IS NOT NULL AND preparation_ciphertext_generation IS NOT NULL`, otpTenant).Scan(&pendingCopies); err != nil || pendingCopies != 1 {
			t.Fatal("failed terminal erasure lost pending provider-response custody", err)
		}
	}
	rows, err := deps.PostgreSQL.Raw().Query(ctx, `SELECT c.state,r.canonical_record FROM identity.commands c JOIN audit.identity_command_bindings b ON b.command_id=c.command_id JOIN audit.records r ON r.record_id=b.event_id WHERE c.tenant_id=$1 AND c.purpose='identity.account.link-token'`, otpTenant)
	if err != nil {
		t.Fatal("read actual terminal account-link audits", err)
	}
	defer rows.Close()
	type terminalAudits struct {
		state   string
		records map[string]audit.Record
	}
	commands := make(map[string]*terminalAudits)
	for rows.Next() {
		var state string
		var wire []byte
		if rows.Scan(&state, &wire) != nil {
			t.Fatal("read bounded account-link audit")
		}
		record, err := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
		if err != nil {
			t.Fatal("parse persisted canonical account-link audit")
		}
		commandID := record.Attributes()["command.id"]
		if commandID == "" || record.Attributes()["retention.class"] != "standard" || record.Description() != "" {
			t.Fatal("callback audit lost command identity, retention or privacy")
		}
		group := commands[commandID]
		if group == nil {
			group = &terminalAudits{state: state, records: make(map[string]audit.Record)}
			commands[commandID] = group
		}
		if group.state != state || group.records[record.Action()].ID() != "" {
			t.Fatal("callback replay duplicated or changed a terminal audit")
		}
		group.records[record.Action()] = record
	}
	if rows.Err() != nil {
		t.Fatal("complete persisted callback audit read")
	}
	wantCommitted, wantAborted := 1, 0
	switch mode {
	case socialVaultRollback, socialExpiredCleanup, socialAttachedProofExpiry, socialAttachedRPExpiry, socialTokenRefusal:
		wantCommitted, wantAborted = 0, 1
	case socialExchangeUnknown, socialProviderDenial, socialProviderDenialRollback, socialLinkErasureRollback:
		wantCommitted = 0
	case socialCredentialEpochRace:
		wantAborted = 1
	}
	if collision {
		wantAborted++
	}
	committed, aborted := 0, 0
	for commandID, group := range commands {
		callback := group.records["identity.oauth.handle_callback"]
		link := group.records["identity.oauth.link_account"]
		kernel := group.records["identity.account.link"]
		if len(group.records) != 3 || callback.ID() == "" || link.ID() == "" || kernel.ID() == "" || callback.Context().CausationID() != commandID || link.Context().CausationID() != callback.ID() || kernel.Context().CausationID() != link.ID() {
			t.Fatal("terminal callback omitted required actions or their causation chain")
		}
		for _, record := range []audit.Record{link, kernel} {
			if record.Outcome() != callback.Outcome() || record.ReasonCode() != callback.ReasonCode() || record.Context().CorrelationID() != callback.Context().CorrelationID() || record.Subject() != callback.Subject() || record.Actor() != callback.Actor() {
				t.Fatal("composed callback audit actions disagree on outcome or identity")
			}
		}
		switch group.state {
		case "committed":
			committed++
			if callback.Outcome() != audit.OutcomeSucceeded || callback.Changes().NoChange() || link.Changes().NoChange() || kernel.Changes().NoChange() {
				t.Fatal("committed account link did not record its actual mutation")
			}
		case "aborted":
			aborted++
			if callback.Outcome() == audit.OutcomeSucceeded || !callback.Changes().NoChange() || !link.Changes().NoChange() || !kernel.Changes().NoChange() {
				t.Fatal("terminally refused callback claimed an account mutation")
			}
		default:
			t.Fatal("unresolved callback persisted a terminal audit")
		}
	}
	if committed != wantCommitted || aborted != wantAborted {
		t.Fatal("callback audits did not match terminal commands", committed, aborted)
	}
}

// Recompose only real public owners with retained original configuration and
// one additional counter key. No state, session, charge or authority is seeded.
func rotateReferenceSocialCounters(t *testing.T, ctx context.Context, c *reference.StoreConfiguration, deps reference.ReferenceDependencies, workers []deliverypg.WorkerConfig, serverConfig reference.ReferenceConfig, selectHandler func(http.Handler)) {
	t.Helper()
	social := *c.SocialOAuth
	counters := *social.Counters.CommandCounters
	if len(counters.Keys) == 0 || len(counters.Keys) >= 4 {
		t.Fatal("rotation fixture needs retained key capacity")
	}
	version := counters.Keys[0].Version() + 1
	key, err := risk.NewCounterDigestKey(version, bytes.Repeat([]byte{byte(180 + version%60)}, 32))
	if err != nil {
		t.Fatal("construct rotated counter key")
	}
	counters.Keys = append([]risk.CounterDigestKey{key}, counters.Keys...)
	social.Counters.CommandCounters = &counters
	c.SocialOAuth = &social
	stores, err := reference.ComposeStores(*c, deps)
	if err != nil {
		t.Fatal("recompose native graph after counter rotation", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workerSet, err := reference.ComposeWorkers(stores, providers, workers...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workerSet)
	if err != nil {
		t.Fatal(err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("initialize same graph after counter rotation", err)
	}
	server, err := reference.NewServer(serverConfig, deps, features)
	if err != nil {
		t.Fatal("compose selected HTTP after counter rotation", err)
	}
	selectHandler(server.Handler())
}

func proveReferenceSocialCounterAliases(t *testing.T, ctx context.Context, deps reference.ReferenceDependencies, c *reference.SocialOAuthConfiguration) {
	t.Helper()
	table := pgx.Identifier{c.Counters.Schema, "counter_charges"}.Sanitize()
	var command []byte
	var aliases []int64
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT command_id,key_versions FROM `+table+` WHERE tenant_id=$1 AND operation='identity.account.link-token'`, otpTenant).Scan(&command, &aliases); err != nil || len(command) != 16 {
		t.Fatal("original callback counter metadata unavailable")
	}
	current := c.Counters.CommandCounters.Keys
	if len(current) != 3 || len(aliases) != 2 || aliases[0] != int64(current[1].Version()) || aliases[1] != int64(current[2].Version()) {
		t.Fatal("callback retry replaced its originally charged key aliases")
	}
	var starts int
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND operation='identity.account.link-start' AND cardinality(key_versions)=1`, otpTenant).Scan(&starts); err != nil || starts != 2 {
		t.Fatal("initiation retry recounted or rewrote original charges")
	}
	_, err := deps.PostgreSQL.Raw().Exec(ctx, `UPDATE `+table+` SET key_versions=ARRAY[4294967295::bigint] WHERE command_id=$1`, command)
	var invalid *pgconn.PgError
	if !errors.As(err, &invalid) || invalid.Code != "23514" {
		t.Fatal("committed original alias history was mutable")
	}
	var retained []int64
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT key_versions FROM `+table+` WHERE command_id=$1`, command).Scan(&retained); err != nil || len(retained) != len(aliases) || retained[0] != aliases[0] || retained[1] != aliases[1] {
		t.Fatal("rejected metadata update altered original aliases")
	}
}

type referenceSocialOIDCPolicy struct{ actor authorization.SubjectID }

func (p *referenceSocialOIDCPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if r.Tenant == otpTenant && c.PolicyRevision == 9 {
		switch r.Action {
		case "identity.account.link-start", "identity.account.link-token", "identity.oauth.signin-start", "identity.oauth.callback":
			self := r.Subject.Kind == authorization.SubjectUser && r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID)
			admission := p.actor != "" && r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == p.actor && r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)
			selfAdmission := r.Action == "identity.account.link-start" && r.Subject.Kind == authorization.SubjectUser && r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)
			if self || admission || selfAdmission {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

type referenceSocialOIDCGrant struct{ nonce, challenge, subject string }

// Advance only the configured capability verifier's clock after the real vault
// write fails. This deterministically expires retained execution authority at
// the rollback boundary without sleeping or seeding identity/proof rows.
type referenceSocialRollbackClock struct{ expired atomic.Bool }

func (c *referenceSocialRollbackClock) now() time.Time {
	if c.expired.Load() {
		return time.Now().Add(time.Hour)
	}
	return time.Now()
}

func newReferenceSocialRollbackClockPool(t *testing.T, ctx context.Context, source *database.Pool) (*database.Pool, *referenceSocialRollbackClock) {
	t.Helper()
	clock := &referenceSocialRollbackClock{}
	pool, err := database.Connect(ctx, database.Config{DSN: source.Raw().Config().ConnConfig.ConnString(), MaxConns: 4, Configure: func(config *database.PoolConfig) error {
		// Work deliberately bypasses pgx's mutable QueryTracer. The database
		// fault emits this notice immediately before refusing its vault write.
		config.ConnConfig.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
			if notice.Message == "controlled-vault-expire" {
				clock.expired.Store(true)
			}
		}
		return nil
	}})
	if err != nil {
		t.Fatal("configure original rollback clock", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(bounded); err != nil {
			t.Error("close rollback clock pool", err)
		}
	})
	return pool, clock
}

type referenceSocialOIDCIssuer struct {
	server            *httptest.Server
	key               *ecdsa.PrivateKey
	redirect          string
	mu                sync.Mutex
	grants            map[string]referenceSocialOIDCGrant
	exchanges         atomic.Int64
	failExchange      atomic.Bool
	refuseExchange    atomic.Bool
	denyAuthorization atomic.Bool
	gate              atomic.Pointer[referenceSocialExchangeGate]
}

func configureReferenceSocialOIDC(t *testing.T, c *reference.StoreConfiguration, origin string, linkOnly bool) *referenceSocialOIDCIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("create controlled provider key")
	}
	p := &referenceSocialOIDCIssuer{key: key, redirect: origin + "/v1/oauth/callback", grants: make(map[string]referenceSocialOIDCGrant)}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{ID: "reference-oidc", Version: 1, Issuer: p.server.URL, AuthorizationEndpoint: p.server.URL + "/authorize", TokenEndpoint: p.server.URL + "/token", RedirectURI: p.redirect, ClientID: "reference-social-client", ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid", "profile"}, Algorithms: []string{"ES256"}, KeySet: p, HTTPClient: p.server.Client(), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal("configure controlled provider", err)
	}
	t.Cleanup(provider.Close)
	c.SocialOAuth = &reference.SocialOAuthConfiguration{
		Schema: "identity_social", ConfigurationID: "reference-social-v1", Origin: origin, IntentKey: [32]byte{174},
		Providers: []oauth.Provider{provider}, PolicyID: "reference-social-link",
		Issuer: c.PasswordSignup.Issuer, Coordinator: c.PasswordSignup.Native.Coordinator, Counters: c.PasswordSignup.Counters,
		MaximumDuration: 3 * time.Second, StateLifetime: 10 * time.Minute,
		CallbackAllowlist:      []string{origin + "/social/complete", origin + "/social/error"},
		CurrentStateKeyVersion: 1, StateKeys: map[uint32][32]byte{1: {171}},
		CurrentPKCEKeyVersion: 1, PKCECommitmentKeys: map[uint32][32]byte{1: {172}},
		CurrentEnvelopeKey: "social-v1", EnvelopeKeys: map[string][]byte{"social-v1": bytes.Repeat([]byte{173}, 32)},
	}
	c.HTTPSocialOAuth = &reference.HTTPSocialOAuthConfiguration{LinkStart: true, SigninStart: !linkOnly, Callback: true}
	return p
}

func (p *referenceSocialOIDCIssuer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/authorize" && r.Method == http.MethodGet {
		q := r.URL.Query()
		if q.Get("client_id") != "reference-social-client" || q.Get("redirect_uri") != p.redirect || q.Get("response_type") != "code" || q.Get("response_mode") != "query" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("nonce")) != 43 || len(q.Get("state")) != 43 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if p.denyAuthorization.Swap(false) {
			callback := p.redirect + "?" + (url.Values{"error": {"access_denied"}, "state": {q.Get("state")}, "iss": {p.server.URL}}).Encode()
			http.Redirect(w, r, callback, http.StatusSeeOther)
			return
		}
		id, err := identity.NewCommandID()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		code := string(id)
		p.mu.Lock()
		p.grants[code] = referenceSocialOIDCGrant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), subject: "stable-provider-subject"}
		p.mu.Unlock()
		callback := p.redirect + "?" + (url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {p.server.URL}}).Encode()
		http.Redirect(w, r, callback, http.StatusSeeOther)
		return
	}
	if r.URL.Path != "/token" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	p.exchanges.Add(1)
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != "reference-social-client" || r.Form.Get("redirect_uri") != p.redirect {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	grant, ok := p.grants[r.Form.Get("code")]
	delete(p.grants, r.Form.Get("code"))
	p.mu.Unlock()
	challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(challenge[:]) != grant.challenge {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if p.failExchange.Swap(false) {
		// The external provider has consumed its one-use code. An HTTP failure
		// cannot prove that exchange was effect-free or permit another attempt.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if p.refuseExchange.Swap(false) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	if gate := p.gate.Load(); gate != nil {
		gate.once.Do(func() { close(gate.entered) })
		select {
		case <-gate.release:
		case <-r.Context().Done():
			return
		}
	}
	now := time.Now().UTC()
	claims, err := json.Marshal(map[string]any{"iss": p.server.URL, "aud": "reference-social-client", "sub": grant.subject, "nonce": grant.nonce, "iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"social-test-key"}`))
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	a, b, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	signature := make([]byte, 64)
	a.FillBytes(signature[:32])
	b.FillBytes(signature[32:])
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-provider-access", "refresh_token": "synthetic-provider-refresh", "token_type": "Bearer", "expires_in": 300, "scope": "openid profile", "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
}

// Independent standard-library signature verification supplies the protocol
// client's configured trust seam. The OIDC client still validates every claim.
func (p *referenceSocialOIDCIssuer) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	invalid := errors.New("controlled provider signature invalid")
	if len(parts) != 3 {
		return nil, invalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, invalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&p.key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, invalid
	}
	return base64.RawURLEncoding.Strict().DecodeString(parts[1])
}

func proveReferenceSocialOIDC(t *testing.T, ctx context.Context, client *http.Client, base, origin string, p *referenceSocialOIDCIssuer, user identity.UserID, original []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool, persistent, linkOnly bool, accounts identity.AccountRepository, rotate func(), collision bool, failureMode socialOIDCFailure, awaitExpiry func(string), concurrent bool) {
	t.Helper()
	app := *client
	app.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("create isolated browser cookie jar")
	}
	appURL, err := url.Parse(base)
	if err != nil || len(original) != 1 {
		t.Fatal("expected real baseline session cookie")
	}
	jar.SetCookies(appURL, original)
	app.Jar = jar
	provider := *p.server.Client()
	provider.CheckRedirect = app.CheckRedirect
	call := func(method, target string, body any, csrfToken, key string) (*http.Response, []byte) {
		t.Helper()
		var input io.Reader
		if body != nil {
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal("encode social request")
			}
			input = bytes.NewReader(wire)
		}
		r, err := http.NewRequestWithContext(ctx, method, target, input)
		if err != nil {
			t.Fatal("build social request")
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
		}
		if csrfToken != "" {
			r.Header.Set("X-CSRF-Token", csrfToken)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		response, err := app.Do(r)
		if err != nil {
			t.Fatal("execute social request")
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(wire) > 16384 {
			t.Fatal("read bounded social response")
		}
		return response, wire
	}
	var lastRedirect, lastTransaction string
	var lastExpiry time.Time
	start := func(link bool, key string) string {
		t.Helper()
		path := "/v1/oauth/signin-start"
		body := map[string]any{"provider": "reference-oidc", "intent": "signin", "scopes": []string{"openid", "profile"}, "successCallback": origin + "/social/complete", "newUserCallback": origin + "/social/complete", "errorCallback": origin + "/social/error", "delivery": "url", "remember": persistent}
		token := csrf
		if link {
			path = "/v1/account/link-start"
			body = map[string]any{"provider": "reference-oidc", "callback": origin + "/social/complete", "errorCallback": origin + "/social/error", "scopes": []string{"openid", "profile"}, "signupDisabled": true}
		} else {
			token = ""
			response, wire := call(http.MethodPost, base+"/v1/session/preauth-issue", map[string]any{"method": "oauth", "remember": persistent}, "", "")
			var preauth struct {
				Issued bool   `json:"issued"`
				FlowID string `json:"flowID"`
			}
			if response.StatusCode != http.StatusOK || json.Unmarshal(wire, &preauth) != nil || !preauth.Issued || preauth.FlowID == "" {
				t.Fatal("provider signin lacks a real original browser flow", response.StatusCode)
			}
			body["flowID"] = preauth.FlowID
		}
		response, wire := call(http.MethodPost, base+path, body, token, key)
		var out struct {
			RedirectURI   string    `json:"redirectURI"`
			TransactionID string    `json:"transactionID"`
			ExpiresAt     time.Time `json:"expiresAt"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(wire, &out) != nil || out.TransactionID == "" || !out.ExpiresAt.After(time.Now()) || !strings.HasPrefix(out.RedirectURI, p.server.URL+"/authorize?") {
			t.Fatal("social initiation did not return a bound authorization transaction", response.StatusCode)
		}
		lastRedirect, lastTransaction, lastExpiry = out.RedirectURI, out.TransactionID, out.ExpiresAt
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, out.RedirectURI, nil)
		if err != nil {
			t.Fatal("build provider authorization request")
		}
		authorized, err := provider.Do(r)
		if err != nil {
			t.Fatal("authorize controlled provider")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(authorized.Body, 1024))
		closeErr := authorized.Body.Close()
		if authorized.StatusCode != http.StatusSeeOther || readErr != nil || closeErr != nil || !strings.HasPrefix(authorized.Header.Get("Location"), p.redirect+"?") {
			t.Fatal("provider did not return the configured code callback")
		}
		return authorized.Header.Get("Location")
	}
	bad, err := url.Parse(start(true, "reference-social-wrong-issuer"))
	if err != nil {
		t.Fatal("read controlled callback")
	}
	query := bad.Query()
	query.Set("iss", "https://wrong-issuer.example")
	bad.RawQuery = query.Encode()
	denied, _ := call(http.MethodGet, bad.String(), nil, "", "")
	if denied.StatusCode < 400 || p.exchanges.Load() != 0 {
		t.Fatal("issuer mix-up reached exchange or returned success")
	}
	if failureMode == socialProviderDenial || failureMode == socialProviderDenialRollback {
		p.denyAuthorization.Store(true)
	}
	goodCallback := start(true, "reference-social-real-link")
	if rotate != nil {
		redirect, transaction, expiry := lastRedirect, lastTransaction, lastExpiry
		rotate()
		_ = start(true, "reference-social-real-link")
		if lastRedirect != redirect || lastTransaction != transaction || lastExpiry != expiry {
			t.Fatal("counter rotation replaced original authorization custody or expiry")
		}
	}
	foreign := app
	foreign.Jar = nil
	foreignRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, goodCallback, nil)
	if err != nil {
		t.Fatal("build foreign-browser callback")
	}
	foreignRequest.AddCookie(&http.Cookie{Name: original[0].Name, Value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{221}, 32))})
	foreignResponse, err := foreign.Do(foreignRequest)
	if err != nil {
		t.Fatal("execute foreign-browser callback")
	}
	_, foreignReadErr := io.Copy(io.Discard, io.LimitReader(foreignResponse.Body, 16385))
	foreignCloseErr := foreignResponse.Body.Close()
	if foreignReadErr != nil || foreignCloseErr != nil || foreignResponse.StatusCode != http.StatusForbidden || p.exchanges.Load() != 0 {
		t.Fatal("foreign browser reached provider exchange or success", foreignResponse.StatusCode)
	}
	if failureMode == socialCredentialEpochRace {
		second := start(true, "reference-social-second-link")
		secondURL, err := url.Parse(second)
		if err != nil {
			t.Fatal("parse second controlled callback")
		}
		p.mu.Lock()
		grant := p.grants[secondURL.Query().Get("code")]
		grant.subject = "second-provider-subject"
		p.grants[secondURL.Query().Get("code")] = grant
		p.mu.Unlock()
		proveReferenceSocialCredentialEpochRace(t, ctx, &app, goodCallback, second, p)
		after, err := accounts.ListAccounts(ctx, identity.AccountQuery{TenantID: otpTenant, UserID: user, MaximumAccounts: 10})
		if err != nil || len(after.Accounts) != 1 || after.Accounts[0].Subject != "second-provider-subject" {
			t.Fatal("delayed callback adopted unrelated credential authority")
		}
		return
	}
	if failureMode == socialProviderDenial || failureMode == socialProviderDenialRollback {
		for attempt := range 2 {
			if attempt == 1 && failureMode == socialProviderDenialRollback {
				awaitExpiry(lastTransaction)
			}
			denial, _ := call(http.MethodGet, goodCallback, nil, "", "")
			status, redirect := http.StatusSeeOther, origin+"/social/error"
			if failureMode == socialProviderDenialRollback && attempt == 0 {
				status, redirect = http.StatusServiceUnavailable, ""
			}
			if denial.StatusCode != status || denial.Header.Get("Location") != redirect || p.exchanges.Load() != 0 || len(denial.Cookies()) != 0 {
				t.Fatal("provider denial did not terminally preserve the original error callback without authentication", denial.StatusCode)
			}
		}
		changed, err := url.Parse(goodCallback)
		if err != nil {
			t.Fatal("parse controlled denial callback")
		}
		values := changed.Query()
		values.Del("error")
		values.Set("code", "synthetic-unexchanged-code")
		changed.RawQuery = values.Encode()
		refused, _ := call(http.MethodGet, changed.String(), nil, "", "")
		if (refused.StatusCode != http.StatusForbidden && refused.StatusCode != http.StatusConflict) || p.exchanges.Load() != 0 {
			t.Fatal("terminal denial permitted a later code exchange", refused.StatusCode)
		}
		if !readSession(original) {
			t.Fatal("provider denial changed original password session authority")
		}
		return
	}
	if failureMode != 0 {
		if failureMode == socialExchangeUnknown {
			p.failExchange.Store(true)
		}
		if failureMode == socialTokenRefusal {
			p.refuseExchange.Store(true)
		}
		wantStatus := http.StatusForbidden
		if failureMode == socialExchangeUnknown || failureMode == socialLinkErasureRollback {
			wantStatus = http.StatusServiceUnavailable
		}
		attempts := 2
		if failureMode == socialAttachedProofExpiry || failureMode == socialAttachedRPExpiry {
			attempts = 3
		}
		for retry := 0; retry < attempts; retry++ {
			if retry == 1 && (failureMode == socialExchangeUnknown || failureMode == socialAttachedProofExpiry || failureMode == socialAttachedRPExpiry) {
				awaitExpiry(lastTransaction)
			}
			if failureMode == socialAttachedProofExpiry || failureMode == socialAttachedRPExpiry {
				wantStatus = http.StatusForbidden
				if retry == 0 {
					wantStatus = http.StatusServiceUnavailable
				}
			}
			failed, _ := call(http.MethodGet, goodCallback, nil, "", "")
			if failed.StatusCode != wantStatus || p.exchanges.Load() != 1 {
				t.Fatal("callback failure repeated exchange or lost its outcome class", failed.StatusCode, "exchange attempts", p.exchanges.Load())
			}
			if (failureMode == socialAttachedProofExpiry || failureMode == socialAttachedRPExpiry) && len(failed.Cookies()) != 0 {
				t.Fatal("expired attachment recovery issued a new session cookie")
			}
		}
		after, err := accounts.ListAccounts(ctx, identity.AccountQuery{TenantID: otpTenant, UserID: user, MaximumAccounts: 10})
		if err != nil || len(after.Accounts) != 0 || !readSession(original) {
			t.Fatal("failed callback changed existing account or password session")
		}
		return
	}
	var linked *http.Response
	if concurrent {
		linked = proveReferenceSocialConcurrentCallbacks(t, ctx, &app, goodCallback, p)
	} else {
		linked, _ = call(http.MethodGet, goodCallback, nil, "", "")
	}
	if linked.StatusCode != http.StatusSeeOther || linked.Header.Get("Location") != origin+"/social/complete" || p.exchanges.Load() != 1 {
		t.Fatal("real provider callback did not commit explicit linking", linked.StatusCode, "exchange attempts", p.exchanges.Load())
	}
	snapshot, err := accounts.ListAccounts(ctx, identity.AccountQuery{TenantID: otpTenant, UserID: user, MaximumAccounts: 10})
	if err != nil || snapshot.User.ID != user {
		t.Fatal("linked account primary snapshot unavailable")
	}
	matches := 0
	for _, account := range snapshot.Accounts {
		if account.Provider == "reference-oidc" && account.Issuer == p.server.URL && account.Subject == "stable-provider-subject" && account.UserID == user && account.Version > 0 {
			matches++
		}
	}
	if matches != 1 {
		t.Fatal("callback did not durably link the verified provider account exactly once")
	}
	if rotate != nil {
		rotate()
	}
	replay, _ := call(http.MethodGet, goodCallback, nil, "", "")
	if replay.StatusCode != http.StatusSeeOther || replay.Header.Get("Location") != origin+"/social/complete" || p.exchanges.Load() != 1 {
		t.Fatal("callback retry did not preserve its committed result without another exchange")
	}
	if linkOnly {
		for _, cookie := range linked.Cookies() {
			if cookie.Name == original[0].Name {
				t.Fatal("account linking replaced the original session cookie")
			}
		}
		passwordCookies, passwordCSRF := fresh()
		if !readSession(passwordCookies) {
			t.Fatal("provider linking removed the password access path")
		}
		if collision {
			jar.SetCookies(appURL, passwordCookies)
			csrf = passwordCSRF
			conflictingCallback := start(true, "reference-social-existing-subject")
			for retry := 0; retry < 2; retry++ {
				refused, _ := call(http.MethodGet, conflictingCallback, nil, "", "")
				if refused.StatusCode != http.StatusForbidden || p.exchanges.Load() != 2 {
					t.Fatal("known provider collision was not terminally refused without re-exchange", refused.StatusCode, "exchange attempts", p.exchanges.Load())
				}
			}
			after, err := accounts.ListAccounts(ctx, identity.AccountQuery{TenantID: otpTenant, UserID: user, MaximumAccounts: 10})
			if err != nil || after.User != snapshot.User || len(after.Accounts) != len(snapshot.Accounts) {
				t.Fatal("refused provider collision changed the existing local account")
			}
			if !readSession(passwordCookies) {
				t.Fatal("refused provider collision invalidated the existing password session")
			}
		}
		disabled, _ := call(http.MethodPost, base+"/v1/oauth/signin-start", map[string]any{}, "", "disabled-social-signin")
		if disabled.StatusCode != http.StatusNotFound {
			t.Fatal("link-only composition exposed unselected social signin")
		}
		return
	}
	// Linking may invalidate the original credential epoch. Either way the next
	// signin must create its own original browser/session ceremony, not reuse it.
	_, _ = call(http.MethodPost, base+"/v1/session/signout", map[string]any{}, csrf, "")
	if readSession(original) {
		t.Fatal("original session remained usable after link/signout")
	}
	signedIn, _ := call(http.MethodGet, start(false, "reference-social-real-signin"), nil, "", "")
	if signedIn.StatusCode != http.StatusSeeOther || signedIn.Header.Get("Location") != origin+"/social/complete" || p.exchanges.Load() != 2 || !readSession(jar.Cookies(appURL)) {
		t.Fatal("linked provider signin did not issue a real readable session", signedIn.StatusCode)
	}
	matchedCookie := false
	for _, cookie := range signedIn.Cookies() {
		lifetime := cookie.MaxAge == 0 && cookie.Expires.IsZero()
		if persistent {
			lifetime = cookie.MaxAge > 0 && cookie.Expires.After(time.Now())
		}
		if cookie.Name == original[0].Name && cookie.Value != "" && cookie.HttpOnly && cookie.Secure && cookie.SameSite == http.SameSiteLaxMode && lifetime {
			matchedCookie = true
		}
	}
	if !matchedCookie {
		t.Fatal("provider callback changed explicit remember/cookie policy")
	}
	current, wire := call(http.MethodGet, base+"/v1/session/get", nil, "", "")
	var sessionResult struct {
		Authenticated bool `json:"authenticated"`
		Principal     *struct {
			UserID string `json:"userID"`
		} `json:"principal"`
	}
	if current.StatusCode != http.StatusOK || json.Unmarshal(wire, &sessionResult) != nil || !sessionResult.Authenticated || sessionResult.Principal == nil || sessionResult.Principal.UserID != string(user) {
		t.Fatal("provider signin did not resolve the existing local user")
	}
	issuedCookies := jar.Cookies(appURL)
	loggedOut, logoutBody := call(http.MethodPost, base+"/v1/session/signout", map[string]any{}, signedIn.Header.Get("X-CSRF-Token"), "")
	var logout struct {
		SignedOut bool   `json:"signedOut"`
		Outcome   string `json:"commitOutcome"`
	}
	if loggedOut.StatusCode != http.StatusOK || json.Unmarshal(logoutBody, &logout) != nil || !logout.SignedOut || logout.Outcome != "committed" || readSession(issuedCookies) {
		t.Fatal("provider session logout did not revoke the issued session", loggedOut.StatusCode)
	}
	passwordCookies, _ := fresh()
	if !readSession(passwordCookies) {
		t.Fatal("explicit provider link removed the password access path")
	}
}

func proveReferenceSocialCredentialEpochRace(t *testing.T, ctx context.Context, app *http.Client, first, second string, p *referenceSocialOIDCIssuer) {
	t.Helper()
	gate := &referenceSocialExchangeGate{entered: make(chan struct{}), release: make(chan struct{})}
	p.gate.Store(gate)
	var release sync.Once
	unblock := func() { release.Do(func() { close(gate.release) }) }
	defer p.gate.Store(nil)
	type result struct {
		status int
		err    error
	}
	request := func(target string) result {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return result{err: err}
		}
		response, err := app.Do(r)
		if err != nil {
			return result{err: err}
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16385))
		return result{status: response.StatusCode, err: errors.Join(readErr, response.Body.Close())}
	}
	firstResult := make(chan result, 1)
	go func() { firstResult <- request(first) }()
	defer func() { unblock(); <-firstResult }()
	select {
	case <-gate.entered:
	case early := <-firstResult:
		firstResult <- early
		t.Fatal("first callback did not reach held exchange", early.status)
	case <-ctx.Done():
		t.Fatal("first callback never entered exchange")
	}
	// Only A is held. B must commit a genuinely different provider subject from
	// the same original session before A obtains its post-exchange primary read.
	p.gate.Store(nil)
	b := request(second)
	unblock()
	a := <-firstResult
	firstResult <- a
	if b.err != nil || b.status != http.StatusSeeOther {
		t.Fatal("second callback did not advance credential authority", b.status)
	}
	if a.err != nil || (a.status != http.StatusForbidden && a.status != http.StatusConflict) || p.exchanges.Load() != 2 {
		t.Fatal("delayed callback accepted a stale initiating credential epoch", a.status)
	}
}

// Hold the real external exchange outside SQL while three competing callbacks
// must finish as pending. No callback may perform a second exchange; releasing
// the sole owner must then commit the ordinary public linking outcome. Together
// with the final committed replay this stays inside the selected five-per-flow
// HTTP budget; rate denial is not a native concurrency failure.
func proveReferenceSocialConcurrentCallbacks(t *testing.T, ctx context.Context, app *http.Client, target string, p *referenceSocialOIDCIssuer) *http.Response {
	t.Helper()
	gate := &referenceSocialExchangeGate{entered: make(chan struct{}), release: make(chan struct{})}
	p.gate.Store(gate)
	var release sync.Once
	unblock := func() { release.Do(func() { close(gate.release) }) }
	defer unblock()
	defer p.gate.Store(nil)
	type result struct {
		response *http.Response
		err      error
	}
	request := func() result {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return result{err: err}
		}
		response, err := app.Do(r)
		if err != nil {
			return result{err: err}
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		return result{response: response, err: errors.Join(readErr, closeErr)}
	}
	winner := make(chan result, 1)
	go func() { winner <- request() }()
	// Drain every task-owned goroutine before the test or its server can close.
	defer func() { unblock(); <-winner }()
	select {
	case <-gate.entered:
	case first := <-winner:
		winner <- first
		t.Fatal("original callback returned before entering provider exchange")
	case <-ctx.Done():
		t.Fatal("original callback never entered exchange", ctx.Err())
	}
	contenders := make(chan result, 3)
	for range 3 {
		go func() { contenders <- request() }()
	}
	var failures []result
	for range 3 {
		failures = append(failures, <-contenders)
	}
	unblock()
	first := <-winner
	// The deferred drain also runs on fatal assertion paths below.
	winner <- first
	for _, contender := range failures {
		if contender.err != nil || contender.response.StatusCode != http.StatusServiceUnavailable {
			status := 0
			if contender.response != nil {
				status = contender.response.StatusCode
			}
			t.Fatal("concurrent callback did not return pending while exchange was held", "status", status, "transport failure", contender.err != nil)
		}
	}
	if first.err != nil || first.response == nil || p.exchanges.Load() != 1 {
		t.Fatal("concurrent callbacks repeated exchange or lost their original owner")
	}
	return first.response
}
