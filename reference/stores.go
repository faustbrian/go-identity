// Package reference owns deployment composition for the identity platform.
// This development slice composes PostgreSQL-journaled Valkey velocity recovery
// and optional native OTP Send/delivery. It is not the complete reference server.
package reference

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/risk"
	riskpostgres "github.com/faustbrian/go-identity/risk/postgres"
	riskvalkey "github.com/faustbrian/go-identity/risk/valkey"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// ReferenceDependencies supplies deployment resources, never domain stores or
// workflow callbacks. PostgreSQL remains caller-owned, including after Close.
// Its pool configuration and callbacks must satisfy go-postgres's contract.
// EnvelopeKeys and DeliverySender are required only for selected OTP/delivery.
// They remain caller-owned, cooperative bounded, concurrency-safe dependencies.
type ReferenceDependencies struct {
	PostgreSQL     *database.Pool
	EnvelopeKeys   envelope.KeyProvider
	DeliverySender delivery.Sender
}

// StoreConfiguration contains selected adapter configuration exactly once.
// Select exactly one of Velocity and DurableAdmission. OTP and Delivery must
// be selected together. Zero is
// invalid. Construction copies configuration. Concurrent input mutation during
// construction is forbidden. No optional feature is silently enabled.
type StoreConfiguration struct {
	Velocity VelocityStoreConfiguration
	// DurableAdmission selects durable PostgreSQL-only risk admission. It is
	// mutually exclusive with Velocity and enables no HTTP feature by itself.
	DurableAdmission *DurableAdmissionConfiguration
	// OTP selects public Send and its mandatory delivery owner. Nil preserves
	// the recovery-only profile. No caller evaluator or domain store is accepted.
	OTP      *OTPSendConfiguration
	Delivery *DeliveryConfiguration
	// Migrations enables explicit operator Apply; nil keeps Check/Plan only.
	Migrations *MigrationApplyPolicy
	// HTTPRate selects the owned strong HTTP admission backend and its native
	// migration history. Nil leaves both disabled without changing legacy history.
	HTTPRate *HTTPRateConfiguration
	// HTTPPreAuth explicitly selects the original-flow route for NewServer.
	HTTPPreAuth *HTTPPreAuthConfiguration
	// HTTPEmailSignin explicitly selects email OTP Send/signin/recovery routes.
	HTTPEmailSignin *HTTPEmailSigninConfiguration
	// HTTPEmailOTPVerification independently selects authenticated email OTP.
	HTTPEmailOTPVerification *HTTPEmailOTPVerificationConfiguration
	// HTTPPhoneVerification selects only cookie enrollment/confirmation/recovery.
	HTTPPhoneVerification *HTTPPhoneVerificationConfiguration
	// HTTPEmailOTPChange independently selects genuine-primary email OTP routes.
	HTTPEmailOTPChange *HTTPEmailOTPChangeConfiguration
	// PasswordReset selects native request/completion/recovery over this graph's
	// existing primary risk, delivery and session owners. Nil selects none.
	PasswordReset *PasswordResetConfiguration
	// PhonePasswordReset independently selects the explicitly carrier-risk-
	// accepted SMS plus independent-TOTP recovery profile, not HTTP or signin.
	PhonePasswordReset *PhonePasswordResetConfiguration
	// HTTPPhonePasswordReset opts into its two routes and named recovery flow.
	HTTPPhonePasswordReset *HTTPPhonePasswordResetConfiguration
	// MagicLink selects native request and optional consumption/original flow,
	// not HTTP. It shares this graph's risk, delivery and primary authority.
	MagicLink *MagicLinkConfiguration
	// PasswordSignin selects native login/recovery using graph-owned counted
	// risk and the selected session base, without enabling any HTTP route.
	PasswordSignin *PasswordSigninConfiguration
	// PasswordSignup selects native registration and confirmation, not HTTP.
	PasswordSignup *PasswordSignupConfiguration
	// Username independently selects native username owners; nil leaves all
	// username handles and migrations disabled without changing email profiles.
	Username *UsernameConfiguration
	// Phone selects native existing-account phone enrollment, not HTTP or login.
	Phone *PhoneConfiguration
	// PhoneRemoval independently selects authenticated self-removal and its
	// required old-number notice, not enrollment, login or HTTP.
	PhoneRemoval *PhoneRemovalConfiguration
	// PhoneChange independently selects verified-phone replacement and original
	// recovery. Enrollment, removal and HTTP are not silently enabled.
	PhoneChange *PhoneChangeConfiguration
	// HTTPPhoneChange selects replacement only, independently of enrollment.
	HTTPPhoneChange *HTTPPhoneChangeConfiguration
	// HTTPPhoneRemoval opts into cookie self-removal only, independently of
	// enrollment and the HTTP signin/password-verification selections.
	HTTPPhoneRemoval *HTTPPhoneRemovalConfiguration
	// PhoneSignin independently selects existing verified-phone/password login.
	// Enrollment and its HTTP routes are not dependencies of this selection.
	PhoneSignin *PhoneSigninConfiguration
	// HTTPPhoneSignin enables only phone/password signin and its bound original
	// pre-auth method; the native owner and shared browser admission are required.
	HTTPPhoneSignin *HTTPPasswordSigninConfiguration
	// PhoneOTPSignin independently selects verified-phone SMS-code login.
	PhoneOTPSignin *PhoneOTPSigninConfiguration
	// HTTPPhoneOTPSignin opts into SMS request/signin/recovery and its bound
	// original-flow method. Nil exposes no phone OTP route or metadata.
	HTTPPhoneOTPSignin *HTTPPhoneOTPSigninConfiguration
	// Session selects native primary reads and self-signout, not HTTP.
	Session *SessionConfiguration
	// PasswordVerification selects native reauthentication/proof recovery, not HTTP.
	PasswordVerification *PasswordVerificationConfiguration
	// Email selects native management and/or address queries without HTTP.
	Email *EmailConfiguration
	// HTTPEmailAddresses independently selects safe address reads, not mutations.
	HTTPEmailAddresses *HTTPEmailAddressesConfiguration
	// HTTPEmailRequests independently selects keyed request/confirmation routes.
	HTTPEmailRequests *HTTPEmailRequestsConfiguration
	// MFAEnrollment selects native first-factor enrollment management, not HTTP.
	MFAEnrollment *MFAEnrollmentConfiguration
	// HTTPMFAEnrollment independently selects native cookie enrollment HTTP.
	HTTPMFAEnrollment *HTTPMFAEnrollmentConfiguration
	// HTTPMFAActiveStepUp independently selects authenticated TOTP proof HTTP.
	HTTPMFAActiveStepUp *HTTPMFAActiveStepUpConfiguration
	// HTTPMFARecoveryRegeneration independently selects whole-set replacement HTTP.
	HTTPMFARecoveryRegeneration *HTTPMFARecoveryRegenerationConfiguration
	// HTTPMFAFactorUpdate independently selects native TOTP rename HTTP.
	HTTPMFAFactorUpdate *HTTPMFAFactorUpdateConfiguration
	// HTTPMFADisable independently selects native disable HTTP, never implicitly.
	HTTPMFADisable *HTTPMFADisableConfiguration
	// HTTPMFAList independently selects cookie-only safe factor metadata.
	HTTPMFAList *HTTPMFAListConfiguration
	// PasswordChange selects native keyed replacement over selected verification.
	PasswordChange *PasswordChangeConfiguration
	// HTTPPasswordVerification explicitly selects native reauthentication HTTP.
	HTTPPasswordVerification *HTTPPasswordProtectionConfiguration
	// HTTPPasswordChange independently selects native keyed replacement HTTP.
	HTTPPasswordChange *HTTPPasswordProtectionConfiguration
	// HTTPSession explicitly selects native session read/self-signout routes.
	HTTPSession *HTTPSessionConfiguration
	// HTTPPasswordReset independently selects request/completion routes. Native
	// reset, strict HTTP rate and the original browser-device issuer are required.
	HTTPPasswordReset *HTTPPasswordResetConfiguration
	// HTTPPasswordSignin explicitly selects browser login and its named original
	// flow method. Native signin/PreAuth, rate and device owners are required.
	HTTPPasswordSignin *HTTPPasswordSigninConfiguration
	// HTTPPasswordSignup explicitly selects browser signup, not confirmation.
	HTTPPasswordSignup *HTTPPasswordSignupConfiguration
	// HTTPUsername independently selects native username routes and flow methods.
	HTTPUsername *HTTPUsernameConfiguration
	// HTTPRegistrationVerification explicitly selects confirmation, not signup.
	HTTPRegistrationVerification *HTTPRegistrationVerificationConfiguration
	// HTTPMagicLink independently selects native magic-link routes and the named
	// original-flow method, requiring real strict rate and signed device custody.
	HTTPMagicLink *HTTPMagicLinkConfiguration
	// HTTPMFA explicitly selects native TOTP completion transport, not other MFA
	// routes. Original pre-auth/device, TOTP and strict rate owners are required.
	HTTPMFA *HTTPMFAConfiguration
	// Anonymous selects native unprivileged guest owners, not HTTP.
	Anonymous *AnonymousConfiguration
	// HTTPAnonymous independently opts into selected guest routes and read.
	HTTPAnonymous *HTTPAnonymousConfiguration
}

// VelocityStoreConfiguration selects one primary/native recovery pair. Native
// owns namespace, replay secret, policy, key history and transport configuration;
// the primary uses those exact values rather than separately selected custody.
// Tenants is a unique allowlist of 1..128 deployment scopes. Schema must satisfy
// the PostgreSQL adapter. PrimaryTimeout is positive and at most one minute.
// LeaseDuration is positive, microsecond-representable and at most one minute.
// RecoveryTimeout is positive and less than LeaseDuration. Batch is 1..1000
// (reference default 100); MaxRecords is 1..100000. Bounds are explicit: zero
// never silently enables defaults, retries or a healthy initial state.
type VelocityStoreConfiguration struct {
	Native          riskvalkey.VelocityRecoveryConfig
	Schema          string
	Tenants         []string
	PrimaryTimeout  time.Duration
	LeaseDuration   time.Duration
	RecoveryTimeout time.Duration
	Batch           int
	MaxRecords      int
}

// StoreSet is sealed deployment composition. Copies share one lifetime and
// immutable configuration. RecoverVelocity is concurrent-safe across tenants;
// concurrent same-tenant attempts fail rather than queue unbounded work. The
// caller owns Close. Zero grants no authority and can be safely closed.
type StoreSet struct{ state *storeState }

type storeState struct {
	pool       *database.Pool
	mu         sync.Mutex
	closed     bool
	active     int
	drained    chan struct{}
	lifetime   context.Context
	cancel     context.CancelFunc
	tenants    map[string]*tenantRecovery
	native     riskvalkey.VelocityRecovery
	primary    riskpostgres.VelocityRecovery
	config     VelocityStoreConfiguration
	policy     risk.Policy
	keys       []risk.CounterDigestKey
	features   *featureState
	migrations *MigrationApplyPolicy
	httpRate   *httpRateState
	durable    bool
}

type tenantRecovery struct {
	busy     bool
	previous risk.VelocityLease
	counter  risk.CounterStore
	health   *velocityHealth
}

// ComposeStores validates/copies deployment configuration without network IO,
// migrations or goroutines. It creates exactly one native custody graph and
// configures the concrete primary adapter with that graph's paired authorities.
// It does not enable traffic: RecoverVelocity must establish real covered
// journal history and native-confirmed activation. Invalid input is redacted.
func ComposeStores(c StoreConfiguration, d ReferenceDependencies) (StoreSet, error) {
	migrationPolicy, err := copyMigrationApplyPolicy(c.Migrations)
	if err != nil {
		return StoreSet{}, err
	}
	httpRate, err := composeHTTPRate(c.HTTPRate, d.PostgreSQL)
	if err != nil {
		return StoreSet{}, err
	}
	if c.DurableAdmission != nil {
		return composeDurableAdmission(c, d, migrationPolicy, httpRate)
	}
	v := c.Velocity
	if len(v.Tenants) < 1 || len(v.Tenants) > 128 || v.Batch < 1 || v.Batch > 1000 || v.MaxRecords < 1 || v.MaxRecords > 100000 || v.RecoveryTimeout <= 0 || v.RecoveryTimeout >= v.LeaseDuration {
		return StoreSet{}, risk.ErrInvalidPolicy
	}
	tenants := make(map[string]*tenantRecovery, len(v.Tenants))
	for _, tenant := range v.Tenants {
		if len(tenant) < 1 || len(tenant) > 128 || tenants[tenant] != nil {
			return StoreSet{}, risk.ErrInvalidPolicy
		}
		// Both concrete adapters require printable ASCII without spaces. Fail
		// composition now instead of retaining an unusable deployment scope.
		for i := range len(tenant) {
			if tenant[i] < '!' || tenant[i] > '~' {
				return StoreSet{}, risk.ErrInvalidPolicy
			}
		}
		tenants[tenant] = &tenantRecovery{}
	}
	journal, err := riskpostgres.NewVelocityJournal(riskpostgres.VelocityJournalConfig{Pool: d.PostgreSQL, Schema: v.Schema, Namespace: v.Native.Namespace, JournalKey: v.Native.ReplaySecret, Policy: v.Native.Policy, Keys: v.Native.Keys, Timeout: v.PrimaryTimeout})
	if err != nil {
		return StoreSet{}, err
	}
	native, err := riskvalkey.NewVelocityRecovery(v.Native)
	if err != nil {
		return StoreSet{}, err
	}
	issuer, verifier, err := native.PrimaryAuthorities()
	if err != nil {
		return StoreSet{}, err
	}
	primary, err := riskpostgres.NewVelocityRecovery(riskpostgres.VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: v.LeaseDuration, JournalIssuer: issuer, NativeVerifier: verifier})
	if err != nil {
		return StoreSet{}, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	drained := make(chan struct{})
	close(drained)
	// Resource owners already copied the sensitive configuration. Retain only
	// traversal bounds; no caller TLS objects, secret slices or tenant slices.
	retained := VelocityStoreConfiguration{Schema: v.Schema, Batch: v.Batch, MaxRecords: v.MaxRecords, RecoveryTimeout: v.RecoveryTimeout, PrimaryTimeout: v.PrimaryTimeout}
	state := &storeState{pool: d.PostgreSQL, drained: drained, lifetime: lifetime, cancel: cancel, tenants: tenants, native: native, primary: primary, config: retained, policy: v.Native.Policy, keys: slices.Clone(v.Native.Keys), migrations: migrationPolicy, httpRate: httpRate}
	if err := state.composeFeatureStores(c, d); err != nil {
		cancel()
		return StoreSet{}, err
	}
	return StoreSet{state: state}, nil
}

// RecoverVelocity performs one explicit bounded recovery, never background
// retry or an implicit debit. It starts a fresh primary-owned generation and
// restores original authenticated terminal history from zero. Unknown/pending
// history, lost acknowledgements, incomplete coverage, concurrent ownership or
// exhausted budgets return no store. Empty fresh storage is unavailable for a
// genuine full hour of journal coverage; no timestamp is backdated here.
// Success returns the exact activated pair's CounterStore, whose later calls
// recheck primary/native eligibility without resetting original expiry. There
// is no healthy-lease renewal. After expiry another explicit recovery is needed.
// A newly composed owner cannot adopt a predecessor's opaque native marker;
// cross-process reconciliation remains unimplemented and fails closed.
func (s StoreSet) RecoverVelocity(ctx context.Context, tenant string) (store risk.CounterStore, err error) {
	if ctx == nil || s.state == nil {
		return nil, risk.ErrInvalidVelocityRecovery
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state := s.state
	if state.durable {
		return nil, risk.ErrInvalidVelocityRecovery
	}
	state.mu.Lock()
	t := state.tenants[tenant]
	if state.closed || t == nil || t.busy {
		state.mu.Unlock()
		return nil, identity.UnavailableError{}
	}
	if state.active == 0 {
		state.drained = make(chan struct{})
	}
	state.active++
	t.busy = true
	// A new recovery generation may fence the old owner even when it fails.
	// Never fall back to a previously installed activation after that attempt.
	t.counter = nil
	t.health = nil
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		t.busy = false
		state.active--
		if state.active == 0 {
			close(state.drained)
		}
		state.mu.Unlock()
	}()
	bounded, cancel := context.WithTimeout(ctx, state.config.RecoveryTimeout)
	var health *velocityHealth
	stop := context.AfterFunc(state.lifetime, cancel)
	defer func() {
		// Primary adapters redact SQL errors. The composition owns the outer
		// lifetime and must preserve its cancellation/deadline, not expose an
		// unavailable substitute or a store activated after shutdown.
		store, err = state.finishVelocityRecovery(bounded, t, store, health, err)
		stop()
		cancel()
	}()
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil || boot == [16]byte{} {
		return nil, identity.UnavailableError{}
	}
	lease, err := state.primary.Acquire(bounded, tenant, boot)
	if err != nil {
		return nil, err
	}
	owned, err := state.primary.OwnedLease(bounded, lease)
	if err != nil {
		return nil, err
	}
	previous := t.previous
	// Preserve attempted fence custody even on ambiguous native ACK. A later
	// explicit generation must never pretend this attempt did not happen.
	t.previous = owned
	if err := state.native.Fence(bounded, owned, previous); err != nil {
		return nil, err
	}
	cursor, err := state.primary.ResumeApplied(bounded, lease)
	if err != nil {
		return nil, err
	}
	count := 0
	for {
		page, err := state.primary.ReadPage(bounded, lease, cursor, state.config.Batch)
		if err != nil {
			return nil, err
		}
		records := page.Records()
		if len(records) > state.config.MaxRecords-count {
			return nil, identity.UnavailableError{}
		}
		for _, record := range records {
			history, err := state.primary.OwnedHistory(bounded, lease, owned, record)
			if err != nil {
				return nil, err
			}
			ack, err := state.native.Restore(bounded, owned, history)
			if err != nil {
				return nil, err
			}
			if err := state.primary.RecordApplied(bounded, lease, owned, ack); err != nil {
				return nil, err
			}
			count++
		}
		cursor = page.Next()
		if len(records) == 0 {
			break
		}
	}
	cut, err := state.primary.PrepareCoveredClosure(bounded, lease)
	if err != nil {
		return nil, err
	}
	exported, err := state.primary.OwnedClosure(bounded, lease, owned, cut)
	if err != nil {
		return nil, err
	}
	publication, err := state.native.Publish(bounded, owned, exported)
	if err != nil {
		return nil, err
	}
	if err := state.primary.ConfirmPublication(bounded, lease, owned, cut, exported, publication); err != nil {
		return nil, err
	}
	confirmation, err := state.primary.OwnedConfirmation(bounded, lease, owned, cut, exported, publication)
	if err != nil {
		return nil, err
	}
	nativeConfirmation, err := state.native.Confirm(bounded, owned, exported, publication, confirmation)
	if err != nil {
		return nil, err
	}
	healthy, err := state.primary.Activate(bounded, lease, owned, cut, exported, publication, confirmation, nativeConfirmation)
	if err != nil {
		return nil, err
	}
	journal, err := state.primary.OwnedJournal(bounded, healthy)
	if err != nil {
		return nil, err
	}
	store, err = state.native.OwnedCounterStore(bounded, journal)
	if err == nil {
		// Capture the inferred opaque journal without exporting its internal
		// type or accepting a caller-supplied checker. Its original custody and
		// native transport remain the same ones used by this counter owner.
		health = &velocityHealth{check: func(ctx context.Context) error { return state.native.CheckCurrent(ctx, journal) }}
	}
	return store, err
}

// finishVelocityRecovery publishes the returned handle and deferred routing
// together at one lifetime-checked synchronization point, before busy clears.
func (s *storeState) finishVelocityRecovery(ctx context.Context, t *tenantRecovery, store risk.CounterStore, health *velocityHealth, err error) (risk.CounterStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.counter = nil
	t.health = nil
	if lifetimeErr := ctx.Err(); lifetimeErr != nil {
		return nil, lifetimeErr
	}
	if s.closed {
		return nil, identity.UnavailableError{}
	}
	if err != nil {
		return nil, err
	}
	if store == nil || health == nil || health.check == nil {
		return nil, identity.UnavailableError{}
	}
	t.counter = store
	t.health = health
	return store, nil
}

// Close permanently denies new recovery, cancels active primary/native work,
// closes owned native connections and joins recovery within ctx. It never
// closes the caller's pool. A timeout leaves closure permanent; repeat Close
// may finish waiting. No lock spans IO or waiting. Nil ctx is invalid.
func (s StoreSet) Close(ctx context.Context) error {
	if ctx == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	if s.state == nil {
		return nil
	}
	state := s.state
	state.mu.Lock()
	state.closed = true
	state.cancel()
	if state.features != nil && state.features.httpAnonymous != nil {
		state.features.httpAnonymous.close()
	}
	if state.httpRate != nil {
		state.httpRate.limiter.Close()
	}
	if state.features != nil && state.features.httpPasswordReset != nil {
		state.features.httpPasswordReset.close()
	}
	if state.features != nil && state.features.httpRegistrationVerification != nil {
		state.features.httpRegistrationVerification.rate.Close()
	}
	if state.features != nil && state.features.httpSession != nil {
		state.features.httpSession.rate.Close()
	}
	if state.features != nil && state.features.httpMFAList != nil && state.features.httpMFAList.owned {
		state.features.httpMFAList.rate.Close()
	}
	if state.features != nil && state.features.httpEmailAddresses != nil && state.features.httpEmailAddresses.owned {
		state.features.httpEmailAddresses.rate.Close()
	}
	if state.features != nil && state.features.httpEmailRequests != nil {
		state.features.httpEmailRequests.close()
	}
	if state.features != nil && state.features.httpEmailOTPVerification != nil {
		state.features.httpEmailOTPVerification.rate.Close()
	}
	if state.features != nil && state.features.httpPhoneVerification != nil {
		state.features.httpPhoneVerification.rate.Close()
	}
	if state.features != nil && state.features.httpPhoneRemoval != nil {
		state.features.httpPhoneRemoval.rate.Close()
	}
	if state.features != nil && state.features.httpPhoneChange != nil {
		state.features.httpPhoneChange.close()
	}
	if state.features != nil && state.features.httpPhonePasswordReset != nil {
		state.features.httpPhonePasswordReset.close()
	}
	if state.features != nil && state.features.httpEmailOTPChange != nil {
		state.features.httpEmailOTPChange.close()
	}
	if state.features != nil && state.features.httpPasswordVerification != nil {
		state.features.httpPasswordVerification.rate.Close()
	}
	if state.features != nil && state.features.httpPasswordChange != nil {
		state.features.httpPasswordChange.rate.Close()
	}
	if state.features != nil && state.features.httpUsername != nil {
		state.features.httpUsername.close()
	}
	if state.features != nil && state.features.httpMagicLink != nil && state.features.httpMagicLink.rate != nil {
		state.features.httpMagicLink.rate.Close()
	}
	if state.features != nil && state.features.httpMFA != nil {
		state.features.httpMFA.rate.Close()
	}
	if state.features != nil && state.features.httpMFAActiveStepUp != nil {
		state.features.httpMFAActiveStepUp.rate.Close()
	}
	if state.features != nil && state.features.httpMFARecoveryRegeneration != nil {
		state.features.httpMFARecoveryRegeneration.rate.Close()
	}
	if state.features != nil && state.features.httpMFAFactorUpdate != nil {
		state.features.httpMFAFactorUpdate.rate.Close()
	}
	if state.features != nil && state.features.httpMFADisable != nil {
		state.features.httpMFADisable.rate.Close()
	}
	if state.features != nil && state.features.httpMFAEnrollment != nil {
		state.features.httpMFAEnrollment.rate.Close()
		if state.features.httpMFAEnrollment.verifyRate != nil {
			state.features.httpMFAEnrollment.verifyRate.Close()
		}
	}
	drained := state.drained
	state.mu.Unlock()
	if !state.durable {
		if err := state.native.Close(ctx); err != nil {
			return err
		}
	}
	select {
	case <-drained:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (StoreConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.StoreConfiguration(redacted)")
}
func (VelocityStoreConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.VelocityStoreConfiguration(redacted)")
}
func (ReferenceDependencies) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.ReferenceDependencies(redacted)")
}
func (StoreSet) Format(s fmt.State, _ rune)             { _, _ = io.WriteString(s, "reference.StoreSet(redacted)") }
func (StoreConfiguration) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (StoreConfiguration) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityStoreConfiguration) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityStoreConfiguration) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (ReferenceDependencies) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (ReferenceDependencies) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (StoreSet) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (StoreSet) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
