// Package postgres implements an opt-in authenticated durable locale preference
// profile on the existing identity coordinator. It is not an HTTP endpoint or a
// privacy export/deletion acknowledgement.
package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/i18n"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

const preferenceSubject = "locale_preference"
const preferenceAction = "identity.i18n.set"
const preferenceEvent = "identity.i18n.preference.updated.v1"

// PreferenceCredentials borrows the submitted bearer and synchronizer for one
// invocation-scoped store. It never belongs in global configuration, a cache,
// scalar command fields, a log or a serialized request. HTTP owns origin and
// transport policy; this selected browser profile always requires CSRF to write.
type PreferenceCredentials struct {
	Bearer authentication.BearerCredential
	CSRF   session.CSRFToken
}

func (PreferenceCredentials) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreferenceCredentials(redacted)"))
}
func (PreferenceCredentials) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (PreferenceCredentials) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PreferenceStoreConfig freezes the selected single-factor password profile,
// exact current notice and supported canonical locales for new mutations. Notice
// acceptance must be explicit; matching a configured version is not legal
// consent proof. Notice/catalog changes require a separately reviewed migration.
// Audit and Lifecycle are the existing native typed same-Work participants;
// both must also implement RecoveryContributor. No caller-provided domain
// store, transaction, journal, current-authority facts or command callback exists.
// Dependencies remain borrowed, bounded and concurrent-safe. Install the kernel,
// session/CSRF, authorization and participant schemas, then PreferenceMigrationSource
// before enabling this profile. Coordinator.MaximumDuration is 1ms..5s.
type PreferenceStoreConfig struct {
	Supported             []i18n.Locale
	CurrentNoticeVersion  uint64
	PolicyID              string
	PolicyVersion         uint64
	AuditRetentionVersion uint64
	Authorization         authorization.Service
	Clock                 clock.Clock
	Session               sessionpg.SessionServiceConfig
	CSRFKey               session.CSRFKey
	Coordinator           kernel.CoordinatorConfig
	Audit                 kernel.AuditContributor
	Lifecycle             kernel.LifecycleContributor
}

func (PreferenceStoreConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreferenceStoreConfig(redacted)"))
}
func (PreferenceStoreConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (PreferenceStoreConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PreferenceStore implements the exact core port with actual primary session
// authentication and scoped current policy. Construct one per request/custody
// lifetime, discard it after bounded use, and never retain it globally. Copies
// of the supplied credentials remain redacted and nonserializable. Calls on a
// live instance may overlap; all execution state is local to each invocation.
// The primary pool, policy/clock and participant resources remain caller-owned.
// Unsupported anonymous, organization, MFA, passkey and other methods deny;
// this profile never drops an authentication dimension to accept a session.
type PreferenceStore struct {
	pool        *database.Pool
	config      PreferenceStoreConfig
	credentials PreferenceCredentials
	sessions    *session.SessionService
	domain      *kernel.Repository
	policy      *i18n.PreferencePolicy
	commit      func(*kernel.Coordinator, kernel.Work, identity.CommandResult) (identity.CommandResult, error)
}

var _ i18n.PreferenceStore = (*PreferenceStore)(nil)

// NewPreferenceStore validates immutable composition without IO. Bearer custody
// is invocation-scoped, never part of the shared configuration. The constructor
// neither authenticates nor initializes authorities; each operation must do so.
func NewPreferenceStore(pool *database.Pool, c PreferenceStoreConfig, credentials PreferenceCredentials) (*PreferenceStore, error) {
	invalid := i18n.PreferenceInputError{}
	if pool == nil || pool.Raw() == nil || nilPreferenceDependency(c.Authorization) || nilPreferenceDependency(c.Clock) || nilPreferenceDependency(c.Audit) || nilPreferenceDependency(c.Lifecycle) {
		return nil, invalid
	}
	if c.CurrentNoticeVersion == 0 || c.PolicyVersion == 0 || c.AuditRetentionVersion == 0 || c.PolicyID == "" || len(c.PolicyID) > 128 || c.CSRFKey.Version() == 0 {
		return nil, invalid
	}
	if c.Coordinator.MaximumDuration < time.Millisecond || c.Coordinator.MaximumDuration > 5*time.Second {
		return nil, invalid
	}
	profile := c.Session.Profile
	if profile.AuthenticationMethod != "password" || profile.CredentialKind != identity.CredentialPassword || profile.CredentialOwner != "identity/password" {
		return nil, invalid
	}
	if c.Audit.Descriptor() != (kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}) || c.Lifecycle.Descriptor() != (kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) {
		return nil, invalid
	}
	if _, ok := c.Audit.(kernel.RecoveryContributor); !ok {
		return nil, invalid
	}
	if _, ok := c.Lifecycle.(kernel.RecoveryContributor); !ok {
		return nil, invalid
	}
	if _, err := session.ParseToken(credentials.Bearer.Token()); err != nil {
		return nil, invalid
	}
	sessions, err := sessionpg.NewSessionService(pool, c.Session)
	if err != nil {
		return nil, invalid
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	c.Supported = slices.Clone(c.Supported)
	c.Session.Validation.LookupKeys = slices.Clone(c.Session.Validation.LookupKeys)
	keys := make(map[uint32][32]byte, len(c.Coordinator.RetainedFingerprintKeys))
	for version, key := range c.Coordinator.RetainedFingerprintKeys {
		keys[version] = key
	}
	c.Coordinator.RetainedFingerprintKeys = keys
	c.Coordinator.FinalAuthentication = nil
	c.Coordinator.QueryPolicy = &kernel.CommandQueryPolicy{Authorization: c.Authorization, Clock: c.Clock, PolicyVersion: c.PolicyVersion}
	c.Coordinator.AdmissionPolicy = c.Coordinator.QueryPolicy
	s := &PreferenceStore{pool: pool, config: c, credentials: credentials, sessions: sessions, domain: domain, commit: func(c *kernel.Coordinator, w kernel.Work, r identity.CommandResult) (identity.CommandResult, error) {
		return c.Commit(w, r)
	}}
	s.policy, err = i18n.NewPreferencePolicy(i18n.PreferencePolicyConfig{Store: preferenceStorage{s}, Supported: c.Supported, Timeout: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	// Validate the real registry/key configuration now, not at the first write.
	phase := &preferencePhase{store: s}
	if _, _, err := s.coordinator(phase); err != nil {
		return nil, invalid
	}
	return s, nil
}

func nilPreferenceDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func (PreferenceStore) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreferenceStore(redacted)"))
}
func (PreferenceStore) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (PreferenceStore) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// GetPreference authenticates/authorizes the exact current subject before a
// primary read. Absence stays explicit; it never persists negotiated fallbacks.
func (s *PreferenceStore) GetPreference(ctx context.Context, key i18n.PreferenceKey) (i18n.Preference, error) {
	if s == nil || s.policy == nil {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	return s.policy.GetPreference(ctx, key)
}

// SetPreference requires explicit acceptance of the configured current notice,
// actual bearer/CSRF possession and a revision-matched policy decision. Each new
// mutation fences all original native authorities and lifecycle state in the
// sole kernel Work, rechecks at commit, and records its checkpoint/result beside
// audit/outbox/journal effects. Exact replay returns the original preference,
// not the latest projection. Preserve the same complete command on uncertainty;
// retries never manufacture a fresh command or restart a completed mutation.
func (s *PreferenceStore) SetPreference(ctx context.Context, cmd i18n.PreferenceCommand) (i18n.Preference, error) {
	if s == nil || s.policy == nil {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	locale, err := i18n.CanonicalLocale(cmd.Locale)
	if err != nil || string(locale) != cmd.Locale {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	// The existing core policy owns structural validation. Current supported-
	// locale policy applies only after original committed history is resolved;
	// retiring a catalog cannot turn an exact historical retry into a new write.
	structural, err := i18n.NewPreferencePolicy(i18n.PreferencePolicyConfig{Store: preferenceStorage{s}, Supported: []i18n.Locale{locale}, Timeout: s.config.Coordinator.MaximumDuration})
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	return structural.SetPreference(ctx, cmd)
}

// Keep structural validation in its existing owner without recursively invoking
// the exported facade or exposing a trusted unauthenticated persistence port.
type preferenceStorage struct{ store *PreferenceStore }

func (p preferenceStorage) GetPreference(ctx context.Context, key i18n.PreferenceKey) (i18n.Preference, error) {
	return p.store.get(ctx, key)
}
func (p preferenceStorage) SetPreference(ctx context.Context, cmd i18n.PreferenceCommand) (i18n.Preference, error) {
	return p.store.set(ctx, cmd)
}

func (s *PreferenceStore) authenticate(ctx context.Context, key i18n.PreferenceKey, action string) (session.GetResult, authorization.DecisionContext, error) {
	token, err := session.ParseToken(s.credentials.Bearer.Token())
	if err != nil {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceDeniedError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceDeniedError{}
	}
	observed, err := s.sessions.Get(ctx, session.GetRequest{TenantID: key.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceUnavailableError{}
	}
	now := s.config.Clock.Now()
	if !observed.Authenticated || observed.ValidateAt(now) != nil {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceDeniedError{}
	}
	spec, err := observed.Session.Bindings()
	if err != nil || spec.TenantID != key.TenantID || spec.UserID != key.SubjectID {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceDeniedError{}
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.PolicyVersion), Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(spec.UserID), Kind: authorization.SubjectUser}, Tenant: authorization.TenantID(spec.TenantID), Action: authorization.Action(action), Resource: authorization.Resource{Type: preferenceSubject, ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: now.UTC()}}}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if err != nil || ctx.Err() != nil {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceUnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceDeniedError{}
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return session.GetResult{}, authorization.DecisionContext{}, i18n.PreferenceDeniedError{}
	}
	return observed, caller, nil
}

const preferenceCurrentSQL = `SELECT p.locale,p.version::text,p.notice_version::text,p.checkpoint::text,p.generation::text,p.privacy_epoch::text,p.closed
 FROM identity_i18n.preferences p JOIN identity.users u ON u.tenant_id=p.tenant_id AND u.user_id=p.subject_id
 WHERE p.tenant_id=$1 AND p.subject_id=$2 AND u.status='active'`
const preferenceReplaySQL = `SELECT r.locale,r.version::text,r.notice_version::text,r.checkpoint::text,r.generation::text,r.privacy_epoch::text,p.closed
 FROM identity_i18n.preference_updates r JOIN identity_i18n.preferences p USING(tenant_id,subject_id)
 JOIN identity.users u ON u.tenant_id=p.tenant_id AND u.user_id=p.subject_id
 WHERE r.command_id=$1 AND r.tenant_id=$2 AND r.subject_id=$3 AND r.generation=p.generation AND r.privacy_epoch=p.privacy_epoch AND u.status='active'`
const preferenceInsertSQL = `INSERT INTO identity_i18n.preferences(tenant_id,subject_id) VALUES($1,$2) ON CONFLICT DO NOTHING`
const preferenceLockSQL = `SELECT locale,version::text,notice_version::text,checkpoint::text,generation::text,privacy_epoch::text,closed FROM identity_i18n.preferences WHERE tenant_id=$1 AND subject_id=$2 FOR UPDATE`
const preferenceUpdateSQL = `UPDATE identity_i18n.preferences SET locale=$3,version=$4::numeric,notice_version=$5::numeric,checkpoint=$6::numeric WHERE tenant_id=$1 AND subject_id=$2 AND version=$7::numeric AND generation=$8::numeric AND privacy_epoch=$9::numeric AND NOT closed`
const preferenceRetainSQL = `INSERT INTO identity_i18n.preference_updates(command_id,tenant_id,subject_id,locale,version,notice_version,checkpoint,generation,privacy_epoch,command_generation,fingerprint) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7::numeric,$8::numeric,$9::numeric,$10::numeric,$11)`
const preferenceRecoverySQL = `SELECT EXISTS(SELECT 1 FROM identity_i18n.preference_updates WHERE command_id=$1)`

type preferenceState struct {
	value                                i18n.Preference
	checkpoint, generation, privacyEpoch uint64
	closed                               bool
}

func scanPreference(row interface{ Scan(...any) error }, key i18n.PreferenceKey) (preferenceState, error) {
	var state preferenceState
	var version, notice, checkpoint, generation, epoch string
	err := row.Scan(&state.value.Locale, &version, &notice, &checkpoint, &generation, &epoch, &state.closed)
	if err != nil {
		return state, err
	}
	state.value.TenantID, state.value.SubjectID = key.TenantID, key.SubjectID
	for _, field := range []struct {
		raw string
		out *uint64
	}{{version, &state.value.Version}, {notice, &state.value.ConsentNoticeVersion}, {checkpoint, &state.checkpoint}, {generation, &state.generation}, {epoch, &state.privacyEpoch}} {
		value, err := strconv.ParseUint(field.raw, 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != field.raw {
			return preferenceState{}, i18n.PreferenceUnavailableError{}
		}
		*field.out = value
	}
	if state.generation == 0 || state.privacyEpoch == 0 || state.checkpoint < state.value.Version || state.value.Version == 0 && (state.value.Locale != "" || state.value.ConsentNoticeVersion != 0) || state.value.Version > 0 && state.value.ConsentNoticeVersion == 0 {
		return preferenceState{}, i18n.PreferenceUnavailableError{}
	}
	return state, nil
}

func (s *PreferenceStore) current(ctx context.Context, key i18n.PreferenceKey) (preferenceState, error) {
	return scanPreference(s.pool.Raw().QueryRow(ctx, preferenceCurrentSQL, string(key.TenantID), string(key.SubjectID)), key)
}

func (s *PreferenceStore) get(ctx context.Context, key i18n.PreferenceKey) (i18n.Preference, error) {
	observed, _, err := s.authenticate(ctx, key, "identity.i18n.get")
	if err != nil {
		return i18n.Preference{}, err
	}
	state, err := s.current(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return i18n.Preference{}, i18n.PreferenceNotFoundError{}
	}
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceUnavailableError{}
	}
	if state.closed || observed.ValidateAt(s.config.Clock.Now()) != nil {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	if state.value.Version == 0 {
		return i18n.Preference{}, i18n.PreferenceNotFoundError{}
	}
	return state.value, nil
}

func preferenceOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/i18n", OperationID: preferenceAction, SchemaID: "identity.i18n.preference.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *PreferenceStore) set(ctx context.Context, cmd i18n.PreferenceCommand) (i18n.Preference, error) {
	observed, caller, err := s.authenticate(ctx, cmd.Key, preferenceAction)
	if err != nil {
		return i18n.Preference{}, err
	}
	spec, _ := observed.Session.Bindings()
	if observed.Session.CSRFState().Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, s.credentials.CSRF, s.config.CSRFKey) != nil {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	state, err := s.current(ctx, cmd.Key)
	if errors.Is(err, pgx.ErrNoRows) {
		state = preferenceState{generation: 1, privacyEpoch: 1}
	} else if err != nil {
		return i18n.Preference{}, i18n.PreferenceUnavailableError{}
	}
	if state.closed {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	phase := &preferencePhase{store: s, input: cmd, observed: observed, generation: state.generation, privacyEpoch: state.privacyEpoch}
	coordinator, registry, err := s.coordinator(phase)
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	query, recoveryCaller := preferenceRecoveryScope(cmd, caller)
	admission, err := coordinator.ObserveCommandAdmission(ctx, query, recoveryCaller)
	if err != nil {
		return s.result(ctx, phase, identity.CommandResult{}, err)
	}
	if !admission.Absent {
		if admission.Record.Feature == nil || *admission.Record.Feature != preferenceOperation() {
			return i18n.Preference{}, i18n.PreferenceDeniedError{}
		}
		if admission.Record.Outcome == identity.CommitOutcomeCommitted || admission.Record.Outcome == identity.CommitOutcomeInProgress {
			return s.recoverObserved(ctx, phase, coordinator, query, recoveryCaller, admission.Record)
		}
	}
	if cmd.ConsentNoticeVersion != s.config.CurrentNoticeVersion {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	if !slices.Contains(s.config.Supported, i18n.Locale(cmd.Locale)) {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	binding := identity.CommandBinding{CommandID: cmd.CommandID, TenantID: cmd.Key.TenantID, UserID: cmd.Key.SubjectID, ActorID: identity.ActorID(cmd.Key.SubjectID), ActorKind: authorization.SubjectUser, OperationID: preferenceAction, PolicyID: s.config.PolicyID, PolicyVersion: s.config.PolicyVersion, SchemaID: preferenceOperation().SchemaID, SchemaVersion: 1, CorrelationID: string(cmd.CommandID), RecordID: string(cmd.Key.SubjectID)}
	fields, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	fields = append(fields, identity.FeatureField{Name: "preference.locale", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: cmd.Locale}}, identity.FeatureField{Name: "preference.expected-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: cmd.ExpectedVersion}}, identity.FeatureField{Name: "preference.notice-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: cmd.ConsentNoticeVersion}}, identity.FeatureField{Name: "preference.generation", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: state.generation}}, identity.FeatureField{Name: "preference.privacy-epoch", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: state.privacyEpoch}})
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: binding, Operation: preferenceOperation(), Fields: fields}, s.credentials.Bearer)
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	phase.binding, phase.command = binding, command
	plan, err := phase.plan(ctx, coordinator, registry)
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceInputError{}
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, binding, command, plan)
	if reservation == (kernel.Reservation{}) && (result.Outcome == identity.CommitOutcomeInProgress || result.Outcome == identity.CommitOutcomeConflict || errors.As(err, new(identity.ConflictError))) {
		// A command may have appeared after the absence observation. A full-
		// intent conflict cannot distinguish rotated session custody from an
		// altered body while that same-owner original is still live. Observe
		// its sole journal, never replace/execute it under this new admission.
		observed, observeErr := coordinator.ObserveCommandAdmission(ctx, query, recoveryCaller)
		if observeErr != nil {
			return s.result(ctx, phase, identity.CommandResult{}, observeErr)
		}
		if !observed.Absent {
			return s.recoverObserved(ctx, phase, coordinator, query, recoveryCaller, observed.Record)
		}
		return i18n.Preference{}, i18n.PreferenceOutcomeUnknownError{CommandID: cmd.CommandID, Cause: ctx.Err()}
	}
	if err != nil || reservation == (kernel.Reservation{}) {
		return s.result(ctx, phase, result, err)
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return i18n.Preference{}, i18n.PreferenceOutcomeUnknownError{CommandID: cmd.CommandID, Cause: ctx.Err()}
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		result, err = coordinator.Abort(work, err)
		return s.result(ctx, phase, result, err)
	}
	result, err = s.commit(coordinator, work, provisional)
	return s.result(ctx, phase, result, err)
}

func (s *PreferenceStore) recoverObserved(ctx context.Context, p *preferencePhase, c *kernel.Coordinator, q identity.RecoveryQuery, caller authorization.DecisionContext, record kernel.CommandRecord) (i18n.Preference, error) {
	if record.Feature == nil || *record.Feature != preferenceOperation() {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	// Current authorized disclosure/reconciliation never rebinds original
	// admission. Only the native recovery owner can settle a pending command;
	// until then even an indistinguishable altered retry remains unknown.
	original, err := c.RecoverFeatureCommand(ctx, q, caller)
	if original.Outcome == identity.CommitOutcomeCommitted {
		return s.historical(ctx, p, record, original, err)
	}
	return s.result(ctx, p, original, err)
}

func preferenceRecoveryScope(cmd i18n.PreferenceCommand, caller authorization.DecisionContext) (identity.RecoveryQuery, authorization.DecisionContext) {
	// The kernel's receipt resource is the exact current identity.user, not the
	// locale record. Current policy must independently authorize this read;
	// changing only resource spelling never grants permission by itself.
	caller = caller.Clone()
	caller.CorrelationID = string(cmd.CommandID)
	caller.Request.Resource.Type = "identity.user"
	caller.Request.Resource.ID = authorization.ResourceID(cmd.Key.SubjectID)
	query := identity.RecoveryQuery{CommandID: cmd.CommandID, TenantID: cmd.Key.TenantID, UserID: cmd.Key.SubjectID, ActorID: identity.ActorID(cmd.Key.SubjectID), ActorKind: authorization.SubjectUser, OperationID: preferenceAction, RecordID: string(cmd.Key.SubjectID)}
	return query, caller
}

func (s *PreferenceStore) historical(ctx context.Context, p *preferencePhase, record kernel.CommandRecord, result identity.CommandResult, err error) (i18n.Preference, error) {
	unknown := i18n.PreferenceOutcomeUnknownError{CommandID: p.input.CommandID, Cause: ctx.Err()}
	if errors.As(err, new(identity.ForbiddenError)) {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	if err != nil || result.Validate() != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding != record.Binding || result.Feature == nil || result.Feature.Operation != preferenceOperation() {
		return i18n.Preference{}, unknown
	}
	if result.Feature.BeforeVersion != p.input.ExpectedVersion || result.Feature.AfterVersion != p.input.ExpectedVersion+1 {
		return i18n.Preference{}, i18n.PreferenceConflictError{}
	}
	state, err := scanPreference(s.pool.Raw().QueryRow(ctx, preferenceReplaySQL, string(p.input.CommandID), string(p.input.Key.TenantID), string(p.input.Key.SubjectID)), p.input.Key)
	if err != nil {
		return i18n.Preference{}, unknown
	}
	if state.closed || state.generation != p.generation || state.privacyEpoch != p.privacyEpoch || p.observed.ValidateAt(s.config.Clock.Now()) != nil {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	if state.value.Version != p.input.ExpectedVersion+1 || state.value.Locale != p.input.Locale || state.value.ConsentNoticeVersion != p.input.ConsentNoticeVersion {
		return i18n.Preference{}, i18n.PreferenceConflictError{}
	}
	return state.value, nil
}

func (s *PreferenceStore) coordinator(phase *preferencePhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.domain, phase, s.config.Audit, s.config.Lifecycle})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.pool, registry, s.config.Coordinator)
	return c, registry, err
}

func (s *PreferenceStore) result(ctx context.Context, p *preferencePhase, result identity.CommandResult, err error) (i18n.Preference, error) {
	if result.Outcome == identity.CommitOutcomeConflict || errors.As(err, new(identity.ConflictError)) {
		return i18n.Preference{}, i18n.PreferenceConflictError{}
	}
	if errors.As(err, new(identity.ForbiddenError)) {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	if result.Outcome != identity.CommitOutcomeCommitted || err != nil || result.Binding != p.binding || result.Feature == nil || result.Feature.Operation != preferenceOperation() || result.Feature.BeforeVersion != p.input.ExpectedVersion || result.Feature.AfterVersion != p.input.ExpectedVersion+1 {
		return i18n.Preference{}, i18n.PreferenceOutcomeUnknownError{CommandID: p.input.CommandID, Cause: ctx.Err()}
	}
	state, readErr := scanPreference(s.pool.Raw().QueryRow(ctx, preferenceReplaySQL, string(p.input.CommandID), string(p.input.Key.TenantID), string(p.input.Key.SubjectID)), p.input.Key)
	if readErr != nil {
		return i18n.Preference{}, i18n.PreferenceOutcomeUnknownError{CommandID: p.input.CommandID, Cause: ctx.Err()}
	}
	if state.closed || p.observed.ValidateAt(s.config.Clock.Now()) != nil {
		return i18n.Preference{}, i18n.PreferenceDeniedError{}
	}
	if state.generation != p.generation || state.privacyEpoch != p.privacyEpoch || state.value.Version != p.input.ExpectedVersion+1 || state.value.Locale != p.input.Locale || state.value.ConsentNoticeVersion != p.input.ConsentNoticeVersion {
		return i18n.Preference{}, i18n.PreferenceOutcomeUnknownError{CommandID: p.input.CommandID, Cause: ctx.Err()}
	}
	return state.value, nil
}

type preferencePhase struct {
	store                    *PreferenceStore
	input                    i18n.PreferenceCommand
	binding                  identity.CommandBinding
	command                  identity.Command
	observed                 session.GetResult
	generation, privacyEpoch uint64
}

func (*preferencePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/i18n/postgres", ContractID: "identity.i18n.preference", Version: 1}
}
func (*preferencePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{preferenceOperation()}
}

func (p *preferencePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	invalid := identity.InvalidInputError{Field: "preference_command"}
	if p == nil || p.store == nil || command != p.command {
		return invalid
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != p.binding || spec.Operation != preferenceOperation() {
		return invalid
	}
	if p.binding.ActorKind != authorization.SubjectUser || string(p.binding.ActorID) != string(p.binding.UserID) || p.binding.RecordID != string(p.binding.UserID) {
		return invalid
	}
	if p.input.ExpectedVersion == math.MaxUint64 || p.input.ConsentNoticeVersion != p.store.config.CurrentNoticeVersion {
		return invalid
	}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: preferenceOperation()}
	lifecycle := kernel.LifecyclePlan{EventType: preferenceEvent, BeforeVersion: p.input.ExpectedVersion, AfterVersion: p.input.ExpectedVersion + 1}
	if plan.SubjectType != preferenceSubject || plan.Feature == nil || *plan.Feature != feature || plan.Lifecycle == nil || *plan.Lifecycle != lifecycle {
		return invalid
	}
	if len(plan.Audits) != 1 {
		return invalid
	}
	declaredAudit := plan.Audits[0]
	if declaredAudit.EventType != preferenceAction || declaredAudit.RetentionClass != "standard" || declaredAudit.RetentionPolicyVersion != p.store.config.AuditRetentionVersion {
		return invalid
	}
	return nil
}

func (p *preferencePhase) plan(ctx context.Context, c *kernel.Coordinator, registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b := p.binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: p.store.config.Clock.Now().UTC().Truncate(time.Microsecond), Action: preferenceAction, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: preferenceSubject, ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": preferenceSubject, "aggregate.before_version": strconv.FormatUint(p.input.ExpectedVersion, 10), "aggregate.after_version": strconv.FormatUint(p.input.ExpectedVersion+1, 10), "retention.class": "standard"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, preferenceOperation(), preferenceSubject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return c.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: preferenceSubject, Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: preferenceOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: preferenceEvent, BeforeVersion: p.input.ExpectedVersion, AfterVersion: p.input.ExpectedVersion + 1}, Audits: []kernel.AuditPlan{{EventType: preferenceAction, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: p.store.config.AuditRetentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}})
}

func (p *preferencePhase) check(ctx context.Context, w kernel.Work, command identity.Command, applying bool) error {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || command != p.command || b != p.binding || feature.Operation != preferenceOperation() {
		return identity.ForbiddenError{}
	}
	if applying {
		if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
			return err
		}
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.store.config.Session.Profile, p.observed.Session, b)
	if err != nil {
		return identity.ForbiddenError{}
	}
	token, ok := command.SessionToken()
	if !ok {
		return identity.ForbiddenError{}
	}
	parsed, err := session.ParseToken(token.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	spec, _ := p.observed.Session.Bindings()
	matched := false
	for _, key := range p.store.config.Session.Validation.LookupKeys {
		digest, err := parsed.Digest(key, string(b.TenantID))
		if err != nil {
			return identity.ForbiddenError{}
		}
		if digest.KeyVersion != spec.Lookup.KeyVersion {
			continue
		}
		if subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:]) != 1 {
			return identity.ForbiddenError{}
		}
		matched = true
	}
	if !matched {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireCSRF(ctx, w, p.store.config.Session.Repository, p.observed.Session, p.store.credentials.CSRF, p.store.config.CSRFKey); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if p.observed.ValidateAt(now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *preferencePhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.check(ctx, w, command, true); err != nil {
		return identity.FeatureReceipt{}, err
	}
	key := p.input.Key
	if _, err := w.Exec(ctx, preferenceInsertSQL, string(key.TenantID), string(key.SubjectID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	rows, err := w.Query(ctx, preferenceLockSQL, string(key.TenantID), string(key.SubjectID))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err == nil {
			err = identity.UnavailableError{}
		}
		return identity.FeatureReceipt{}, err
	}
	state, err := scanPreference(rows, key)
	if err != nil {
		rows.Close()
		return identity.FeatureReceipt{}, err
	}
	extra := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if extra {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if state.closed || state.generation != p.generation || state.privacyEpoch != p.privacyEpoch {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if state.value.Version != p.input.ExpectedVersion || state.checkpoint == math.MaxUint64 {
		return identity.FeatureReceipt{}, identity.ConflictError{CommandID: p.input.CommandID}
	}
	count, err := w.Exec(ctx, preferenceUpdateSQL, string(key.TenantID), string(key.SubjectID), p.input.Locale, strconv.FormatUint(p.input.ExpectedVersion+1, 10), strconv.FormatUint(p.input.ConsentNoticeVersion, 10), strconv.FormatUint(state.checkpoint+1, 10), strconv.FormatUint(p.input.ExpectedVersion, 10), strconv.FormatUint(p.generation, 10), strconv.FormatUint(p.privacyEpoch, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{CommandID: p.input.CommandID}
	}
	_, fingerprint, commandGeneration, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, err = w.Exec(ctx, preferenceRetainSQL, string(p.input.CommandID), string(key.TenantID), string(key.SubjectID), p.input.Locale, strconv.FormatUint(p.input.ExpectedVersion+1, 10), strconv.FormatUint(p.input.ConsentNoticeVersion, 10), strconv.FormatUint(state.checkpoint+1, 10), strconv.FormatUint(p.generation, 10), strconv.FormatUint(p.privacyEpoch, 10), strconv.FormatUint(commandGeneration, 10), fingerprint[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: preferenceOperation(), BeforeVersion: p.input.ExpectedVersion, AfterVersion: p.input.ExpectedVersion + 1}, nil
}

func (p *preferencePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command, false)
}

func (p *preferencePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || feature.Operation != preferenceOperation() {
		return kernel.RecoveryUnknown, identity.InvalidInputError{Field: "preference_recovery"}
	}
	rows, err := w.Query(ctx, preferenceRecoverySQL, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if err := rows.Scan(&exists); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryNotCommitted, nil
}
