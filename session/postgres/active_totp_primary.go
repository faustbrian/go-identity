package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// PasswordActiveTOTPPrimaryConfig selects native password and password/MFA
// session reads plus retained synchronizer keys. No application SessionReader
// or reauthentication callback is accepted. Cookie transport is mandatory in
// this profile; unsupported method/organization/passkey owners deny.
type PasswordActiveTOTPPrimaryConfig struct {
	Session  SessionServiceConfig
	CSRFKeys []session.CSRFKey
}

// PasswordActiveTOTPPrimarySource borrows the primary pool and owns immutable
// native session/current-authority composition. It has no background workers,
// cache or transaction ownership. The pool must outlive concurrent bounded calls.
type PasswordActiveTOTPPrimarySource struct {
	sessions *session.SessionService
	guard    *PasswordMFAActionSessionGuard
	config   PasswordActiveTOTPPrimaryConfig
}

// NewPasswordActiveTOTPPrimarySource freezes actual primary adapter ownership.
// Install the selected password/MFA/session histories before use. Construction
// performs no IO, proof generation or session promotion.
func NewPasswordActiveTOTPPrimarySource(pool *database.Pool, c PasswordActiveTOTPPrimaryConfig) (*PasswordActiveTOTPPrimarySource, error) {
	if len(c.CSRFKeys) < 1 || len(c.CSRFKeys) > 64 {
		return nil, session.ErrInvalidSessionCommand
	}
	for i, key := range c.CSRFKeys {
		if key.Version() == 0 {
			return nil, session.ErrInvalidSessionCommand
		}
		for _, old := range c.CSRFKeys[:i] {
			if old.Version() == key.Version() {
				return nil, session.ErrInvalidSessionCommand
			}
		}
	}
	guard, err := NewPasswordMFAActionSessionGuard(c.Session.Repository, c.Session.Profile)
	if err != nil {
		return nil, err
	}
	profile := c.Session.Profile
	native, err := NewSelectedSessionService(pool, SelectedSessionServiceConfig{Repository: c.Session.Repository, Validation: c.Session.Validation, Admission: SelectedSessionAdmissionConfig{SingleFactor: SingleFactorSessionAdmissionConfig{Verified: &profile}, MFAPassword: &profile}})
	if err != nil {
		return nil, err
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	c.Session.Validation.LookupKeys = slices.Clone(c.Session.Validation.LookupKeys)
	return &PasswordActiveTOTPPrimarySource{sessions: native, guard: guard, config: c}, nil
}

type activePrimarySnapshot struct {
	Schema  uint32
	Profile activePrimaryProfile
	Store   Config
	Fields  []identity.FeatureField
	Until   time.Time
}

type activePrimaryProfile IdentifierAdmissionConfig
type passwordActiveTOTPPrimary struct {
	source        *PasswordActiveTOTPPrimarySource
	request       activeSessionRequest
	original      session.Session
	until         time.Time
	expected      identity.Command
	continuation  bool
	originalUntil time.Time
	observation   session.GetResult
	observed      bool
}

type activeSessionRequest struct {
	TenantID    identity.TenantID
	UserID      identity.UserID
	CommandID   identity.CommandID
	OperationID string
	Session     auth.BearerCredential
	CSRFToken   session.CSRFToken
}

// PrepareStepUp authenticates the actual submitted cookie using the configured
// native primary reader, then checks its exact synchronizer and caller subject.
// The returned owned observation is unchanged, including its exclusive expiry.
// It verifies no factor and never upgrades or renews the source session.
func (s *PasswordActiveTOTPPrimarySource) PrepareStepUp(ctx context.Context, r mfa.TotpVerifyRequest) (mfapg.TOTPActivePrimary, session.GetResult, error) {
	zero := session.GetResult{}
	if ctx == nil || s == nil || s.sessions == nil || r.StepUp == nil || r.Validate() != nil {
		return nil, zero, session.ErrInvalidSessionCommand
	}
	return s.prepareCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.totp-verify", Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken})
}

// PrepareRegeneration authenticates a real current cookie/synchronizer without
// fabricating a TOTP request or treating an MFA session as a fresh factor proof.
// The native regeneration owner separately authenticates and consumes that proof.
func (s *PasswordActiveTOTPPrimarySource) PrepareRegeneration(ctx context.Context, r mfa.RecoveryRegenerateRequest) (mfapg.TOTPActivePrimary, session.GetResult, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	return s.prepareCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.recovery-regenerate", Session: r.Session, CSRFToken: r.CSRFToken})
}

// PrepareFactorUpdate authenticates actual cookie/synchronizer custody for the
// keyed command selected by MFA's owner. It does not fabricate a regeneration
// request, authenticate a factor projection or renew the original observation.
func (s *PasswordActiveTOTPPrimarySource) PrepareFactorUpdate(ctx context.Context, r mfa.FactorUpdateRequest, command identity.CommandID) (mfapg.TOTPActivePrimary, session.GetResult, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil || r.CommandID != "" && r.CommandID != command {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	return s.prepareCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: command, OperationID: "identity.mfa.factor-update", Session: r.Session, CSRFToken: r.CSRFToken})
}

// PrepareDisable authenticates actual native cookie/synchronizer custody for
// exact disable, not a translated update request or caller's proof projection.
func (s *PasswordActiveTOTPPrimarySource) PrepareDisable(ctx context.Context, r mfa.DisableRequest, command identity.CommandID) (mfapg.TOTPActivePrimary, session.GetResult, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil || r.CommandID != "" && r.CommandID != command {
		return nil, session.GetResult{}, session.ErrInvalidSessionCommand
	}
	return s.prepareCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: command, OperationID: "identity.mfa.disable", Session: r.Session, CSRFToken: r.CSRFToken})
}

func (s *PasswordActiveTOTPPrimarySource) prepareCurrent(ctx context.Context, r activeSessionRequest) (mfapg.TOTPActivePrimary, session.GetResult, error) {
	zero := session.GetResult{}
	token, err := session.ParseToken(r.Session.Token())
	if err != nil {
		return nil, zero, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return nil, zero, identity.ForbiddenError{}
	}
	got, err := s.sessions.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
	if err != nil {
		return nil, zero, err
	}
	b, err := got.Session.Bindings()
	if err != nil || got.ValidateAt(time.Now()) != nil || b.TenantID != r.TenantID || b.UserID != r.UserID {
		return nil, zero, identity.ForbiddenError{}
	}
	p := &passwordActiveTOTPPrimary{source: s, request: r, original: got.Session, until: got.ValidUntil()}
	if _, err := p.keys(); err != nil {
		return nil, zero, err
	}
	return p, got, nil
}

// RestoreStepUp is an IO-free native restore of already envelope-authenticated
// snapshot bytes. It authenticates neither arbitrary bytes nor current owners.
// Submitted bearer/CSRF must still match the exact original record; final Work
// compares current owners and the original exclusive deadline before mutation.
func (s *PasswordActiveTOTPPrimarySource) RestoreStepUp(ctx context.Context, r mfa.TotpVerifyRequest, wire []byte) (mfapg.TOTPActivePrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.StepUp == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.totp-verify", Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken}, wire)
}

// RestoreRegeneration restores only native-envelope-authenticated original
// session metadata. It checks bearer/CSRF possession, not current authorization,
// and cannot renew the retained deadline or manufacture factor verification.
func (s *PasswordActiveTOTPPrimarySource) RestoreRegeneration(ctx context.Context, r mfa.RecoveryRegenerateRequest, wire []byte) (mfapg.TOTPActivePrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.recovery-regenerate", Session: r.Session, CSRFToken: r.CSRFToken}, wire)
}

// RestoreFactorUpdate checks original possession against MFA-authenticated
// snapshot bytes and the retained keyed command without IO or new freshness.
// The mutation still must fence current owners in the actual protected Work.
func (s *PasswordActiveTOTPPrimarySource) RestoreFactorUpdate(ctx context.Context, r mfa.FactorUpdateRequest, command identity.CommandID, wire []byte) (mfapg.TOTPActivePrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil || r.CommandID != "" && r.CommandID != command {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: command, OperationID: "identity.mfa.factor-update", Session: r.Session, CSRFToken: r.CSRFToken}, wire)
}

// RestoreDisable checks retained original session possession without IO,
// current authorization or freshness renewal. MFA must authenticate wire first.
func (s *PasswordActiveTOTPPrimarySource) RestoreDisable(ctx context.Context, r mfa.DisableRequest, command identity.CommandID, wire []byte) (mfapg.TOTPActivePrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(string(command)); err != nil || r.CommandID != "" && r.CommandID != command {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreCurrent(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: command, OperationID: "identity.mfa.disable", Session: r.Session, CSRFToken: r.CSRFToken}, wire)
}

// RestoreReplacementForURI checks original bearer/synchronizer possession
// against the native factor-update snapshot already authenticated by MFA.
// It neither translates password-enable provenance nor renews freshness.
func (s *PasswordActiveTOTPPrimarySource) RestoreReplacementForURI(ctx context.Context, r mfa.TotpUriRequest, wire []byte, ceiling time.Time) (mfapg.TOTPReplacementPrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreReplacement(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.totp-uri", Session: r.Session, CSRFToken: r.CSRFToken}, wire, ceiling)
}

// RestoreReplacementForConfirmation restores the same original active-session
// custody for the exact enrollment variant. Current owners and original
// exclusive deadline remain checked by the protected continuation Work.
func (s *PasswordActiveTOTPPrimarySource) RestoreReplacementForConfirmation(ctx context.Context, r mfa.TotpVerifyRequest, wire []byte, ceiling time.Time) (mfapg.TOTPReplacementPrimary, error) {
	if ctx == nil || s == nil || s.sessions == nil || r.Enrollment == nil || r.Validate() != nil || len(wire) < 1 || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	return s.restoreReplacement(ctx, activeSessionRequest{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), CommandID: r.CommandID, OperationID: "identity.mfa.totp-verify", Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken}, wire, ceiling)
}

func (s *PasswordActiveTOTPPrimarySource) restoreReplacement(ctx context.Context, r activeSessionRequest, wire []byte, ceiling time.Time) (mfapg.TOTPReplacementPrimary, error) {
	if ceiling.IsZero() {
		return nil, session.ErrInvalidSessionCommand
	}
	restored, err := s.restoreCurrent(ctx, r, wire)
	if err != nil {
		return nil, err
	}
	p, ok := restored.(*passwordActiveTOTPPrimary)
	if !ok {
		return nil, session.ErrInvalidSessionCommand
	}
	p.continuation, p.originalUntil, p.until = true, p.until, ceiling
	return p, nil
}

// ReadCurrent acquires one genuine native observation before locks. Neither
// the retained original snapshot nor a second call resets its freshness.
func (p *passwordActiveTOTPPrimary) ReadCurrent(ctx context.Context) error {
	if ctx == nil || p == nil || p.source == nil || !p.continuation {
		return identity.ForbiddenError{}
	}
	if p.observed {
		return p.observation.ValidateAt(time.Now().UTC())
	}
	token, err := session.ParseToken(p.request.Session.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return identity.ForbiddenError{}
	}
	current, err := p.source.sessions.Get(ctx, session.GetRequest{TenantID: p.request.TenantID, Credential: credential})
	if err != nil {
		return err
	}
	if current.ValidateAt(time.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	original, _, originalErr := encodeRecord(p.original)
	actual, _, actualErr := encodeRecord(current.Session)
	defer clear(original)
	defer clear(actual)
	if originalErr != nil || actualErr != nil || !bytes.Equal(original, actual) {
		return identity.ForbiddenError{}
	}
	p.observation, p.observed = current, true
	return nil
}

// OriginalDeadline returns unchanged initial observation custody, not a lease.
func (p *passwordActiveTOTPPrimary) OriginalDeadline() (time.Time, error) {
	if p == nil || !p.continuation || p.originalUntil.IsZero() {
		return time.Time{}, identity.ForbiddenError{}
	}
	return p.originalUntil, nil
}

func (s *PasswordActiveTOTPPrimarySource) restoreCurrent(ctx context.Context, r activeSessionRequest, wire []byte) (mfapg.TOTPActivePrimary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var v activePrimarySnapshot
	if decodeActivePrimary(wire, &v) != nil || v.Schema != 1 || IdentifierAdmissionConfig(v.Profile) != s.config.Session.Profile || v.Store != s.config.Session.Repository || v.Until.IsZero() {
		return nil, identity.ForbiddenError{}
	}
	original, err := OriginalSessionFromFields(r.TenantID, r.UserID, v.Fields)
	if err != nil {
		return nil, err
	}
	p := &passwordActiveTOTPPrimary{source: s, request: r, original: original, until: v.Until}
	if _, err := p.keys(); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeActivePrimary(wire []byte, v *activePrimarySnapshot) error {
	// Use the owned closed record codec's strict JSON parser and trailing-data
	// rejection; the native MFA envelope authenticates bytes before this call.
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func (p *passwordActiveTOTPPrimary) keys() (PasswordMFAActionSessionInput, error) {
	zero := PasswordMFAActionSessionInput{}
	if p == nil || p.source == nil {
		return zero, identity.ForbiddenError{}
	}
	s, err := p.original.Bindings()
	if err != nil {
		return zero, err
	}
	token, err := session.ParseToken(p.request.Session.Token())
	if err != nil {
		return zero, identity.ForbiddenError{}
	}
	var lookup session.DigestKey
	matches := 0
	for _, key := range p.source.config.Session.Validation.LookupKeys {
		digest, e := token.Digest(key, string(s.TenantID))
		if e != nil {
			return zero, identity.ForbiddenError{}
		}
		if digest.KeyVersion == s.Lookup.KeyVersion {
			lookup = key
			matches++
		}
	}
	csrf, err := p.original.CSRFState().Bindings()
	if err != nil {
		return zero, identity.ForbiddenError{}
	}
	var csrfKey session.CSRFKey
	for _, key := range p.source.config.CSRFKeys {
		if key.Version() == csrf.KeyVersion {
			csrfKey = key
		}
	}
	if matches != 1 || csrfKey.Version() == 0 {
		return zero, identity.ForbiddenError{}
	}
	input := PasswordMFAActionSessionInput{Command: p.expected, Original: p.original, ValidUntil: p.until, LookupKey: lookup, CSRFToken: p.request.CSRFToken, CSRFKey: csrfKey}
	// At preparation/restoration no feature command exists yet, but possession
	// still must be checked before any encrypted-factor read or risk generation.
	digest, err := token.Digest(lookup, string(s.TenantID))
	if err != nil || digest.KeyVersion != s.Lookup.KeyVersion || !hmac.Equal(digest.Sum[:], s.Lookup.Sum[:]) || p.original.CSRFState().Check(session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, input.CSRFToken, csrfKey) != nil {
		return zero, identity.ForbiddenError{}
	}
	return input, nil
}

func (p *passwordActiveTOTPPrimary) Original() (session.Session, error) {
	if p == nil || p.source == nil {
		return session.Session{}, identity.ForbiddenError{}
	}
	return p.original, nil
}
func (p *passwordActiveTOTPPrimary) Deadline() (time.Time, error) {
	if p == nil || p.until.IsZero() {
		return time.Time{}, identity.ForbiddenError{}
	}
	if p.continuation {
		if !p.observed || p.observation.ValidateAt(time.Now().UTC()) != nil {
			return time.Time{}, identity.ForbiddenError{}
		}
		if p.observation.ValidUntil().Before(p.until) {
			return p.observation.ValidUntil(), nil
		}
	}
	return p.until, nil
}
func (p *passwordActiveTOTPPrimary) Snapshot() ([]byte, error) {
	if p == nil || p.source == nil {
		return nil, identity.ForbiddenError{}
	}
	fields, err := OriginalSessionFields(p.original)
	if err != nil {
		return nil, err
	}
	until := p.until
	if p.continuation {
		until = p.originalUntil
	}
	wire, err := json.Marshal(activePrimarySnapshot{Schema: 1, Profile: activePrimaryProfile(p.source.config.Session.Profile), Store: p.source.config.Session.Repository, Fields: fields, Until: until})
	if err != nil || len(wire) > 32768 {
		return nil, session.ErrInvalidSessionCommand
	}
	return wire, nil
}
func (p *passwordActiveTOTPPrimary) Command(b identity.CommandBinding, fields []identity.FeatureField) (identity.Command, error) {
	if p == nil || p.source == nil || b.CommandID != p.request.CommandID || b.TenantID != p.request.TenantID || b.UserID != p.request.UserID || b.OperationID != p.request.OperationID || !nativeMFAActionBinding(b) {
		return identity.Command{}, identity.ForbiddenError{}
	}
	original, err := OriginalSessionFields(p.original)
	if err != nil {
		return identity.Command{}, err
	}
	original = append(original, fields...)
	original = append(original, identity.FeatureField{Name: "mfa.session-valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.until.UTC().Format(storedTimeLayout)}})
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	c, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: original}, p.request.Session)
	if err == nil {
		p.expected = c
	}
	return c, err
}
func (p *passwordActiveTOTPPrimary) Admit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.source == nil {
		return identity.ForbiddenError{}
	}
	spec, ok := c.Feature()
	expected, has := p.expected.Feature()
	if !ok || !has || spec.Binding != expected.Binding {
		return identity.ForbiddenError{}
	}
	// Counter preparation adds owner fields without replacing bearer custody.
	input, err := p.keys()
	if err != nil {
		return err
	}
	input.Command = c
	preparation, ok := owner.(kernel.FeaturePreparationContributor)
	if !ok {
		return identity.ForbiddenError{}
	}
	if p.continuation {
		return p.source.guard.checkObservation(ctx, w, preparation, input, false, &p.observation)
	}
	return p.source.guard.AdmitPreparation(ctx, w, preparation, input)
}
func (p *passwordActiveTOTPPrimary) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if p == nil || p.source == nil {
		return identity.ForbiddenError{}
	}
	input, err := p.keys()
	if err != nil {
		return err
	}
	input.Command = c
	commit, ok := owner.(kernel.FeatureCommitContributor)
	if !ok {
		return identity.ForbiddenError{}
	}
	if p.continuation {
		return p.source.guard.checkObservation(ctx, w, commit, input, false, &p.observation)
	}
	return p.source.guard.RecheckCommit(ctx, w, commit, input)
}

// Format redacts native primary ownership and synchronizer configuration.
func (PasswordActiveTOTPPrimaryConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordActiveTOTPPrimaryConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (PasswordActiveTOTPPrimaryConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export.
func (PasswordActiveTOTPPrimaryConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts borrowed owners.
func (*PasswordActiveTOTPPrimarySource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordActiveTOTPPrimarySource(redacted)"))
}

// MarshalJSON rejects implicit source export.
func (*PasswordActiveTOTPPrimarySource) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit source export.
func (*PasswordActiveTOTPPrimarySource) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

var _ mfapg.TOTPActivePrimarySource = (*PasswordActiveTOTPPrimarySource)(nil)
var _ mfapg.RecoveryRegenerationPrimarySource = (*PasswordActiveTOTPPrimarySource)(nil)
var _ mfapg.FactorUpdatePrimarySource = (*PasswordActiveTOTPPrimarySource)(nil)
var _ mfapg.TOTPReplacementPrimarySource = (*PasswordActiveTOTPPrimarySource)(nil)

func (*passwordActiveTOTPPrimary) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.passwordActiveTOTPPrimary(redacted)"))
}
func (*passwordActiveTOTPPrimary) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (*passwordActiveTOTPPrimary) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
