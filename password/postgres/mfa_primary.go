package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// MFAEnablePrimaryConfig selects an exact password-specific enrollment target.
// MaximumAge and PrimaryFreshFor are positive and at most fifteen minutes;
// freshness is measured from original proof/authentication times, never lookup.
// Install password migration 7 before consuming. No risk or factor policy is
// provided here: the enrollment workflow must independently enforce them.
type MFAEnablePrimaryConfig struct {
	Audience                    string
	MaximumAge, PrimaryFreshFor time.Duration
}

// MFAEnablePrimaryRequest borrows the source bearer and original signed
// reauthentication proof for one stable enrollment command and factor ID.
// TenantID and Caller require trusted composition. This initial native profile
// accepts single-factor password sessions only. It does not grant MFA, bypass
// required browser CSRF/origin checks or authorize other enrollment methods.
type MFAEnablePrimaryRequest struct {
	TenantID  identity.TenantID
	CommandID identity.CommandID
	FactorID  string
	Session   auth.BearerCredential
	Proof     auth.ReauthenticationProof
	Caller    authorization.DecisionContext
	CSRFToken session.CSRFToken
}

// MFAEnablePrimarySource borrows the existing immutable password source and
// its primary pool. It owns no transaction, retry, cache or goroutine. Prepare
// authenticates signed original custody outside protected locks; the returned
// admission independently fences current primary authority inside Apply.
// Concurrent calls require immutable inputs; close the pool only after draining.
type MFAEnablePrimarySource struct {
	source    *ReauthenticationService
	config    MFAEnablePrimaryConfig
	validator *auth.AuthorityAuthenticator
	csrfKeys  []session.CSRFKey
}

type mfaEnablePrimaryCustody struct {
	source   *MFAEnablePrimarySource
	request  MFAEnablePrimaryRequest
	original session.Session
	record   auth.SignedReauthenticationRecord
	use      auth.ReauthenticationUse
	fields   []identity.FeatureField
	uri      *mfaURIPrimaryCustody
	csrf     *mfaEnableCSRFCustody
}

// MFAEnableAdmission retains an authenticated original behind immutable opaque
// custody. Zero denies. Copies share immutable state; it conveys no permission
// outside the exact registered enrollment participant's synchronous Work.
// It is intermediate adapter custody, not a public enrollment result or proof.
type MFAEnableAdmission struct {
	custody func() mfaEnablePrimaryCustody
}

// NewMFAEnablePrimarySource validates native composition without IO. The exact
// identity.password.verify -> identity.mfa.enable target must already be in the
// password source's startup allowlist. The upstream authentication validator
// remains the sole signature engine; configuration alone grants no admission.
func NewMFAEnablePrimarySource(source *ReauthenticationService, c MFAEnablePrimaryConfig) (*MFAEnablePrimarySource, error) {
	if source == nil || source.repository == nil || !source.repository.configuredWriter() || source.sessions == nil || c.MaximumAge <= 0 || c.MaximumAge > 15*time.Minute || c.PrimaryFreshFor <= 0 || c.PrimaryFreshFor > 15*time.Minute || !reauthenticationText(c.Audience, 256) {
		return nil, password.ErrPasswordWork
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: c.Audience}
	if !slices.Contains(source.c.Targets, target) {
		return nil, password.ErrPasswordWork
	}
	var keys []auth.AuthorityKey
	for id, key := range source.c.VerificationKeys {
		keys = append(keys, auth.AuthorityKey{ID: id, PublicKey: key})
	}
	validator, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: source.c.Issuer, Environment: source.c.Environment, Audience: c.Audience, Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: keys, EvidenceKeys: keys, Source: passwordProofSource{source.repository}, Clock: passwordProofClock{source.c.Verifier.Now}, ReadTimeout: min(source.c.Repository.MaximumDuration, 5*time.Second), ClockUncertainty: time.Millisecond, MaximumDelegationDepth: 1})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return &MFAEnablePrimarySource{source: source, config: c, validator: validator}, nil
}

func mfaEnableOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.enable", SchemaID: "mfa-enable", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Prepare validates original bearer possession, exact signed evidence, target,
// credential version, recent primary authentication and user policy. It neither
// consumes a proof nor creates an enrollment. Errors reveal no partial custody;
// earlier caller deadlines win over the existing source's bounded read budget.
// Native cookie composition must additionally check and fence its synchronizer.
func (s *MFAEnablePrimarySource) Prepare(ctx context.Context, r MFAEnablePrimaryRequest) (MFAEnableAdmission, error) {
	if ctx == nil || s == nil || s.source == nil || s.validator == nil {
		return MFAEnableAdmission{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return MFAEnableAdmission{}, err
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(r.FactorID); err != nil {
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	bounded, cancel := context.WithTimeout(ctx, s.source.c.Repository.MaximumDuration)
	defer cancel()
	original, err := s.source.lookup(bounded, r.TenantID, r.Session)
	if err != nil {
		return MFAEnableAdmission{}, err
	}
	bindings, err := original.Bindings()
	if err != nil {
		return MFAEnableAdmission{}, password.ErrPasswordWork
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: s.config.Audience}
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: bindings.UserID, ActorID: identity.ActorID(bindings.UserID), ActorKind: authorization.SubjectUser, OperationID: target.Action, RecordID: r.FactorID}
	if err := s.source.authorize(bounded, r.Caller, b, target); err != nil {
		return MFAEnableAdmission{}, err
	}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.TenantID), Subject: string(bindings.UserID), Purpose: target.Purpose, Audience: target.Audience}, SessionID: bindings.SessionID, SessionVersion: bindings.Version, Action: target.Action, MaximumAge: s.config.MaximumAge}
	if s.validator.ValidateReauthenticationProof(bounded, r.Proof, use) != nil {
		if err := bounded.Err(); err != nil {
			return MFAEnableAdmission{}, err
		}
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	record, err := s.source.repository.Reauthentication(bounded, r.Proof.Proof.ID)
	if err != nil || record.Proof != r.Proof || record.Issuer != s.source.c.Issuer || record.Environment != s.source.c.Environment || record.CredentialID != bindings.Authentication.CredentialID || record.CredentialVersion != original.EffectiveCredentialVersion() {
		if err := bounded.Err(); err != nil {
			return MFAEnableAdmission{}, err
		}
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	// Validate complete native session profile now, without inferring support
	// from a successful bearer lookup. The same expected owners are fenced later.
	if _, _, _, err = sessionpg.OriginalSessionAdmission(s.source.c.Profile, original, b); err != nil {
		return MFAEnableAdmission{}, identity.ForbiddenError{}
	}
	custody := mfaEnablePrimaryCustody{source: s, request: r, original: original, record: record, use: use}
	if err = custody.checkTime(s.source.c.Verifier.Now()); err != nil {
		return MFAEnableAdmission{}, err
	}
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		return MFAEnableAdmission{}, err
	}
	payload, err := encodeReauthenticationRecord(record)
	if err != nil {
		return MFAEnableAdmission{}, err
	}
	digest := sha256.Sum256(payload)
	clear(payload)
	fields = append(fields, identity.FeatureField{Name: "mfa.primary.proof.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(digest[:])}})
	custody.fields = fields
	if err = attachMFAEnableCSRF(&custody); err != nil {
		return MFAEnableAdmission{}, err
	}
	custody.request.Caller = r.Caller.Clone()
	if err := bounded.Err(); err != nil {
		return MFAEnableAdmission{}, err
	}
	return MFAEnableAdmission{custody: func() mfaEnablePrimaryCustody { return custody }}, nil
}

func (s mfaEnablePrimaryCustody) checkTime(now time.Time) error {
	use := s.use
	use.ProofUse.Now = now
	if s.record.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	lifetime, err := s.original.Lifetime(now)
	bindings, bindingErr := s.original.Bindings()
	if err != nil || bindingErr != nil || !lifetime.Fresh || !now.Before(bindings.Authentication.Proof.IssuedAt.Add(s.source.config.PrimaryFreshFor)) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Command freezes original session fields, proof digest and borrowed bearer
// with additional factor/policy fields. Scope must match this exact prepared
// command, account and factor. Proof bodies and bearer never enter safe scalar
// fields. No signature is validated, consumer marker written or freshness renewed.
func (a MFAEnableAdmission) Command(b identity.CommandBinding, additional []identity.FeatureField) (identity.Command, error) {
	if a.custody == nil {
		return identity.Command{}, password.ErrPasswordWork
	}
	s := a.custody()
	bindings, err := s.original.Bindings()
	op := s.operation()
	if err != nil || b.CommandID != s.request.CommandID || b.TenantID != s.request.TenantID || b.UserID != bindings.UserID || b.ActorID != identity.ActorID(bindings.UserID) || b.ActorKind != authorization.SubjectUser || b.RecordID != s.request.FactorID || b.OperationID != op.OperationID || b.SchemaID != op.SchemaID || b.SchemaVersion != op.SchemaVersion {
		return identity.Command{}, identity.ForbiddenError{}
	}
	fields := append(append([]identity.FeatureField(nil), s.fields...), additional...)
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, s.request.Session)
}

func (a MFAEnableAdmission) scope(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) (mfaEnablePrimaryCustody, identity.CommandBinding, error) {
	if ctx == nil || a.custody == nil {
		return mfaEnablePrimaryCustody{}, identity.CommandBinding{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return mfaEnablePrimaryCustody{}, identity.CommandBinding{}, err
	}
	s := a.custody()
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation != s.operation() || !s.lifecycle(life.EventType, life.BeforeVersion, life.AfterVersion) {
		return mfaEnablePrimaryCustody{}, identity.CommandBinding{}, password.ErrPasswordWork
	}
	got, ok := c.Feature()
	token, has := c.SessionToken()
	if !ok || !has || token.Token() != s.request.Session.Token() || got.Binding != b || len(got.Fields) < len(s.fields) {
		return mfaEnablePrimaryCustody{}, identity.CommandBinding{}, identity.ForbiddenError{}
	}
	// Root owns field ordering. Match by exact name/value rather than assuming
	// an append order survives canonical command construction.
	for _, expected := range s.fields {
		found := false
		for _, field := range got.Fields {
			if field.Name == expected.Name && reflect.DeepEqual(field.Value, expected.Value) {
				found = true
				break
			}
		}
		if !found {
			return mfaEnablePrimaryCustody{}, identity.CommandBinding{}, identity.ForbiddenError{}
		}
	}
	if _, err := a.Command(b, nil); err != nil {
		return mfaEnablePrimaryCustody{}, identity.CommandBinding{}, err
	}
	return s, b, nil
}

// Check rechecks original proof and primary freshness against database time
// during the exact enrollment Apply. Call after every potentially waiting
// effect and before commit. It does not fence current authorities by itself;
// Consume performs those retained primary checks before the protected mutation.
func (a MFAEnableAdmission) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	s, _, err := a.scope(ctx, w, owner, c)
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return s.checkTime(now)
}

// Consume fences current directory, credential, authorization, exact source
// session and active family, then consumes the existing password-owned proof
// record once in the same Work as pending enrollment. Expiry is checked again
// after the exclusive proof lock. Return every error to the coordinator; no
// private transaction, retry, proof renewal or replacement marker is created.
// Browser composition must independently fence exact CSRF state before this.
func (a MFAEnableAdmission) Consume(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if a.custody == nil || a.custody().uri != nil {
		return identity.ForbiddenError{}
	}
	// Consumption is Apply-only. The non-consuming time check additionally runs
	// in the coordinator's registered final-commit callback, where Apply custody
	// has deliberately ended but FeatureScope still identifies the participant.
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	if err := a.Admit(ctx, w, owner, c); err != nil {
		return err
	}
	s, b, err := a.scope(ctx, w, owner, c)
	if err != nil {
		return err
	}
	check := func(ctx context.Context, w kernel.Work) error {
		now, err := w.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		return s.checkTime(now)
	}
	return consumeReauthenticationRecord(ctx, w, b, s.record, check)
}

// Admit fences current original primary owners during the exact enrollment
// preparation or Apply invocation without consuming a proof or changing state.
// These locks belong to the borrowed Work and do not survive generation;
// Consume repeats admission inside the final protected mutation. No callback,
// network operation, clock renewal or standalone transaction is introduced.
func (a MFAEnableAdmission) Admit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	s, b, err := a.scope(ctx, w, owner, c)
	if err != nil {
		return err
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(s.source.source.c.Profile, s.original, b)
	if err != nil {
		return identity.ForbiddenError{}
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err = w.RequireActiveCredential(ctx, owner, credential); err != nil {
		return err
	}
	if err = w.RequireActiveUserAuthorization(ctx, owner, policy); err != nil {
		return err
	}
	if err = sessionpg.RequireSession(ctx, w, s.source.source.c.Session, s.original); err != nil {
		return err
	}
	if s.csrf != nil {
		if err = sessionpg.RequireCSRF(ctx, w, s.source.source.c.Session, s.original, s.csrf.token, s.csrf.key); err != nil {
			return err
		}
	}
	if s.uri != nil {
		if err = s.admitURI(ctx, w, b); err != nil {
			return err
		}
	}
	return a.Check(ctx, w, owner, c)
}

// Deadline is the earliest original reauthentication, primary freshness,
// session absolute/idle and session freshness boundary. It is computed without
// a clock or IO and cannot be renewed by lookup, activity or copying. A native
// workflow must bound generation/commit to it and independently check database
// time after waits. Zero or malformed original custody returns no deadline.
func (a MFAEnableAdmission) Deadline() (time.Time, error) {
	if a.custody == nil {
		return time.Time{}, password.ErrPasswordWork
	}
	s := a.custody()
	if s.source == nil || s.source.source == nil {
		return time.Time{}, password.ErrPasswordWork
	}
	b, err := s.original.Bindings()
	if err != nil {
		return time.Time{}, err
	}
	policy, err := b.Remember.Bindings()
	if err != nil {
		return time.Time{}, err
	}
	until := s.record.Proof.Proof.ExpiresAt
	for _, bound := range []time.Time{s.record.Proof.Proof.IssuedAt.Add(s.source.config.MaximumAge), b.Authentication.Proof.IssuedAt.Add(s.source.config.PrimaryFreshFor), b.Authentication.Proof.IssuedAt.Add(policy.FreshFor), b.IssuedAt.Add(policy.AbsoluteTTL), b.LastActivityAt.Add(policy.IdleTTL)} {
		if bound.IsZero() || bound.Year() < 1 || bound.Year() > 9999 {
			return time.Time{}, password.ErrPasswordWork
		}
		if bound.Before(until) {
			until = bound
		}
	}
	return until, nil
}

// Recover reconciles only the immutable consumer marker for this original
// enrollment command. It returns no proof, secret, session or current authority.
// The enrollment participant must combine it with factor and lifecycle recovery;
// a marker alone cannot certify the complete protected workflow.
func (a MFAEnableAdmission) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || a.custody == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	s := a.custody()
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation != mfaEnableOperation() || life.EventType != "factor.enrollment-created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if _, err = a.Command(b, nil); err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	rows, err := w.Query(ctx, `SELECT proof_id,user_id,CASE WHEN octet_length(record)<=$4 THEN record ELSE ''::bytea END FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND consumed_purpose=$2 AND consumed_command_id=$3`, string(b.TenantID), b.OperationID, id, maximumReauthenticationRecordBytes)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var proofID, user string
	var payload []byte
	if rows.Scan(&proofID, &user, &payload) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	record, err := decodeReauthenticationRecord(auth.ProofID(proofID), string(b.TenantID), string(b.UserID), payload)
	want, wantErr := encodeReauthenticationRecord(s.record)
	defer clear(want)
	if err != nil || wantErr != nil || user != string(b.UserID) || record.Proof != s.record.Proof || !slices.Equal(payload, want) {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	return kernel.RecoveryCommitted, nil
}

// Format redacts original bearer, proof and source configuration.
func (MFAEnablePrimaryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.MFAEnablePrimaryRequest(redacted)")
}

// MarshalJSON denies implicit credential export.
func (MFAEnablePrimaryRequest) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit credential export.
func (MFAEnablePrimaryRequest) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format redacts private runtime/source custody.
func (MFAEnablePrimarySource) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.MFAEnablePrimarySource(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (MFAEnablePrimarySource) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit runtime export.
func (MFAEnablePrimarySource) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format redacts original transactional admission custody.
func (MFAEnableAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.MFAEnableAdmission(redacted)")
}

// MarshalJSON denies implicit admission export.
func (MFAEnableAdmission) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit admission export.
func (MFAEnableAdmission) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
