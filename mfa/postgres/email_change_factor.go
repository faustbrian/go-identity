package mfapostgres

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// EmailChangeFactorSource borrows the explicitly selected active-TOTP issuer's
// original evidence and signing trust. It owns no transaction, store, retry or
// goroutine. Prepare authenticates original evidence; the registered email
// participant must fence current authority and consume it in protected Work.
type EmailChangeFactorSource struct {
	stepup    *activeStepUpState
	source    *FactorVerificationSource
	validator *auth.AuthorityAuthenticator
}

// EmailChangeFactorAdmission retains authenticated original factor custody,
// not permission to mutate an email. Zero denies. Copies cannot renew proof
// age, change its factor/session/action, or bypass protected consumption.
type EmailChangeFactorAdmission struct {
	custody func() emailChangeFactorCustody
}

type emailChangeFactorCustody struct {
	record        factorVerificationRecord
	use           auth.ReauthenticationUse
	sessionFactor session.MFAAuthentication
}

func emailChangeSessionFactor(original session.Session, use auth.ReauthenticationUse) (session.MFAAuthentication, error) {
	b, err := original.Bindings()
	if err != nil || string(b.TenantID) != use.ProofUse.Tenant || string(b.UserID) != use.ProofUse.Subject || b.SessionID != use.SessionID || b.Version != use.SessionVersion || b.Authentication.Kind != session.AuthenticationVerified {
		return session.MFAAuthentication{}, identity.ForbiddenError{}
	}
	factor := original.MFAAuthentication()
	if factor != (session.MFAAuthentication{}) {
		m, err := factor.Bindings()
		if err != nil || m.Method != "totp" && m.Method != "recovery-code" {
			return session.MFAAuthentication{}, identity.ForbiddenError{}
		}
	}
	return factor, nil
}

// NewEmailChangeFactorSource selects only identity.email.change-request from
// an issuer configured with EmailChange. Construction is IO-free. The caller
// retains pool/issuer lifetime; authentication owns the existing signed frame.
// Its authority authenticator accepts at most32 retained keys (authentication's
// copyAuthorityKeys bound); a larger issuer ring cannot select this consumer.
func NewEmailChangeFactorSource(stepup *TOTPActiveStepUpService) (*EmailChangeFactorSource, error) {
	if stepup == nil || stepup.state == nil {
		return nil, invalidAuthority()
	}
	state := stepup.state()
	if state == nil || !state.config.EmailChange || state.shared == nil || len(state.config.VerificationKeys) > 32 {
		return nil, invalidAuthority()
	}
	source, err := NewFactorVerificationSource(state.shared.pool, min(state.shared.config.MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	keys := make([]auth.AuthorityKey, 0, len(state.config.VerificationKeys))
	for id, key := range state.config.VerificationKeys {
		keys = append(keys, auth.AuthorityKey{ID: id, PublicKey: key})
	}
	validator, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{
		Issuer: state.config.Issuer, Environment: state.config.Environment, Audience: state.config.Audience,
		Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: keys, EvidenceKeys: keys,
		Source: factorReauthenticationOnlySource{source}, Clock: state.shared.config.Coordinator.QueryPolicy.Clock,
		ReadTimeout: min(state.shared.config.MaximumDuration, 5*time.Second), ClockUncertainty: time.Millisecond, MaximumDelegationDepth: 1,
	})
	if err != nil {
		return nil, invalidAuthority()
	}
	return &EmailChangeFactorSource{stepup: state, source: source, validator: validator}, nil
}

// Prepare authenticates a committed original TOTP proof for the exact email
// action/session/audience and bounded MaximumAge. It neither consumes nor
// infers current factor or session authority. Original must be the separately
// authenticated session frozen by the consumer. Its own factor provenance is
// retained even when the fresh step-up used a different enrolled factor. IO
// observes the issuer's bounded read budget and earlier cancellation. Invalid
// or unavailable evidence denies.
func (s *EmailChangeFactorSource) Prepare(ctx context.Context, proof auth.ReauthenticationProof, use auth.ReauthenticationUse, original session.Session) (EmailChangeFactorAdmission, error) {
	if ctx == nil || s == nil || s.stepup == nil || s.source == nil || s.validator == nil {
		return EmailChangeFactorAdmission{}, invalidAuthority()
	}
	if use.ProofUse.Purpose != "identity.email.change-request" || use.Action != string(use.ProofUse.Purpose) || use.ProofUse.Audience != s.stepup.config.Audience || use.MaximumAge <= 0 || use.MaximumAge > 5*time.Minute || proof.Proof.Method != "totp" || proof.Proof.Assurance != auth.AssuranceMultiFactor {
		return EmailChangeFactorAdmission{}, identity.ForbiddenError{}
	}
	sessionFactor, err := emailChangeSessionFactor(original, use)
	if err != nil {
		return EmailChangeFactorAdmission{}, err
	}
	ctx, stop := context.WithTimeout(ctx, s.source.maximumDuration)
	defer stop()
	if err := s.validator.ValidateReauthenticationProof(ctx, proof, use); err != nil {
		if ctx.Err() != nil {
			return EmailChangeFactorAdmission{}, ctx.Err()
		}
		return EmailChangeFactorAdmission{}, identity.ForbiddenError{}
	}
	r, err := s.source.readRecord(ctx, proof.Proof.ID)
	if err != nil {
		return EmailChangeFactorAdmission{}, err
	}
	if r.Original.Proof != proof || r.Original.Issuer != s.stepup.config.Issuer || r.Original.Environment != s.stepup.config.Environment {
		return EmailChangeFactorAdmission{}, identity.ForbiddenError{}
	}
	state := emailChangeFactorCustody{record: r, use: use, sessionFactor: sessionFactor}
	return EmailChangeFactorAdmission{custody: func() emailChangeFactorCustody { return state }}, nil
}

// Restore authenticates the same original proof and exact digest retained by
// the email owner's encrypted committed request. Historical lookup never
// renews expiry or waives current-authority/consumption checks. The caller must
// obtain id/digest/use and original session from authenticated origin custody,
// never request fields. The original session's factor is retained separately
// from the action proof's factor; neither is replaced by current metadata.
func (s *EmailChangeFactorSource) Restore(ctx context.Context, id auth.ProofID, digest [32]byte, use auth.ReauthenticationUse, original session.Session) (EmailChangeFactorAdmission, error) {
	if ctx == nil || s == nil || s.source == nil || s.stepup == nil {
		return EmailChangeFactorAdmission{}, invalidAuthority()
	}
	sessionFactor, err := emailChangeSessionFactor(original, use)
	if err != nil {
		return EmailChangeFactorAdmission{}, err
	}
	r, err := s.source.readRecord(ctx, id)
	if err != nil {
		return EmailChangeFactorAdmission{}, err
	}
	// The email goal's keyed retry/recovery retains original evidence after
	// expiry. Authenticate its existing signed frame, not present-day validity;
	// CheckAuthority independently enforces the original deadline before use.
	frame, err := r.Original.SigningBytes()
	defer clear(frame)
	originalUse := use
	originalUse.ProofUse.Now = r.Original.Proof.Proof.IssuedAt
	key := s.stepup.config.VerificationKeys[r.Original.KeyID]
	if err != nil || use.ProofUse.Purpose != "identity.email.change-request" || use.Action != string(use.ProofUse.Purpose) || use.ProofUse.Audience != s.stepup.config.Audience || use.MaximumAge <= 0 || use.MaximumAge > 5*time.Minute || r.Original.Issuer != s.stepup.config.Issuer || r.Original.Environment != s.stepup.config.Environment || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, r.Original.Signature) || r.Original.Proof.Validate(originalUse) != nil {
		return EmailChangeFactorAdmission{}, identity.ForbiddenError{}
	}
	state := emailChangeFactorCustody{record: r, use: use, sessionFactor: sessionFactor}
	a := EmailChangeFactorAdmission{custody: func() emailChangeFactorCustody { return state }}
	got, err := a.Digest()
	if err != nil || got != digest {
		return EmailChangeFactorAdmission{}, identity.ForbiddenError{}
	}
	return a, nil
}

// Original returns a copy of signed original evidence, not current authority.
func (a EmailChangeFactorAdmission) Original() (auth.SignedReauthenticationRecord, error) {
	if a.custody == nil {
		return auth.SignedReauthenticationRecord{}, invalidAuthority()
	}
	r := a.custody().record.Original
	r.Signature = slices.Clone(r.Signature)
	return r, nil
}

// Digest binds original signed evidence and its immutable factor generation.
// It is provenance metadata, never a substitute for signature validation.
func (a EmailChangeFactorAdmission) Digest() ([32]byte, error) {
	if a.custody == nil {
		return [32]byte{}, invalidAuthority()
	}
	wire, err := encodeFactorVerificationRecord(a.custody().record)
	defer clear(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(wire), nil
}

// AuthorityVersion is the original observed account-wide factor generation.
func (a EmailChangeFactorAdmission) AuthorityVersion() (uint64, error) {
	if a.custody == nil {
		return 0, invalidAuthority()
	}
	return a.custody().record.FactorAuthorityVersion, nil
}

func (a EmailChangeFactorAdmission) scope(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (emailChangeFactorCustody, identity.CommandBinding, error) {
	if ctx == nil || a.custody == nil || owner == nil {
		return emailChangeFactorCustody{}, identity.CommandBinding{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return emailChangeFactorCustody{}, identity.CommandBinding{}, err
	}
	spec, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	request := f.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-request", SchemaID: "identity.email.change-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired})
	confirm := f.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-confirm", SchemaID: "identity.email.change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired})
	state := a.custody()
	proof := state.record.Original.Proof
	if err != nil || !ok || spec.Binding != b || spec.Operation != f.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || !request && !confirm || proof.Proof.Tenant != string(b.TenantID) || proof.Proof.Subject != string(b.UserID) || request && (b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID)) {
		return emailChangeFactorCustody{}, identity.CommandBinding{}, identity.ForbiddenError{}
	}
	return state, b, nil
}

// CheckAuthority locks the original confirmed enrollment and exact factor
// generation, and rechecks original proof validity with authoritative database
// time. Only the registered self-user change-request or change-confirm Work
// can call it. It grants no primary-session, directory or email authority.
func (a EmailChangeFactorAdmission) CheckAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	state, b, err := a.scope(ctx, w, owner, command)
	if err != nil {
		return err
	}
	r := state.record
	if err := requireTOTPSessionFactor(ctx, w, b, b.UserID, r.Original.CredentialID, TOTPSessionFactorState{EnrollmentVersion: r.Original.CredentialVersion, AuthorityVersion: r.FactorAuthorityVersion}); err != nil {
		return err
	}
	if state.sessionFactor != (session.MFAAuthentication{}) {
		m, err := state.sessionFactor.Bindings()
		if err != nil {
			return identity.ForbiddenError{}
		}
		if err := requireTOTPSessionFactor(ctx, w, b, b.UserID, m.FactorID, TOTPSessionFactorState{EnrollmentVersion: m.EnrollmentVersion, AuthorityVersion: m.FactorAuthorityVersion}); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	use := state.use
	use.ProofUse.Now = now
	if r.Original.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Admit additionally locks the unused original proof for request preparation
// or Apply. The coordinator retains its locks until commit/rollback. It never
// consumes during discovery, signature validation or source restoration.
func (a EmailChangeFactorAdmission) Admit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if err := a.CheckAuthority(ctx, w, owner, command); err != nil {
		return err
	}
	state, b, err := a.scope(ctx, w, owner, command)
	if err != nil || b.OperationID != "identity.email.change-request" {
		return identity.ForbiddenError{}
	}
	return lockFactorVerificationUse(ctx, w, state.record, b, false)
}

// Consume marks the original evidence once, atomically with the email owner's
// pending attachment, link/delivery, audit and lifecycle. Apply-only; propagate
// any error to abort. The final callback must also call CheckConsumed.
func (a EmailChangeFactorAdmission) Consume(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := a.Admit(ctx, w, owner, command); err != nil {
		return err
	}
	state, b, err := a.scope(ctx, w, owner, command)
	if err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return invalidAuthority()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity_mfa.factor_verifications SET used_command_id=$4,used_purpose=$5,used_at=$6 WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3 AND used_command_id IS NULL AND used_purpose IS NULL AND used_at IS NULL`, string(b.TenantID), string(b.UserID), string(state.record.Original.Proof.Proof.ID), id, b.OperationID, now)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return a.CheckConsumed(ctx, w, owner, command, b.CommandID)
}

// CheckConsumed requires original consumption by the authenticated originating
// change-request command, plus current unchanged factor authority and original
// validity. Confirmation does not reconsume or accept an unused proof. The
// caller obtains origin from authenticated retained email intent, not the wire.
func (a EmailChangeFactorAdmission) CheckConsumed(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, origin identity.CommandID) error {
	if err := a.CheckAuthority(ctx, w, owner, command); err != nil {
		return err
	}
	state, b, err := a.scope(ctx, w, owner, command)
	if err != nil {
		return err
	}
	if _, err := identity.ParseCommandID(string(origin)); err != nil || b.OperationID == "identity.email.change-request" && origin != b.CommandID {
		return identity.ForbiddenError{}
	}
	b.CommandID, b.OperationID = origin, "identity.email.change-request"
	return lockFactorVerificationUse(ctx, w, state.record, b, true)
}

// CheckCurrent performs scanner-safe original-consumption/current-factor
// discovery without a lock, debit or mutation. Explicit completion must repeat
// these checks inside Work. IO is bounded by the original source read budget;
// the proof's original validity is checked at the end, never refreshed.
func (s *EmailChangeFactorSource) CheckCurrent(ctx context.Context, a EmailChangeFactorAdmission, origin identity.CommandID) error {
	if ctx == nil || s == nil || s.source == nil || a.custody == nil {
		return invalidAuthority()
	}
	if _, err := identity.ParseCommandID(string(origin)); err != nil {
		return identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, s.source.maximumDuration)
	defer stop()
	state := a.custody()
	r := state.record
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(origin))
	var sourceFactor session.MFAAuthenticationSpec
	if state.sessionFactor != (session.MFAAuthentication{}) {
		var err error
		sourceFactor, err = state.sessionFactor.Bindings()
		if err != nil {
			return identity.ForbiddenError{}
		}
	}
	var valid bool
	var now time.Time
	err := s.source.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp(),EXISTS(
 SELECT 1 FROM identity_mfa.factor_verifications v
 JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id)
 JOIN identity_mfa.totp_factors f ON f.tenant_id=v.tenant_id AND f.user_id=v.user_id AND f.factor_id=v.factor_id
 JOIN identity.commands j ON j.tenant_id=v.tenant_id AND j.purpose=v.used_purpose AND j.command_id=v.used_command_id
 JOIN identity.identity_command_id_claims c ON c.tenant_id=j.tenant_id AND c.purpose=j.purpose AND c.command_id=j.command_id
 WHERE v.proof_id=$1 AND v.tenant_id=$2 AND v.user_id=$3 AND v.factor_id=$4
 AND v.enrollment_version=$5::numeric AND f.enrollment_version=v.enrollment_version
 AND v.factor_authority_version=$6::numeric AND a.version=v.factor_authority_version AND a.active_factors BETWEEN 1 AND 64
 AND f.state=2 AND f.confirmed_at IS NOT NULL AND f.encrypted_secret IS NOT NULL
 AND v.used_command_id=$7 AND v.used_purpose='identity.email.change-request' AND j.state='committed' AND NOT c.retired
 AND ($8='' OR EXISTS(SELECT 1 FROM identity_mfa.totp_factors sf
   WHERE sf.tenant_id=v.tenant_id AND sf.user_id=v.user_id AND sf.factor_id=$8
   AND sf.enrollment_version=$9::numeric AND a.version=$10::numeric
   AND sf.state=2 AND sf.confirmed_at IS NOT NULL AND sf.encrypted_secret IS NOT NULL)))`,
		string(r.Original.Proof.Proof.ID), r.Original.Proof.Proof.Tenant, r.Original.Proof.Proof.Subject, r.Original.CredentialID,
		strconv.FormatUint(r.Original.CredentialVersion, 10), strconv.FormatUint(r.FactorAuthorityVersion, 10), id,
		sourceFactor.FactorID, strconv.FormatUint(sourceFactor.EnrollmentVersion, 10), strconv.FormatUint(sourceFactor.FactorAuthorityVersion, 10)).Scan(&now, &valid)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	use := state.use
	use.ProofUse.Now = now
	if !valid || r.Original.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// RecoverEmailChangeUse reads only durable consumption metadata for the exact
// registered email request. It grants no authority or replacement proof; the
// sole command journal resolves a committed/unknown result independently.
func RecoverEmailChangeUse(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || owner == nil {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || f.Operation != (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-request", SchemaID: "identity.email.change-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND used_command_id=$3 AND used_purpose='identity.email.change-request')`, string(b.TenantID), string(b.UserID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var used bool
	if !rows.Next() || rows.Scan(&used) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if used {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

// Format hides original correlated evidence and borrowed native owners.
func (EmailChangeFactorSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.EmailChangeFactorSource(redacted)"))
}

// MarshalJSON rejects implicit native-owner export.
func (EmailChangeFactorSource) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit native-owner export.
func (EmailChangeFactorSource) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format hides original factor evidence.
func (EmailChangeFactorAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.EmailChangeFactorAdmission(redacted)"))
}

// MarshalJSON rejects implicit original-evidence export.
func (EmailChangeFactorAdmission) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit original-evidence export.
func (EmailChangeFactorAdmission) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
