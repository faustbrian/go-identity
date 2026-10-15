package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// EmailPrimaryConfig selects a startup-allowlisted email action and original
// signed-proof audience. MaximumAge is positive and at most five minutes.
// Transport must explicitly select bearer or cookie; cookie requires CSRF keys.
type EmailPrimaryConfig struct {
	Action, Audience string
	MaximumAge       time.Duration
	Transport        session.CredentialKind
	CSRFKeys         []session.CSRFKey
}

// EmailPrimaryRequest borrows the original signed password reauthentication
// and source credential for one stable command/address. Tenant and Caller are
// trusted authenticated composition. Neither IDs nor this request grant access.
type EmailPrimaryRequest struct {
	TenantID  identity.TenantID
	CommandID identity.CommandID
	AddressID identity.IdentifierID
	Session   auth.BearerCredential
	Proof     auth.ReauthenticationProof
	Caller    authorization.DecisionContext
	CSRFToken session.CSRFToken
}

// EmailPrimarySource supplies the password owner's email-management admission.
// It owns no transaction, store, retry, cache or goroutine.
type EmailPrimarySource struct {
	source    *ReauthenticationService
	config    EmailPrimaryConfig
	validator *auth.AuthorityAuthenticator
}

// EmailPrimaryAdmission is opaque original custody, not mutation permission.
// Zero denies. A native email participant must repeat admission and consume
// through the sole coordinator's protected Work before changing an address.
type EmailPrimaryAdmission struct{ custody func() emailPrimaryCustody }

type emailPrimaryCustody struct {
	source   *EmailPrimarySource
	request  EmailPrimaryRequest
	original session.Session
	record   auth.SignedReauthenticationRecord
	use      auth.ReauthenticationUse
	fields   []identity.FeatureField
	csrfKey  session.CSRFKey
}

// NewEmailPrimarySource validates composition without IO or proof issuance.
func NewEmailPrimarySource(source *ReauthenticationService, config EmailPrimaryConfig) (*EmailPrimarySource, error) {
	if source == nil || source.repository == nil || !source.repository.configuredWriter() || source.sessions == nil || source.c.Verifier.Now == nil || config.MaximumAge <= 0 || config.MaximumAge > 5*time.Minute || emailPrimaryOperation(config.Action).Owner == "" || !reauthenticationText(config.Audience, 256) {
		return nil, password.ErrPasswordWork
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: config.Action, Audience: config.Audience}
	if !slices.Contains(source.c.Targets, target) {
		return nil, password.ErrPasswordWork
	}
	switch config.Transport {
	case session.CredentialCookie:
		if len(config.CSRFKeys) == 0 || len(config.CSRFKeys) > 4 {
			return nil, password.ErrPasswordWork
		}
		for index, key := range config.CSRFKeys {
			if key.Version() == 0 {
				return nil, password.ErrPasswordWork
			}
			for _, previous := range config.CSRFKeys[:index] {
				if key.Version() == previous.Version() {
					return nil, password.ErrPasswordWork
				}
			}
		}
	case session.CredentialBearer:
		if len(config.CSRFKeys) != 0 {
			return nil, password.ErrPasswordWork
		}
	default:
		return nil, password.ErrPasswordWork
	}
	config.CSRFKeys = slices.Clone(config.CSRFKeys)
	keys := make([]auth.AuthorityKey, 0, len(source.c.VerificationKeys))
	for id, key := range source.c.VerificationKeys {
		keys = append(keys, auth.AuthorityKey{ID: id, PublicKey: key})
	}
	validator, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: source.c.Issuer, Environment: source.c.Environment, Audience: config.Audience, Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: keys, EvidenceKeys: keys, Source: passwordProofSource{source.repository}, Clock: passwordProofClock{source.c.Verifier.Now}, ReadTimeout: min(source.c.Repository.MaximumDuration, 5*time.Second), ClockUncertainty: time.Millisecond, MaximumDelegationDepth: 1})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return &EmailPrimarySource{source: source, config: config, validator: validator}, nil
}

// Prepare authenticates original bearer and signed action/session-bound proof.
// It performs no mutation, proof consumption or freshness renewal.
func (s *EmailPrimarySource) Prepare(ctx context.Context, request EmailPrimaryRequest) (out EmailPrimaryAdmission, err error) {
	defer func() {
		if recover() != nil {
			out, err = EmailPrimaryAdmission{}, password.ErrPasswordWork
		}
	}()
	if ctx == nil || s == nil || s.source == nil || s.validator == nil {
		return out, password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, s.source.c.Repository.MaximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return out, err
	}
	if _, err := identity.ParseCommandID(string(request.CommandID)); err != nil {
		return out, identity.ForbiddenError{}
	}
	if _, err := identity.ParseIdentifierID(string(request.AddressID)); err != nil {
		return out, identity.ForbiddenError{}
	}
	if !validEmailPrimaryCaller(request.Caller) {
		return out, identity.ForbiddenError{}
	}
	if s.config.Transport == session.CredentialCookie && request.CSRFToken == (session.CSRFToken{}) || s.config.Transport == session.CredentialBearer && request.CSRFToken != (session.CSRFToken{}) {
		return out, identity.ForbiddenError{}
	}
	original, err := s.source.lookup(bounded, request.TenantID, request.Session)
	if err != nil {
		return out, err
	}
	bindings, err := original.Bindings()
	if err != nil {
		return out, password.ErrPasswordWork
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: s.config.Action, Audience: s.config.Audience}
	binding := identity.CommandBinding{CommandID: request.CommandID, TenantID: request.TenantID, UserID: bindings.UserID, ActorID: identity.ActorID(bindings.UserID), ActorKind: authorization.SubjectUser, RecordID: string(request.AddressID), OperationID: target.Action}
	if err := s.source.authorize(bounded, request.Caller, binding, target); err != nil {
		return out, err
	}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(request.TenantID), Subject: string(bindings.UserID), Purpose: target.Purpose, Audience: target.Audience}, SessionID: bindings.SessionID, SessionVersion: bindings.Version, Action: target.Action, MaximumAge: s.config.MaximumAge}
	if s.validator.ValidateReauthenticationProof(bounded, request.Proof, use) != nil {
		if err := bounded.Err(); err != nil {
			return out, err
		}
		return out, identity.ForbiddenError{}
	}
	record, err := s.source.repository.Reauthentication(bounded, request.Proof.Proof.ID)
	if err != nil || record.Proof != request.Proof || record.Issuer != s.source.c.Issuer || record.Environment != s.source.c.Environment || record.CredentialID != bindings.Authentication.CredentialID || record.CredentialVersion != original.EffectiveCredentialVersion() {
		if err := bounded.Err(); err != nil {
			return out, err
		}
		return out, identity.ForbiddenError{}
	}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.source.c.Profile, original, binding); err != nil {
		return out, identity.ForbiddenError{}
	}
	state := emailPrimaryCustody{source: s, request: request, original: original, record: record, use: use}
	if err := state.checkTime(s.source.c.Verifier.Now()); err != nil {
		return out, err
	}
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		return out, err
	}
	payload, err := encodeReauthenticationRecord(record)
	if err != nil {
		return out, err
	}
	digest := sha256.Sum256(payload)
	clear(payload)
	state.fields = append(fields,
		identity.FeatureField{Name: "email.primary.proof.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(digest[:])}},
		identity.FeatureField{Name: "email.primary.proof.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(record.Proof.Proof.ID)}},
		identity.FeatureField{Name: "email.primary.maximum-age-nanos", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(s.config.MaximumAge)}},
		identity.FeatureField{Name: "email.primary.cookie", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: s.config.Transport == session.CredentialCookie}},
	)
	if s.config.Transport == session.CredentialCookie {
		csrf, err := original.CSRFState().Bindings()
		if err != nil {
			return out, identity.ForbiddenError{}
		}
		for _, key := range s.config.CSRFKeys {
			if key.Version() == csrf.KeyVersion {
				state.csrfKey = key
				break
			}
		}
		if state.csrfKey.Version() == 0 || original.CSRFState().Check(session.CSRFBinding{TenantID: bindings.TenantID, SessionID: bindings.SessionID, SessionVersion: bindings.Version}, request.CSRFToken, state.csrfKey) != nil {
			return out, identity.ForbiddenError{}
		}
	}
	state.request.Caller = request.Caller.Clone()
	if err := bounded.Err(); err != nil {
		return out, err
	}
	return EmailPrimaryAdmission{custody: func() emailPrimaryCustody { return state }}, nil
}

// Original returns the retained immutable source session, not fresh authority.
func (a EmailPrimaryAdmission) Original() (session.Session, error) {
	if a.custody == nil {
		return session.Session{}, password.ErrPasswordWork
	}
	return a.custody().original, nil
}

// Deadline is the earliest original proof-age, proof-expiry and session limit.
// Copying, preparing again or reading the clock cannot extend this deadline.
func (a EmailPrimaryAdmission) Deadline() (time.Time, error) {
	if a.custody == nil {
		return time.Time{}, password.ErrPasswordWork
	}
	state := a.custody()
	bindings, err := state.original.Bindings()
	if err != nil {
		return time.Time{}, password.ErrPasswordWork
	}
	policy, err := bindings.Remember.Bindings()
	if err != nil {
		return time.Time{}, password.ErrPasswordWork
	}
	until := state.record.Proof.Proof.ExpiresAt
	for _, bound := range []time.Time{state.record.Proof.Proof.IssuedAt.Add(state.source.config.MaximumAge), bindings.IssuedAt.Add(policy.AbsoluteTTL), bindings.LastActivityAt.Add(policy.IdleTTL)} {
		if bound.IsZero() || bound.Year() < 1 || bound.Year() > 9999 {
			return time.Time{}, password.ErrPasswordWork
		}
		if bound.Before(until) {
			until = bound
		}
	}
	return until, nil
}

func emailPrimaryOperation(action string) identity.FeatureOperation {
	switch action {
	case "identity.email.verification-send", "identity.email.change-request", "identity.email.address-remove":
		return identity.FeatureOperation{Owner: "identity/email", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	default:
		return identity.FeatureOperation{}
	}
}

func (s emailPrimaryCustody) checkTime(now time.Time) error {
	use := s.use
	use.ProofUse.Now = now
	if s.record.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	if _, err := s.original.Lifetime(now); err != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Command binds original session/proof custody to one exact email command and
// native schema. Additional domain fields cannot replace protected names.
// It neither consumes, authorizes, normalizes nor grants transaction ownership.
func (a EmailPrimaryAdmission) Command(binding identity.CommandBinding, additional []identity.FeatureField) (identity.Command, error) {
	return a.command(binding, additional, false)
}

func (a EmailPrimaryAdmission) command(binding identity.CommandBinding, additional []identity.FeatureField, resend bool) (identity.Command, error) {
	if a.custody == nil {
		return identity.Command{}, password.ErrPasswordWork
	}
	state := a.custody()
	original, err := state.original.Bindings()
	op := emailPrimaryOperation(state.source.config.Action)
	if resend {
		if state.source.config.Action != "identity.email.verification-send" {
			return identity.Command{}, identity.ForbiddenError{}
		}
		op = managedResendOperation()
	}
	if err != nil || binding.CommandID != state.request.CommandID || binding.TenantID != state.request.TenantID || binding.UserID != original.UserID || binding.ActorID != identity.ActorID(original.UserID) || binding.ActorKind != authorization.SubjectUser || binding.RecordID != string(state.request.AddressID) || binding.OperationID != op.OperationID || binding.SchemaID != op.SchemaID || binding.SchemaVersion != op.SchemaVersion {
		return identity.Command{}, identity.ForbiddenError{}
	}
	if len(state.fields) > 128 || len(additional) > 128-len(state.fields) {
		return identity.Command{}, password.ErrPasswordWork
	}
	fields := append(append([]identity.FeatureField(nil), state.fields...), additional...)
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, state.request.Session)
}

func (a EmailPrimaryAdmission) scope(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (emailPrimaryCustody, identity.CommandBinding, error) {
	if ctx == nil || a.custody == nil {
		return emailPrimaryCustody{}, identity.CommandBinding{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return emailPrimaryCustody{}, identity.CommandBinding{}, err
	}
	state := a.custody()
	binding, feature, _, err := work.FeatureScope(owner)
	resend := state.source.config.Action == "identity.email.verification-send" && feature.Operation == managedResendOperation()
	if err != nil || feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || !resend && feature.Operation != emailPrimaryOperation(state.source.config.Action) {
		return emailPrimaryCustody{}, identity.CommandBinding{}, identity.ForbiddenError{}
	}
	spec, ok := command.Feature()
	token, has := command.SessionToken()
	if !ok || !has || spec.Binding != binding || token.Token() != state.request.Session.Token() || len(spec.Fields) < len(state.fields) {
		return emailPrimaryCustody{}, identity.CommandBinding{}, identity.ForbiddenError{}
	}
	for _, expected := range state.fields {
		found := false
		for _, actual := range spec.Fields {
			if actual.Name == expected.Name && reflect.DeepEqual(actual.Value, expected.Value) {
				found = true
				break
			}
		}
		if !found {
			return emailPrimaryCustody{}, identity.CommandBinding{}, identity.ForbiddenError{}
		}
	}
	if _, err := a.command(binding, nil, resend); err != nil {
		return emailPrimaryCustody{}, identity.CommandBinding{}, err
	}
	return state, binding, nil
}

// Check rechecks original proof age/expiry and session lifetime using database
// time during the exact native email invocation, including its final callback.
// It does not renew evidence or fence credential/factor/risk policy by itself.
func (a EmailPrimaryAdmission) Check(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	state, _, err := a.scope(ctx, work, owner, command)
	if err != nil {
		return err
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return state.checkTime(now)
}

// Admit fences current original directory, credential, user-authorization,
// session/family and selected synchronizer in the sole coordinator Work. It
// consumes nothing. The email owner additionally owns factor/risk/domain policy.
func (a EmailPrimaryAdmission) Admit(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	state, binding, err := a.scope(ctx, work, owner, command)
	if err != nil {
		return err
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(state.source.source.c.Profile, state.original, binding)
	if err != nil {
		return identity.ForbiddenError{}
	}
	if err := work.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := work.RequireActiveCredential(ctx, owner, credential); err != nil {
		return err
	}
	if err := work.RequireActiveUserAuthorization(ctx, owner, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, work, state.source.source.c.Session, state.original); err != nil {
		return err
	}
	if state.source.config.Transport == session.CredentialCookie {
		if err := sessionpg.RequireCSRF(ctx, work, state.source.source.c.Session, state.original, state.request.CSRFToken, state.csrfKey); err != nil {
			return err
		}
	}
	return a.Check(ctx, work, owner, command)
}

// Consume is Apply-only and atomically consumes the existing password-owned
// original proof record in the same Work as the email mutation. It repeats
// primary admission and checks original expiry after the exclusive proof lock.
// The owner must propagate every error and run Check in its final callback.
func (a EmailPrimaryAdmission) Consume(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if err := work.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := a.Admit(ctx, work, owner, command); err != nil {
		return err
	}
	state, binding, err := a.scope(ctx, work, owner, command)
	if err != nil {
		return err
	}
	return consumeReauthenticationRecord(ctx, work, binding, state.record, func(ctx context.Context, work kernel.Work) error {
		now, err := work.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		return state.checkTime(now)
	})
}

func validEmailPrimaryCaller(c authorization.DecisionContext) bool {
	request := c.Request
	if len(request.Subject.Groups) > 64 {
		return false
	}
	for _, group := range request.Subject.Groups {
		if !reauthenticationText(string(group), 128) {
			return false
		}
	}
	for _, attributes := range []authorization.Attributes{request.Attributes, request.Subject.Attributes, request.Resource.Attributes, request.Environment.Attributes} {
		if len(attributes) > 64 {
			return false
		}
		for name, value := range attributes {
			if !reauthenticationText(string(name), 128) || value.Kind() == authorization.ValueMissing {
				return false
			}
			if text, ok := value.String(); ok && (len(text) > 4096 || !utf8.ValidString(text)) {
				return false
			}
			if count, ok := value.CollectionLength(); ok {
				if count > 64 {
					return false
				}
				items, _ := value.StringSet()
				for _, item := range items {
					if len(item) > 4096 || !utf8.ValidString(item) {
						return false
					}
				}
			}
		}
	}
	return len(c.CorrelationID) <= 128 && utf8.ValidString(c.CorrelationID)
}

// Format redacts original bearer, proof and caller metadata.
func (EmailPrimaryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.EmailPrimaryRequest(redacted)")
}

// MarshalJSON refuses implicit sensitive request export.
func (EmailPrimaryRequest) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText refuses implicit text and map-key export.
func (EmailPrimaryRequest) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// Format prevents diagnostic traversal of original custody.
func (EmailPrimaryAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.EmailPrimaryAdmission(redacted)")
}

// MarshalJSON refuses implicit custody export.
func (EmailPrimaryAdmission) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText refuses implicit text and map-key export.
func (EmailPrimaryAdmission) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// Format redacts borrowed source and startup policy.
func (EmailPrimarySource) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.EmailPrimarySource(redacted)")
}

// MarshalJSON refuses implicit native source export.
func (EmailPrimarySource) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText refuses implicit text and map-key export.
func (EmailPrimarySource) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
