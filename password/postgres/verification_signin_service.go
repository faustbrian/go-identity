package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// VerificationSigninConfig explicitly selects email-possession signin after a
// committed registration-link confirmation. It is trusted startup input, never
// request policy. Issuance.Authority must be nil; Profile must select the same
// authorization namespace initialized by signup and its exact session audience.
// The signup service supplies bounded current authorization, counted/audited
// Authentication risk, retained browser keys and the sole primary pool. Only
// known-empty MFA is supported; enrolled/unknown accounts deny without fallback.
type VerificationSigninConfig struct {
	Profile  sessionpg.MagicLinkAdmissionConfig
	Issuance session.IssuerConfig
	CSRFKey  session.CSRFKey
}

// VerificationSigninService borrows the immutable native signup graph. Each
// invocation commits verification first, then independently coordinates at most
// one linked signin. Known verification success survives login denial/ambiguity.
// No password proof is reused or manufactured. Calls own ephemeral token custody,
// no goroutines, and no second journal; concurrent calls require independent
// inputs. Recover returns metadata only and cannot generate credentials.
type VerificationSigninService struct {
	signup *SignupService
	c      VerificationSigninConfig
	policy *authoritypg.AuthorityStore
	effect *sessionpg.EmailVerificationSigninEffect
}

var _ email.RegistrationVerificationSigninService = (*VerificationSigninService)(nil)

// NewVerificationSigninService validates selected native composition without IO
// or callbacks. Install the verification, email-grant session/CSRF, known-empty
// MFA authority and EmailVerificationSigninMigrationSource histories before use.
// Ordinary SignupService confirmation remains verification-only.
func NewVerificationSigninService(signup *SignupService, c VerificationSigninConfig) (*VerificationSigninService, error) {
	if signup == nil || signup.config == nil || signup.pool == nil || signup.directory == nil || signup.config().Verification.Counters == nil || signup.config().AuthorizationNamespace == "" || c.Profile.PolicyNamespace != signup.config().AuthorizationNamespace || c.Issuance.Authority != nil || c.Issuance.Clock == nil {
		return nil, email.ErrInvalidVerification
	}
	effect, err := sessionpg.NewEmailVerificationSigninEffect(signup.config().Session, c.Profile)
	if err != nil {
		return nil, email.ErrInvalidVerification
	}
	policy, err := authoritypg.NewAuthorityStore(signup.pool.Raw(), signup.config().Repository.MaximumDuration)
	if err != nil {
		return nil, email.ErrInvalidVerification
	}
	if _, err := session.NewEmailVerificationSessionIssuerWithCSRF(&verificationSigninPhase{}, c.Issuance, c.CSRFKey); err != nil {
		return nil, email.ErrInvalidVerification
	}
	return &VerificationSigninService{signup: signup, c: c, policy: policy, effect: effect}, nil
}

// VerificationConfirmAndSignin authenticates the original encrypted signup flow
// and browser before confirmation. Original resolved Remember and grant expiry
// are never replaced. Only this fresh, successful verification invocation can
// attempt the separate signin; scanner inspection, replay and recovery cannot.
// Current risk/account/address/authorization/factor fences apply to signin. Any
// error withholds bearer, cookie and CSRF while preserving known durable outcomes.
// The safe fallback after failed/unknown login is ordinary signin, not replay.
func (s *VerificationSigninService) VerificationConfirmAndSignin(ctx context.Context, r email.VerificationSigninRequest) (out email.VerificationSigninResult, err error) {
	if ctx == nil || s == nil || s.signup == nil || s.effect == nil || r.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	c := s.signup.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Issuance.Token, out.Issuance.Cookie, out.CSRFToken = session.Token{}, http.Cookie{}, session.CSRFToken{}
		}
	}()
	caller := r.Confirmation.Caller.Clone()
	grant, _, _, err := c.Verification.Issuer.ReadRegistrationOrigin(ctx, s.signup.pool, r.Confirmation.Token)
	if err != nil {
		return out, err
	}
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(grant.Payload().Subject)
	}
	spec, _, flow, err := s.signup.readRegistrationVerification(ctx, r.Confirmation.Token, caller)
	if err != nil {
		return out, err
	}
	if err := s.originalBrowser(r, spec, flow, s.c.Issuance.Clock.Now()); err != nil {
		return out, err
	}
	out.Verification, err = s.signup.VerificationConfirm(ctx, r.Confirmation)
	if err != nil || out.Verification.Outcome != identity.CommitOutcomeCommitted || out.Verification.Replayed {
		return out, err
	}
	vq, err := out.Verification.Recovery.Bindings()
	if err != nil {
		return out, identity.UnavailableError{}
	}
	confirmation, err := s.signup.RecoverRegistrationVerification(ctx, vq, caller)
	if err != nil || confirmation.Outcome != identity.CommitOutcomeCommitted {
		return out, identity.ForbiddenError{}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, identity.UnavailableError{}
	}
	op := verificationSigninOperation()
	b := identity.CommandBinding{CommandID: id, TenantID: vq.TenantID, UserID: vq.UserID, ActorID: vq.ActorID, ActorKind: vq.ActorKind, RecordID: string(vq.CommandID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(id)}
	out.Recovery = identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, RecordID: b.RecordID, OperationID: b.OperationID}
	// From here there is an attempted child identity, even if admission fails
	// before reservation. No durable receipt means Unknown, never invented rollback.
	out.Issuance = session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeUnknown}
	subjectMAC := hmac.New(sha256.New, c.IntentKey[:])
	subjectMAC.Write([]byte("identity-email-verification-signin-risk-v1\x00" + string(b.TenantID) + "\x00" + spec.Payload.CanonicalAddress.Record().Value))
	subject := risk.Subject{Network: r.Confirmation.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(subjectMAC.Sum(nil))}
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(id)}
	evaluated, err := c.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}})
	if err != nil {
		return out, identity.UnavailableError{}
	}
	admission, err := s.signup.custody.Prepare(ctx, evaluated, scope, subject)
	if err != nil {
		return out, err
	}
	recipient, err := s.signup.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: spec.Payload.CanonicalAddress.Record().Value, Eligibility: kernel.RecipientVerified})
	if err != nil || recipient.Suppressed || recipient.User.ID != b.UserID || recipient.Identifier.ID != spec.IdentifierID || recipient.Identifier.Version != confirmation.Feature.AfterVersion || recipient.Verification.Version != confirmation.Feature.AfterVersion {
		return out, identity.ForbiddenError{}
	}
	factor, err := mfapg.ReadEmailVerificationSigninFactors(ctx, s.signup.pool, b.TenantID, b.UserID, c.Repository.MaximumDuration)
	if err != nil {
		return out, err
	}
	now := s.c.Issuance.Clock.Now().UTC().Truncate(time.Microsecond)
	if err := s.originalBrowser(r, spec, flow, now); err != nil {
		return out, err
	}
	sessionID, err := identity.NewSubjectID()
	if err != nil {
		return out, identity.UnavailableError{}
	}
	familyID, err := identity.NewSubjectID()
	if err != nil {
		return out, identity.UnavailableError{}
	}
	authority, err := recipientSessionAuthority(ctx, s.signup.directory, s.policy, s.c.Profile.GlobalAuthorityID, s.c.Profile.PolicyNamespace, recipient, string(sessionID), string(familyID))
	if err != nil {
		return out, err
	}
	// Capture epochs before the policy callback. Its approval cannot borrow a
	// newer epoch read afterward; the session effect fences this exact vector.
	if err := s.authorize(ctx, r.Confirmation.Caller, b); err != nil {
		return out, err
	}
	metadata, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: id, RequestCommandID: spec.Binding.CommandID, CapabilityID: grant.Payload().ID, IdentifierID: spec.IdentifierID, IdentifierVersion: recipient.Identifier.Version, VerificationVersion: recipient.Verification.Version, AuthenticatedAt: now, ValidUntil: grant.Payload().ExpiresAt})
	if err != nil {
		return out, err
	}
	p := &verificationSigninPhase{service: s, request: r, origin: spec, flow: flow, recipient: recipient, confirmation: confirmation, factorVersion: factor.Version(), admission: admission}
	issuer, err := session.NewEmailVerificationSessionIssuerWithCSRF(p, s.c.Issuance, s.c.CSRFKey)
	if err != nil {
		return out, err
	}
	f, _ := flow.Bindings()
	prepared, err := issuer.PrepareEmailVerification(b, session.SessionSpec{SessionID: string(sessionID), FamilyID: string(familyID), TenantID: b.TenantID, UserID: b.UserID, Audience: s.c.Profile.Audience, Version: 1, FamilyVersion: 1, Remember: f.Binding.Intent.Remember, Authority: authority, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}, IssuedAt: now, LastActivityAt: now}, metadata)
	if err != nil {
		return out, err
	}
	p.record, _ = prepared.Session()
	fields, err := sessionpg.MagicLinkSigninSessionFields(p.record)
	if err != nil {
		return out, err
	}
	fields = append(fields, identity.FeatureField{Name: "verification.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factor.Version()}})
	p.command, err = identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, r.Browser)
	if err != nil {
		return out, err
	}
	prepared, err = issuer.BindEmailVerification(prepared, p.command)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return out, err
	}
	p.plan, err = p.preparePlan(now)
	if err != nil {
		return out, err
	}
	issued, err := issuer.Issue(ctx, prepared)
	if issued.CommitOutcome == identity.CommitOutcomeInvalid {
		// Refusal before executor entry observes no durable child outcome.
		// Retain its allocated Unknown scope and the committed parent instead
		// of replacing them with the issuer's empty pre-execution result.
		if err == nil {
			err = identity.UnavailableError{}
		}
		return out, err
	}
	out.Issuance = issued
	if err == nil && out.Issuance.Token != (session.Token{}) {
		out.CSRFToken, err = prepared.CSRFToken()
	}
	return out, err
}

func (s *VerificationSigninService) originalBrowser(r email.VerificationSigninRequest, original email.RegistrationVerificationSpec, flow session.PreAuthTransaction, now time.Time) error {
	c := s.signup.config()
	f, err := flow.Bindings()
	if err != nil || f.Binding.Intent.TenantID != r.Confirmation.TenantID || f.Binding.Intent.Action != "identity.password.signup" || f.Binding.Intent.Origin != r.Origin || f.Binding.Intent.CallbackURL != r.Confirmation.Callback.String() || original.Payload.Redirect.String() != r.Confirmation.Callback.String() || !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.CallbackURLs, r.Confirmation.Callback.String()) || f.Binding.Intent.PolicyID != c.PolicyID || f.Binding.Intent.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(r.Browser.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	for _, key := range c.FlowKeys {
		digest, err := token.PreAuthDigest(key, f.Binding)
		if err == nil && flow.Check(now, f.Binding, digest) == nil {
			return nil
		}
	}
	return identity.ForbiddenError{}
}

func (s *VerificationSigninService) authorize(ctx context.Context, original authorization.DecisionContext, b identity.CommandBinding) error {
	caller := original.Clone()
	caller.PolicyRevision = authorization.Revision(b.PolicyVersion)
	caller.CorrelationID = b.CorrelationID
	caller.Request.Tenant, caller.Request.Action = authorization.TenantID(b.TenantID), authorization.Action(b.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	for _, values := range []authorization.Attributes{caller.Request.Attributes, caller.Request.Subject.Attributes, caller.Request.Environment.Attributes} {
		for key := range values {
			if strings.HasPrefix(string(key), "identity.authentication.") {
				delete(values, key)
			}
		}
	}
	if caller.Request.Attributes == nil {
		caller.Request.Attributes = authorization.Attributes{}
	}
	caller.Request.Attributes["identity.authentication.method"] = authorization.StringValue("email-possession")
	caller.Request.Attributes["identity.authentication.profile"] = authorization.StringValue("single-factor")
	caller.Request.Attributes["identity.authentication.phase"] = authorization.StringValue("proposed")
	caller.Request.Attributes["identity.authentication.factor-count"] = authorization.IntValue(1)
	decision, err := s.signup.config().Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

// VerificationSigninRecover reconciles the exact retained child command under
// current query policy. No grant/browser/password, token generation, provider
// evaluation, new attempt or authority renewal occurs. Original parent, user,
// actor and tenant scope must match. A committed result is historical metadata,
// never a promise that the session is currently valid. Cancellation is bounded
// by the original signup owner's duration; errors and panic details are redacted.
func (s *VerificationSigninService) VerificationSigninRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out identity.CommandResult, err error) {
	if ctx == nil || s == nil || s.signup == nil || s.effect == nil || q.OperationID != verificationSigninOperation().OperationID || q.UserID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return out, email.ErrInvalidVerification
	}
	if _, err := identity.ParseCommandID(q.RecordID); err != nil || q.RecordID == string(q.CommandID) {
		return out, email.ErrInvalidVerification
	}
	ctx, stop := context.WithTimeout(ctx, s.signup.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	c, _, err := s.coordinator(&verificationSigninPhase{service: s})
	if err != nil {
		return out, err
	}
	return c.RecoverFeatureCommand(ctx, q, caller)
}

func verificationSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Format hides deployment, policy and native pool correlation.
func (*VerificationSigninService) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("passwordpostgres.VerificationSigninService(redacted)"))
}

// Format hides secret-bearing issuer configuration.
func (VerificationSigninConfig) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("passwordpostgres.VerificationSigninConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (VerificationSigninConfig) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit configuration/map-key export.
func (VerificationSigninConfig) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
