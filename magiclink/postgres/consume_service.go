package magiclinkpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ConsumeConfig selects the session owner's original lookup/cookie/CSRF custody
// and current user authorization namespace. ConfigurationID pins these semantics
// and must change when they change. RequestService retains the original request
// profile, issuer, browser, risk and envelope configuration. Neither config is
// client input. Authority must be nil for this grant-consuming issuance profile.
type ConsumeConfig struct {
	ConfigurationID, PolicyNamespace string
	Issuer                           session.IssuerConfig
	CSRF                             session.CSRFKey
	MFA                              *MFAChallengeConfig
}

// MFAChallengeConfig enables native TOTP continuation, never a single-factor
// session for enrolled accounts. Lifetime is absolute and capped by original
// primary expiry/five minutes. Missing supported factor authority denies.
type MFAChallengeConfig struct {
	Lifetime    time.Duration
	MaxAttempts uint32
}

// Format redacts borrowed secret and deployment configuration.
func (ConsumeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkpostgres.ConsumeConfig(redacted)"))
}

// MarshalJSON prevents implicit secret-bearing configuration export.
func (ConsumeConfig) MarshalJSON() ([]byte, error) { return nil, invalid() }

// ConsumeService composes original request custody with native one-use/session
// effects under the existing coordinator. It owns no goroutine, connection,
// sender, token table or independent journal. The borrowed RequestService and
// primary pool outlive calls; callers close their resources. Zero denies.
type ConsumeService struct {
	request *RequestService
	config  ConsumeConfig
	profile [32]byte
	policy  *authoritypg.AuthorityStore
	effect  *sessionpg.MagicLinkSigninEffect
}

// NewConsumeService freezes the actual native owners without IO or migrations.
// Install magic-link session/issuance and authorization histories alongside all
// RequestService prerequisites. The default denies enrolled factor authority;
// explicit MFA selection additionally needs MFA continuation and confirmed TOTP
// histories. It issues only a continuation, never an enrolled account's session.
func NewConsumeService(request *RequestService, c ConsumeConfig) (*ConsumeService, error) {
	if request == nil || request.pool == nil || request.pool.Raw() == nil || request.config == nil || !visible(c.ConfigurationID, 128) || !visible(c.PolicyNamespace, 128) || c.Issuer.Authority != nil {
		return nil, invalid()
	}
	r := request.config()
	if c.MFA != nil {
		if !r.MFAContinuation || c.MFA.Lifetime < time.Second || c.MFA.Lifetime > 5*time.Minute || c.MFA.Lifetime%time.Second != 0 || c.MFA.MaxAttempts < 1 || c.MFA.MaxAttempts > 100 {
			return nil, invalid()
		}
		owned := *c.MFA
		c.MFA = &owned
	}
	policy, err := authoritypg.NewAuthorityStore(request.pool.Raw(), r.MaximumDuration)
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewMagicLinkSigninEffect(r.Session, sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: r.GlobalAuthorityID, PolicyNamespace: c.PolicyNamespace, Audience: r.Issuer.Audience})
	if err != nil {
		return nil, err
	}
	// Validate session composition through the real owner, without generating
	// tokens or calling an executor. Each invocation constructs its own issuer.
	if _, err = session.NewMagicLinkSessionIssuerWithCSRF(&consumePhase{}, c.Issuer, c.CSRF); err != nil {
		return nil, err
	}
	frame, err := json.Marshal(struct {
		Domain, ID, Namespace string
		Request               [32]byte
		MFA                   *MFAChallengeConfig `json:",omitempty"`
	}{"identity-magic-link-consume-profile-v1", c.ConfigurationID, c.PolicyNamespace, request.configuration, c.MFA})
	defer clear(frame)
	if err != nil {
		return nil, invalid()
	}
	return &ConsumeService{request: request, config: c, profile: sha256.Sum256(frame), policy: policy, effect: effect}, nil
}

func consumeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func (s *ConsumeService) coordinator(p *consumePhase) (*kernel.Coordinator, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	o, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.request.directory, a, o, p, issuerpg.NewParticipant()})
	if s.config.MFA != nil {
		registry, err = kernel.NewContributorRegistry([]kernel.Contributor{s.request.directory, a, o, p, issuerpg.NewParticipant(), s.request.issuer})
	}
	if err != nil {
		return nil, err
	}
	c, err := kernel.NewCoordinator(s.request.pool, registry, s.request.config().Coordinator)
	p.coordinator, p.registry = c, registry
	return c, err
}

// Consume attempts one original stable command. It authenticates durable grant
// origin and browser intent before native preparation, then generates one
// prospective session only after acknowledged journal ownership. The retained
// output contains tokenless session fields, never the new bearer. Protected
// effects and one-use finalize atomically; only the generating invocation can
// deliver credentials after an exact committed receipt. Ambiguity and replay
// never regenerate. Caller-supplied user, factor, expiry or remember overrides
// are absent from the input contract.
func (s *ConsumeService) Consume(ctx context.Context, r magiclink.ConsumeRequest) (out magiclink.ConsumeResult, err error) {
	if ctx == nil || s == nil || s.request == nil || r.Validate() != nil {
		return out, invalid()
	}
	c := s.request.config()
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = magiclink.ConsumeResult{}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			out.Session.Token = session.Token{}
			out.Session.Cookie = emptyCookie()
			out.CSRFToken = session.CSRFToken{}
			err = ctx.Err()
		}
		if err != nil {
			out.Challenge = magiclink.MFAChallengeResult{}
		}
	}()
	if !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.Callbacks, r.Callback) {
		return out, identity.ForbiddenError{}
	}
	grant, origin, replayVersion, superseded, err := s.request.issuer.ReadMagicLinkOrigin(ctx, s.request.pool, r.Token)
	if err != nil {
		return out, err
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.request.pool.Raw(), c.Session, r.TenantID, r.PreAuthID)
	if err != nil {
		return out, err
	}
	flowInput := magiclink.RequestRequest{TenantID: r.TenantID, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Origin: r.Origin, Callback: r.Callback}
	if err = s.request.admitFlow(flowInput, flow, time.Now().UTC()); err != nil {
		return out, err
	}
	canonical := grant.Payload().Caveats["magiclink.canonical-email"]
	recipient, err := s.request.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return out, err
	}
	var selected requestSelection
	if grant.Payload().Caveats["magiclink.prospective"] == "1" {
		selected, err = s.request.readProspectiveOrigin(ctx, r, flow, grant, origin)
	} else {
		selected, err = s.request.validateConsumptionScope(r, flow, grant, origin, recipient, time.Now().UTC())
	}
	if err != nil {
		return out, err
	}
	if superseded {
		return out, magiclink.SupersededError{}
	}
	op := consumeOperation()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID)}
	user, identifier := recipient.User.ID, recipient.Identifier.ID
	if selected.prospective != nil {
		user, identifier = selected.prospective.Creation.Binding.UserID, selected.prospective.Identifier.ID
	}
	proof, err := s.request.issuer.PrepareMagicLinkConsumption(ctx, b, user, identifier, r.Token, grant.EnvelopeDigest(), replayVersion)
	if err != nil {
		return out, err
	}
	frame, err := json.Marshal(struct {
		Profile                   [32]byte
		Proof                     [32]byte
		Origin                    identity.CommandID
		Callback, Network, Device string
	}{s.profile, grant.EnvelopeDigest(), origin, r.Callback, r.Network, r.Device})
	defer clear(frame)
	if err != nil {
		return out, invalid()
	}
	mac := hmac.New(sha256.New, c.IntentKey[:])
	mac.Write([]byte("identity-magic-link-consume-input-v1\x00"))
	mac.Write(frame)
	fields := []identity.FeatureField{{Name: "consume.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(mac.Sum(nil))}}}
	var signup *kernel.MagicLinkRegistrationIntent
	if selected.prospective != nil {
		intent := *selected.prospective
		creationBinding := b
		creationBinding.OperationID, creationBinding.AnonymousFlowID, creationBinding.UserID = "identity.user.create", "", user
		creationBinding.SchemaID, creationBinding.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
		intent.Creation.Binding = creationBinding
		owned, e := identity.NewUserCreationCommand(intent.Creation)
		if e != nil {
			return out, e
		}
		intent.Creation, _ = owned.CreateUser()
		registrationFields, e := kernel.MagicLinkRegistrationFields(intent)
		if e != nil {
			return out, e
		}
		fields = append(fields, registrationFields...)
		signup = &intent
	}
	original, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, r.Cookie)
	if err != nil {
		return out, err
	}
	mac = hmac.New(sha256.New, c.IntentKey[:])
	mac.Write([]byte("identity-magic-link-consume-counter-v1\x00" + string(r.TenantID) + "\x00" + canonical))
	p := &consumePhase{service: s, request: r, original: original, flow: flow, grant: grant, origin: origin, selected: selected, proof: proof, subject: risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}, signup: signup}
	defer func() {
		if err != nil && p.generatedChallengeProof != (capability.Proof{}) {
			_ = p.generatedChallengeProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		}
	}()
	if s.config.MFA != nil && signup == nil {
		p.mfaRequired, err = mfapg.ReadMagicLinkChallengeRequired(ctx, s.request.pool, grant, s.request.config().MaximumDuration)
		if err != nil {
			return out, err
		}
	}
	p.issuer, err = session.NewMagicLinkSessionIssuerWithCSRF(p, s.config.Issuer, s.config.CSRF)
	if err != nil {
		return out, err
	}
	coordinator, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	plan, err := p.plan(original, time.Now().UTC())
	if err != nil {
		return out, err
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, original, plan)
	out = consumeReceipt(r.CommandID, result)
	if p.mfaRequired {
		if result.Outcome == identity.CommitOutcomeCommitted {
			out.State = auth.SignInStateChallengeRequired
		}
		if err == nil && result.Validate() == nil && result.Binding.CommandID == r.CommandID && result.Outcome == identity.CommitOutcomeCommitted && p.generatedChallengeProof != (capability.Proof{}) && p.execution != nil && p.execution.challenge != nil {
			c, e := p.execution.challenge.continuation.Bindings()
			if e != nil {
				return magiclink.ConsumeResult{}, e
			}
			out.Challenge = magiclink.MFAChallengeResult{ID: identity.CommandID(c.ID), Proof: p.generatedChallengeProof, Method: "totp", ExpiresAt: c.ExpiresAt}
			out.Session.Replayed = false
		}
		return out, err
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || p.prepared == (session.PreparedIssuance{}) || p.command == (identity.Command{}) {
		return out, err
	}
	p.receipt, p.deliverable = result, true
	prepared, err := p.issuer.BindMagicLink(p.prepared, p.command)
	if err != nil {
		return out, err
	}
	out.Session, err = p.issuer.Issue(ctx, prepared)
	out.Outcome = out.Session.CommitOutcome
	if err == nil && out.Session.Token != (session.Token{}) {
		out.CSRFToken, err = prepared.CSRFToken()
	}
	if err != nil {
		out.Session.Token = session.Token{}
		out.Session.Cookie = emptyCookie()
		out.CSRFToken = session.CSRFToken{}
	}
	return out, err
}

func consumeReceipt(id identity.CommandID, result identity.CommandResult) magiclink.ConsumeResult {
	state := auth.SignInStateRejected
	if result.Outcome == identity.CommitOutcomeCommitted {
		state = auth.SignInStateAuthenticated
	}
	return magiclink.ConsumeResult{Outcome: result.Outcome, State: state, Session: session.IssueResult{CommandID: id, CommitOutcome: result.Outcome, Replayed: result.Outcome == identity.CommitOutcomeCommitted, RetryAfter: result.RetryAfter}}
}

// RecoverConsume reconciles only the original proof-free command under current
// result-access policy. No proof/browser input, session generation, provider,
// sender or credential delivery is possible. Committed metadata never implies
// a currently valid session; live session validation remains session-owned.
func (s *ConsumeService) RecoverConsume(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (magiclink.ConsumeResult, error) {
	if ctx == nil || s == nil || s.request == nil || q.OperationID != consumeOperation().OperationID || q.UserID != "" || q.RecordID != "" || q.AnonymousFlowID == "" {
		return magiclink.ConsumeResult{}, invalid()
	}
	ctx, stop := context.WithTimeout(ctx, s.request.config().MaximumDuration)
	defer stop()
	c, err := s.coordinator(&consumePhase{service: s})
	if err != nil {
		return magiclink.ConsumeResult{}, err
	}
	caller = caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.request.config().Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	result, err := c.RecoverFeatureCommand(ctx, q, caller)
	out := consumeReceipt(q.CommandID, result)
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted && s.config.MFA != nil {
		challenge, e := mfapg.ReadMagicLinkChallengeOutcome(ctx, s.request.pool, result, s.request.config().MaximumDuration)
		if e != nil {
			return magiclink.ConsumeResult{}, e
		}
		if challenge {
			out.State = auth.SignInStateChallengeRequired
		}
	}
	return out, err
}

var _ magiclink.ConsumptionService = (*ConsumeService)(nil)

func emptyCookie() http.Cookie { return http.Cookie{} }
