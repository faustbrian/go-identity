package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// SendConfig selects one immutable purpose/template/policy deployment. All
// fields are trusted startup input. Store.Codec must be nil; Codec constructs
// owned copied custody. Session is optional and selects authenticated-session
// support; Store.PreAuth and retained cookies independently select pre-auth.
// The service owns its renderer and uses Codec's digest keys for both generation
// and persistence. Policy and template/locale fields fix preparation. Risk must
// own genuine counted/audited Authentication-lane evaluation. IntentKey and
// IdentifierKey are distinct dedicated keys; preserve every retained key and
// configuration while dependent request history exists. Timeout is 1ms..5s.
// RequestKeys selects the existing kernel request-key namespace and admission
// policy. No dependency is called or migration run during construction.
// Caller must not mutate inputs during construction; owners copy configuration.
type SendConfig struct {
	Store                    ContributorConfig
	Codec                    AttemptCodecConfig
	Session                  *SessionAdmissionConfig
	Delivery                 deliverypg.ContributorConfig
	Coordinator              kernel.CoordinatorConfig
	RequestKeys              kernel.RequestKeyConfig
	Risk                     risk.AuthenticationAdmissionCustodyConfig
	Policy                   otp.AttemptPolicy
	TemplateID               string
	TemplateVersion          uint32
	LocaleChain              []string
	Templates                []delivery.Template
	ProviderVersion          uint64
	PolicyID                 string
	PolicyVersion            uint64
	PreAuthAction            string
	IntentKey, IdentifierKey [32]byte
	Timeout                  time.Duration
}

// SendService is the concrete public PostgreSQL Send workflow. It composes
// recipient resolution, original-flow possession, counted risk, same-code
// generation and transactional issuance or enumeration-safe suppression. The
// existing kernel owns all correlation, journals, transactions and recovery.
// No domain store, handler or workflow callback is supplied by consumers.
// Borrowed pool, envelope and policy/risk dependencies remain caller-owned.
// No goroutines are started; immutable construction supports concurrent calls.
// Zero/nil is invalid. Initialize must succeed against installed migrations
// before use; no missing schema or retired key is silently repaired at Send.
type SendService struct {
	pool                 *database.Pool
	owner                *authenticationSendContributor
	coordinator          *kernel.Coordinator
	registry             *kernel.ContributorRegistry
	requestKeys          kernel.RequestKeyConfig
	timeout              time.Duration
	requestPolicyVersion uint64
	digestVersions       []uint32
	participants         []kernel.Contributor
	coordinatorConfig    kernel.CoordinatorConfig
}

// NewSendService validates pure startup composition and owns all native
// participants before registry construction. It performs no service/database
// IO, entropy, migrations or callbacks. Install kernel directory/credential,
// request-key/preparation/admission-preparation, audit/outbox/lifecycle, OTP
// lockout/send-family/issuance, delivery and selected session/pre-auth schemas.
// Then Initialize the stable key namespace. Incomplete configuration denies.
func NewSendService(pool *database.Pool, c SendConfig, crypto *envelope.Service) (*SendService, error) {
	return newSendService(pool, c, crypto, nil, nil)
}

func newSendService(pool *database.Pool, c SendConfig, crypto *envelope.Service, email, changeDomain *emailVerificationProfile) (*SendService, error) {
	if pool == nil || pool.Raw() == nil || crypto == nil || c.Timeout < time.Millisecond || c.Timeout > 5*time.Second || c.Store.Codec != nil {
		return nil, ErrInvalidConfiguration
	}
	codec, err := NewAttemptCodec(c.Codec)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	c.Store.Codec = codec
	store, err := newContributor(c.Store, c.Session)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	store.emailVerification = email
	store.emailChangeDomain = changeDomain
	deliveryOwner, err := deliverypg.NewContributor(c.Delivery, crypto)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Timeout})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	auditOwner, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	lifecycleOwner, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	descriptors := []kernel.ContributorDescriptor{repo.Descriptor(), auditOwner.Descriptor(), lifecycleOwner.Descriptor(), store.Descriptor(), deliveryOwner.Descriptor()}
	store, err = newPreparedSendContributor(store, deliveryOwner, preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: c.Policy, TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, LocaleChain: c.LocaleChain}, provider: c.ProviderVersion, contributors: descriptors, templates: c.Templates, publicAudit: true})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	store, err = newSendInitiationContributor(store, pool, sendInitiationConfig{policyID: c.PolicyID, policyVersion: c.PolicyVersion, preAuthAction: c.PreAuthAction, intentKey: c.IntentKey, identifierKey: c.IdentifierKey, maximumDuration: c.Timeout})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	owner, err := newAuthenticationSendContributor(store, c.Risk)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	participants := []kernel.Contributor{repo, auditOwner, lifecycleOwner, owner, deliveryOwner}
	registry, err := kernel.NewContributorRegistry(participants)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if c.Coordinator.AdmissionPolicy == nil {
		policy := c.RequestKeys.Policy
		c.Coordinator.AdmissionPolicy = &policy
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(pool, registry, c.Coordinator, c.RequestKeys)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	versions := make([]uint32, 0, len(c.Codec.CodeKeys))
	for version := range c.Codec.CodeKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return &SendService{pool: pool, owner: owner, coordinator: coordinator, registry: registry, requestKeys: c.RequestKeys, timeout: c.Timeout, requestPolicyVersion: c.RequestKeys.Policy.PolicyVersion, digestVersions: versions, participants: participants, coordinatorConfig: snapshotSendCoordinator(c.Coordinator)}, nil
}

// Own configuration used when selecting an invocation-local native phase. The
// coordinator still owns the same journal/keys; no request can select a policy.
func snapshotSendCoordinator(c kernel.CoordinatorConfig) kernel.CoordinatorConfig {
	c.RetainedFingerprintKeys = maps.Clone(c.RetainedFingerprintKeys)
	if c.QueryPolicy != nil {
		p := *c.QueryPolicy
		c.QueryPolicy = &p
	}
	if c.AdmissionPolicy != nil {
		p := *c.AdmissionPolicy
		c.AdmissionPolicy = &p
	}
	if c.FinalAuthentication != nil {
		p := *c.FinalAuthentication
		c.FinalAuthentication = &p
	}
	return c
}

// Initialize installs only the configured stable lockout-key binding and
// retained digest-key metadata, never schema or business records. It is bounded,
// concurrent/idempotent for exact configuration; a changed installed key fails
// closed. It starts one startup-only transaction, not a command authority. A
// lost commit acknowledgement is unavailable/unknown startup, never success;
// retry identical configuration. Missing migrations fail closed.
func (s *SendService) Initialize(ctx context.Context) error {
	if ctx == nil || s == nil || s.owner == nil || s.pool == nil {
		return ErrInvalidConfiguration
	}
	return initializeIssuanceKeys(ctx, s.pool, s.owner.store, s.timeout, s.digestVersions)
}

func initializeIssuanceKeys(ctx context.Context, pool *database.Pool, store *Contributor, timeout time.Duration, versions []uint32) error {
	if ctx == nil || pool == nil || pool.Raw() == nil || store == nil || store.codec == nil || len(versions) == 0 {
		return ErrInvalidConfiguration
	}
	ctx, stop := context.WithTimeout(ctx, timeout)
	defer stop()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		return custodyFailure(ctx)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	schema := pgx.Identifier{store.schema}.Sanitize()
	binding := store.lockout.binding()
	if _, err := tx.Exec(ctx, `INSERT INTO `+schema+`.lockout_key_binding VALUES(true,$1) ON CONFLICT(singleton) DO NOTHING`, binding[:]); err != nil {
		return custodyFailure(ctx)
	}
	var original []byte
	if err := tx.QueryRow(ctx, `SELECT key_binding FROM `+schema+`.lockout_key_binding WHERE singleton`).Scan(&original); err != nil {
		return custodyFailure(ctx)
	}
	if !hmac.Equal(original, binding[:]) {
		return ErrInvalidConfiguration
	}
	for _, version := range versions {
		if _, err := tx.Exec(ctx, `INSERT INTO `+schema+`.digest_keys(key_version,algorithm) VALUES($1,'hmac-sha256-v1') ON CONFLICT(key_version) DO NOTHING`, version); err != nil {
			return custodyFailure(ctx)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return custodyFailure(ctx)
	}
	return nil
}

// Send is the complete native caller path. Matching keys restore the unchanged
// original input before risk/generation. Changed intent conflicts; unknown or
// in-progress journal outcomes never generate a replacement. Submitted bearer
// possession is checked on every call, including terminal replay. Public results
// never distinguish suppression from issuance or queue acceptance from delivery.
func (s *SendService) Send(ctx context.Context, r otp.SendRequest) (result otp.SendResult, err error) {
	if r.Validate() != nil {
		return result, ErrInvalidCommand
	}
	return s.send(ctx, r, nil)
}

func (s *SendService) send(ctx context.Context, r otp.SendRequest, email *otp.EmailVerificationSendRequest) (result otp.SendResult, err error) {
	if ctx == nil || s == nil || s.owner == nil || s.coordinator == nil || email != nil && (s.owner.store.emailVerification == nil || email.Validate() != nil) {
		return result, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.timeout)
	defer stop()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	entered := false
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
			if entered {
				result.Outcome = identity.CommitOutcomeUnknown
				if result.CommandID != "" {
					err = identity.UnknownCommitError{CommandID: result.CommandID}
				}
			}
		}
	}()
	kind, id, bearer, err := r.Flow.Bindings()
	if err != nil {
		return result, ErrInvalidCommand
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.requestPolicyVersion)
	caller.Request.Action = "identity.otp.send"
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.send"}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, Method: "POST", RouteID: "identity.otp.send"}
	request := sendInitiatingRequest{userID: r.UserID, flowKind: kind, flowID: id, purpose: r.Purpose, channel: r.Channel, destination: r.Destination, target: r.TargetID, network: r.Network, device: r.Device}
	if email != nil {
		request.addressID, request.addressVersion = email.AddressID, email.AddressVersion
	}
	intent, err := s.owner.store.sendRequestIntent(request, bearer)
	if err != nil {
		return result, ErrInvalidCommand
	}
	subject := identity.FeatureSubjectUser
	if r.UserID == "" {
		subject = identity.FeatureSubjectAnonymousFlow
	}
	feature := kernel.FeatureRegistration{Contributor: s.owner.Descriptor(), Operation: issuanceOperation(subject)}
	entered = true
	binding, wire, err := s.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, feature, s.owner)
	if err != nil {
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			result.CommandID, result.Outcome = unknown.CommandID, identity.CommitOutcomeUnknown
		}
		var conflict identity.ConflictError
		if errors.As(err, &conflict) {
			result.Outcome = identity.CommitOutcomeConflict
		}
		return result, err
	}
	defer clear(wire)
	// A mapping is correlation, not a negative journal receipt: matching retry
	// may already have committed. Failures before authoritative execution cannot
	// claim NotCommitted merely because this invocation performed no mutation.
	result.CommandID, result.Outcome = binding.Admission.CommandID, identity.CommitOutcomeUnknown
	input, err := s.owner.store.restoreSendInitiation(ctx, binding, wire, bearer)
	if err != nil {
		return result, err
	}
	var command identity.Command
	var plan kernel.CommandPlan
	if input.suppressed {
		command, err = s.owner.mapSuppressedSend(ctx, input, bearer)
		if err == nil {
			plan, err = s.owner.suppressedSendPlan(command)
		}
	} else {
		command, err = s.owner.mapInitiatedSend(ctx, input)
		if err == nil {
			plan, err = s.owner.store.preparedSendPlan(input.original, nil)
		}
	}
	if err != nil {
		return result, err
	}
	outcome, err := s.coordinator.ExecutePreparedFeature(ctx, command, plan)
	if outcome.Outcome != 0 {
		result.Outcome, result.RetryAfter = outcome.Outcome, outcome.RetryAfter
	}
	return result, err
}

func (SendConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.SendConfig(redacted)"))
}
func (SendConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (SendConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (SendConfig) LogValue() slog.Value         { return slog.StringValue("otp.postgres.SendConfig(redacted)") }
func (SendService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.SendService(redacted)"))
}
func (SendService) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (SendService) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
func (SendService) LogValue() slog.Value {
	return slog.StringValue("otp.postgres.SendService(redacted)")
}

var _ otp.Service = (*SendService)(nil)
