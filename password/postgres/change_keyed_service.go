package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// KeyedPasswordChangeConfig enables durable request correlation on the existing
// kernel journal. Its dedicated nonzero HMAC key is fixed for this
// namespace; retain it and original policy configuration while mappings exist.
// ActiveEnvelopeKeyID selects new encryption; the borrowed local keyring must
// also retain decrypting keys for original input and output. All input is trusted
// startup configuration, never request data. Construct with
// NewKeyedPasswordChangeConfig; zero/literal values are invalid.
type KeyedPasswordChangeConfig struct {
	RequestKeys         kernel.RequestKeyConfig
	ActiveEnvelopeKeyID string
	intentKey           func() [32]byte
}

// NewKeyedPasswordChangeConfig freezes an independent intent key in opaque
// custody. It performs no callbacks, crypto or IO. RequestKeys must be a kernel-
// constructed configuration; the service constructor revalidates it. Keys must
// be independent from request-lookup, command-fingerprint and encryption keys.
// Copies share immutable custody; changing public fields is revalidated at use.
func NewKeyedPasswordChangeConfig(requestKeys kernel.RequestKeyConfig, intentKey [32]byte, activeEnvelopeKeyID string) (KeyedPasswordChangeConfig, error) {
	if intentKey == ([32]byte{}) || !reauthenticationText(requestKeys.Namespace, 128) || requestKeys.Policy.PolicyVersion == 0 || requestKeys.Policy.Clock == nil || requestKeys.Policy.Authorization == nil || !reauthenticationText(activeEnvelopeKeyID, 256) {
		return KeyedPasswordChangeConfig{}, password.ErrPasswordWork
	}
	return KeyedPasswordChangeConfig{RequestKeys: requestKeys, ActiveEnvelopeKeyID: activeEnvelopeKeyID, intentKey: func() [32]byte { return intentKey }}, nil
}

// KeyedPasswordChangeService implements keyed authenticated password change.
// It borrows the existing native source, primary pool and local keyring. Each
// call owns one private comparable participant for all of its kernel phases;
// no shared registry, raw password map, private journal or workflow is mutated.
// Calls are concurrent-safe with independently owned request secrets. Install
// request-key/preparation and counter-preparation histories before use. It owns
// no persistent goroutines and never destroys caller-owned secrets. Per-call
// deadline propagation callbacks are stopped before Change returns.
type KeyedPasswordChangeService struct {
	native   *PasswordChangeService
	crypto   *envelope.Service
	config   func() KeyedPasswordChangeConfig
	identity [32]byte
	csrf     func() passwordChangeCSRF
}

// NewKeyedPasswordChangeService validates additive keyed composition. Existing
// NewPasswordChangeService remains the unkeyed trusted native profile; public
// keyed endpoints must select this service and pass exactly one retry key.
// Missing key/schema/custody never falls back to a new unkeyed command.
func NewKeyedPasswordChangeService(source *ReauthenticationService, policy PasswordChangeConfig, c KeyedPasswordChangeConfig, keys *keyring.Provider) (*KeyedPasswordChangeService, error) {
	if keys == nil || c.intentKey == nil || c.intentKey() == ([32]byte{}) || !reauthenticationText(c.ActiveEnvelopeKeyID, 256) {
		return nil, password.ErrPasswordWork
	}
	native, err := NewPasswordChangeService(source, policy)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	hibp, err := native.c.Screening.Policy.HIBPConfiguration()
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	admission, err := native.c.Screening.Policy.Admit(risk.Action(replacementOperation().OperationID))
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	primitivePolicy := native.c.Screening.Primitive.Policy()
	primitiveFrame, err := json.Marshal(struct {
		Algorithm   string
		Argon2id    any
		BcryptCost  int
		Limits      any
		DummyDigest [32]byte
		HIBP        risk.HIBPPolicy
		Admission   risk.Admission
	}{string(primitivePolicy.Algorithm()), primitivePolicy.Argon2idParameters(), primitivePolicy.BcryptCost(), primitivePolicy.Limits(), sha256.Sum256([]byte(native.c.Screening.DummyHash.String())), hibp, admission})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	primitiveDigest := sha256.Sum256(primitiveFrame)
	clear(primitiveFrame)
	// Freeze the scalar behavior selection, not ephemeral provider observations.
	// Encryption-key selection is deliberately absent: retained envelopes identify
	// their original key and changing only the active key must not remap input.
	frame, err := json.Marshal(struct {
		Profile                      string
		Namespace, Audience          string
		Issuer, Environment          string
		SessionProfile               []string
		ProofAge, ScreeningTimeout   time.Duration
		Minimum, Maximum, SessionCap uint32
		SessionDisposition           uint8
		AdmissionPolicy, QueryPolicy uint64
		PrimitivePolicy              [32]byte
	}{"identity-password-keyed-v1", c.RequestKeys.Namespace, native.c.Audience, source.c.Issuer, source.c.Environment, []string{source.c.Profile.GlobalAuthorityID, source.c.Profile.PolicyNamespace, source.c.Profile.Audience, source.c.Profile.AuthenticationMethod, source.c.Profile.CredentialOwner, source.c.Session.Schema}, native.c.MaximumAge, native.c.Screening.Timeout, native.c.Screening.MinimumBytes, native.c.Screening.MaximumBytes, native.c.MaximumSessions, uint8(native.c.SessionDisposition), source.c.Coordinator.AdmissionPolicy.PolicyVersion, c.RequestKeys.Policy.PolicyVersion, primitiveDigest})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	s := &KeyedPasswordChangeService{native: native, crypto: crypto, config: func() KeyedPasswordChangeConfig { return c }, identity: digest}
	if _, _, err := s.coordinator(&keyedPasswordChangePhase{service: s}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func (s *KeyedPasswordChangeService) coordinator(p *keyedPasswordChangePhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	_, registry, err := s.native.coordinator(p)
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.native.source.pool, registry, s.native.source.c.Coordinator, s.config().RequestKeys)
	return coordinator, registry, err
}

// Change maps exact borrowed password/bearer/proof bytes to purpose-bound keyed
// digests before preparation. Matching retries restore original encrypted input
// and journal outcomes before current-material lookup or hashing. Changed intent
// conflicts; pending/unknown generation cannot authorize a replacement hash.
// Original one-use proof, password/session effects, audit and lifecycle still
// commit through the sole native transaction. Recovery remains available through
// the existing code-free PasswordChangeService.Recover contract. Destroy Password
// after return. Earlier deadlines win; secret errors and panics are redacted.
func (s *KeyedPasswordChangeService) Change(ctx context.Context, r PasswordChangeRequest, key identity.IdempotencyKey) (result PasswordChangeResult, err error) {
	if s != nil && s.csrf != nil {
		return result, password.ErrPasswordWork
	}
	return s.change(ctx, r, key, session.CSRFToken{})
}

func (s *KeyedPasswordChangeService) change(ctx context.Context, r PasswordChangeRequest, key identity.IdempotencyKey, token session.CSRFToken) (result PasswordChangeResult, err error) {
	if ctx == nil || s == nil || s.native == nil || s.config == nil {
		return result, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.native.source.c.Repository.MaximumDuration)
	defer stop()
	ctx, expire := context.WithCancelCause(ctx)
	defer expire(context.Canceled)
	var deadlineStops []func()
	defer func() {
		for _, stop := range deadlineStops {
			stop()
		}
	}()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			err = context.Cause(ctx)
		}
		if err != nil {
			result.CredentialVersion, result.AuthorityInvalidated = 0, false
		}
	}()
	intent, err := s.requestIntent(ctx, r, token)
	if err != nil {
		return result, err
	}
	p := &keyedPasswordChangePhase{service: s, request: func() PasswordChangeRequest { return r }, csrfToken: func() session.CSRFToken { return token }}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: replacementOperation().OperationID}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: replacementOperation()}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().RequestKeys.Policy.PolicyVersion)
	caller.Request.Tenant, caller.Request.Action = authorization.TenantID(scope.TenantID), authorization.Action(scope.RouteID)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	binding, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, key, intent, caller, feature, p)
	if err != nil {
		var unknown identity.UnknownCommitError
		var conflict identity.ConflictError
		if errors.As(err, &unknown) {
			result.CommandID, result.Outcome = unknown.CommandID, identity.CommitOutcomeUnknown
		}
		if errors.As(err, &conflict) {
			result.Outcome = identity.CommitOutcomeConflict
		}
		return result, err
	}
	defer clear(wire)
	result.CommandID, result.Outcome = binding.Admission.CommandID, identity.CommitOutcomeUnknown
	input, err := p.restoreInput(ctx, binding, wire)
	if err != nil {
		return result, err
	}
	// Freeze invocation-local custody before synchronous execution. No other call
	// can see this participant; generation/restoration never changes its input.
	p.input = func() keyedPasswordChangeInput { return input }
	command, plan, err := p.originalCommand(coordinator, registry)
	if err != nil {
		return result, err
	}
	p.command, p.plan = command, plan
	var earliest time.Time
	p.arm = func(until time.Time) error {
		remaining := until.Sub(time.Now())
		if remaining <= 0 {
			return identity.ForbiddenError{}
		}
		if !earliest.IsZero() && !until.Before(earliest) {
			return nil
		}
		earliest = until
		deadline, cancel := context.WithTimeout(ctx, remaining)
		stop := context.AfterFunc(deadline, func() { expire(context.DeadlineExceeded) })
		deadlineStops = append(deadlineStops, func() { stop(); cancel() })
		return nil
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	if receipt.Outcome != 0 {
		result.Outcome = receipt.Outcome
	}
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted && receipt.Feature != nil {
		result.CredentialVersion, result.AuthorityInvalidated = receipt.Feature.AfterVersion, true
	}
	return result, err
}

func (s *KeyedPasswordChangeService) requestIntent(ctx context.Context, r PasswordChangeRequest, token session.CSRFToken) (identity.RequestIntent, error) {
	if ctx.Err() != nil {
		return identity.RequestIntent{}, ctx.Err()
	}
	if r.Caller.Request.Subject.Kind != authorization.SubjectUser || !reauthenticationText(string(r.Caller.Request.Subject.ID), 128) || !reauthenticationText(string(r.TenantID), 128) || !reauthenticationText(r.Network, 128) || r.Password.Len() < int(s.native.c.Screening.MinimumBytes) || r.Password.Len() > int(s.native.c.Screening.MaximumBytes) || len(r.Session.Token()) > 128 {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	// Upstream structure is bounded before serialization; current signed proof
	// authentication occurs only while preparing the original mapping candidate.
	if r.Proof.Validate(s.proofUse(r, r.Proof.Proof.IssuedAt)) != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	proof, err := json.Marshal(r.Proof)
	if err != nil || len(proof) > maximumReauthenticationRecordBytes {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(proof)
	digest := func(purpose string, raw []byte) []byte {
		key := s.config().intentKey()
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("identity-password-request-v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(raw))))
		_, _ = mac.Write(raw)
		return mac.Sum(nil)
	}
	var candidate []byte
	if err := r.Password.Use(func(raw []byte) error {
		if ctx.Err() != nil || len(raw) < int(s.native.c.Screening.MinimumBytes) || len(raw) > int(s.native.c.Screening.MaximumBytes) {
			return password.ErrPasswordWork
		}
		candidate = digest("password", raw)
		return nil
	}); err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	fields := []identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.identity[:]}},
		{Name: "password", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: candidate}},
		{Name: "bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("bearer", []byte(r.Session.Token()))}},
		{Name: "proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("proof", proof)}},
		{Name: "network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.Network}},
	}
	if s.csrf != nil {
		// A fixed non-authoritative binding provides stable purpose-specific token
		// correlation across CSRF key rotation. This digest is never admission.
		state, err := token.Digest(s.csrf().intent, session.CSRFBinding{TenantID: r.TenantID, SessionID: "password-cookie-intent", SessionVersion: 1})
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		spec, err := state.Bindings()
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		fields = append(fields, identity.FeatureField{Name: "csrf", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: spec.Digest[:]}})
	}
	return identity.NewRequestIntent(fields)
}

func (s *KeyedPasswordChangeService) proofUse(r PasswordChangeRequest, now time.Time) auth.ReauthenticationUse {
	return auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.TenantID), Subject: string(r.Caller.Request.Subject.ID), Purpose: "identity.password.verify", Audience: s.native.c.Audience, Now: now}, SessionID: r.Proof.SessionID, SessionVersion: r.Proof.SessionVersion, Action: replacementOperation().OperationID, MaximumAge: s.native.c.MaximumAge}
}

func (KeyedPasswordChangeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.KeyedPasswordChangeConfig(redacted)"))
}
func (KeyedPasswordChangeConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (KeyedPasswordChangeService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.KeyedPasswordChangeService(redacted)"))
}

// Recover discloses the original journal outcome under current query policy,
// without resubmitting a password, bearer, retry key or provider observation.
// It preserves the native code-free recovery scope and never regenerates output.
func (s *KeyedPasswordChangeService) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (PasswordChangeResult, error) {
	if s == nil || s.native == nil {
		return PasswordChangeResult{}, password.ErrPasswordWork
	}
	return s.native.Recover(ctx, q, caller)
}
