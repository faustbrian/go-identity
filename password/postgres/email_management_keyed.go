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

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// KeyedEmailManagementConfig selects the existing durable request-key mapping.
// Construct with NewKeyedEmailManagementConfig. Retain the namespace, dedicated
// intent key, original configuration and decrypting keys while mappings exist.
// The intent key must be independent of lookup, fingerprint and envelope keys.
type KeyedEmailManagementConfig struct {
	RequestKeys kernel.RequestKeyConfig
	intentKey   func() [32]byte
}

// NewKeyedEmailManagementConfig freezes a nonzero purpose-specific intent key.
// RequestKeys must be constructed by the kernel. This performs no IO.
func NewKeyedEmailManagementConfig(keys kernel.RequestKeyConfig, intentKey [32]byte) (KeyedEmailManagementConfig, error) {
	if intentKey == ([32]byte{}) || !reauthenticationText(keys.Namespace, 128) || keys.Policy.PolicyVersion == 0 || keys.Policy.Clock == nil || keys.Policy.Authorization == nil {
		return KeyedEmailManagementConfig{}, password.ErrPasswordWork
	}
	return KeyedEmailManagementConfig{RequestKeys: keys, intentKey: func() [32]byte { return intentKey }}, nil
}

// KeyedEmailManagementService adds retry correlation to a native email owner.
// It borrows its immutable pool, configuration and envelope keyring; no private
// journal, transaction, goroutine or delivery engine is created. Install kernel
// request-key/preparation histories. Calls are concurrent-safe with independent
// borrowed request credentials. No raw bearer, CSRF token or retry key persists.
type KeyedEmailManagementService struct {
	native     *EmailManagementService
	config     func() KeyedEmailManagementConfig
	profile    [32]byte
	csrfIntent session.CSRFKey
}

// NewKeyedEmailManagementService validates additive keyed composition without
// IO. It preserves the native cookie/bearer profile and existing unkeyed APIs.
func NewKeyedEmailManagementService(native *EmailManagementService, c KeyedEmailManagementConfig) (*KeyedEmailManagementService, error) {
	if native == nil || native.primary == nil || native.config == nil || native.crypto == nil || c.intentKey == nil || c.intentKey() == ([32]byte{}) {
		return nil, password.ErrPasswordWork
	}
	source := native.primary.source
	frame, err := json.Marshal(struct {
		Native                                   [32]byte
		Namespace, Issuer, Environment, Audience string
		Policy                                   uint64
		Transport                                session.CredentialKind
	}{native.profile, c.RequestKeys.Namespace, source.c.Issuer, source.c.Environment, native.primary.config.Audience, c.RequestKeys.Policy.PolicyVersion, native.primary.config.Transport})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	key := c.intentKey()
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-email-csrf-intent-v1"))
	material := mac.Sum(nil)
	csrf, err := session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	s := &KeyedEmailManagementService{native: native, config: func() KeyedEmailManagementConfig { return c }, profile: profile, csrfIntent: csrf}
	p := &emailManagementPhase{service: native}
	if _, _, err := s.coordinator(p); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func (s *KeyedEmailManagementService) coordinator(p *emailManagementPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	_, registry, err := s.native.coordinator(p)
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.native.primary.source.pool, registry, s.native.primary.source.c.Coordinator, s.config().RequestKeys)
	return c, registry, err
}

// VerificationSend selects a new server-generated address and winning command
// once. Primary.CommandID and AddressID must be empty. Matching retries restore
// encrypted original custody before live reads; changed intent conflicts.
func (s *KeyedEmailManagementService) VerificationSend(ctx context.Context, r EmailManagementRequest, key identity.IdempotencyKey) (EmailManagementResult, error) {
	return s.request(ctx, r, key, "identity.email.verification-send", false)
}

// VerificationResend retains the exact supplied pending AddressID. It never
// changes the mailbox target, bypasses cooldown or creates a new command on retry.
// Primary.CommandID must be empty; a new retry key requires fresh primary proof.
func (s *KeyedEmailManagementService) VerificationResend(ctx context.Context, r EmailManagementRequest, key identity.IdempotencyKey) (EmailManagementResult, error) {
	return s.request(ctx, r, key, "identity.email.verification-send", true)
}

// ChangeRequest freezes original previous-address policy and a server-generated
// pending candidate. Both supplied command/address IDs must be empty. It neither
// promotes the new address nor sends an old-address notification before confirm.
func (s *KeyedEmailManagementService) ChangeRequest(ctx context.Context, r EmailManagementRequest, key identity.IdempotencyKey) (EmailManagementResult, error) {
	return s.request(ctx, r, key, "identity.email.change-request", false)
}

func (s *KeyedEmailManagementService) request(ctx context.Context, r EmailManagementRequest, key identity.IdempotencyKey, action string, resend bool) (out EmailManagementResult, err error) {
	if ctx == nil || s == nil || s.native == nil || s.config == nil || s.native.primary.config.Action != action || resend && s.native.config().ResendInterval == 0 {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.native.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = EmailManagementResult{CommandID: out.CommandID, Outcome: out.Outcome}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.AddressID = ""
			out.IdentifierVersion = 0
			out.VerificationVersion = 0
		}
	}()
	intent, err := s.requestIntent(ctx, r, resend)
	if err != nil {
		return out, err
	}
	p := &emailManagementPhase{service: s.native, keyed: &keyedEmailInvocation{service: s, request: r, resend: resend}}
	c, registry, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	scope, caller, feature := s.requestScope(r, resend, p.Descriptor())
	binding, wire, err := c.ResolvePreparedRequestKey(ctx, scope, key, intent, caller, feature, p)
	if err != nil {
		var unknown identity.UnknownCommitError
		var conflict identity.ConflictError
		if errors.As(err, &unknown) {
			out.CommandID = unknown.CommandID
			out.Outcome = identity.CommitOutcomeUnknown
		}
		if errors.As(err, &conflict) {
			out.Outcome = identity.CommitOutcomeConflict
		}
		return out, err
	}
	defer clear(wire)
	out.CommandID, out.Outcome = binding.Admission.CommandID, identity.CommitOutcomeUnknown
	if err = p.restoreRequestKey(ctx, binding, wire); err != nil {
		return out, err
	}
	p.coordinator, p.registry = c, registry
	plan, err := p.plan(false)
	if err != nil {
		return out, err
	}
	receipt, err := c.ExecutePreparedFeature(ctx, p.command, plan)
	if receipt.Outcome != 0 {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		out.AddressID = p.link.IdentifierID
		out.IdentifierVersion, out.VerificationVersion = p.link.IdentifierVersion, p.link.VerificationVersion
	}
	return out, err
}

func (s *KeyedEmailManagementService) requestScope(r EmailManagementRequest, resend bool, owner kernel.ContributorDescriptor) (kernel.RequestKeyScope, authorization.DecisionContext, kernel.FeatureRegistration) {
	op := emailPrimaryOperation(s.native.primary.config.Action)
	if resend {
		op = managedResendOperation()
	}
	scope := kernel.RequestKeyScope{TenantID: r.Primary.TenantID, ActorID: identity.ActorID(r.Primary.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := r.Primary.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().RequestKeys.Policy.PolicyVersion)
	caller.Request.Tenant, caller.Request.Action = authorization.TenantID(scope.TenantID), authorization.Action(op.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	return scope, caller, kernel.FeatureRegistration{Contributor: owner, Operation: op}
}

// RequestRateSource returns authenticated subject and canonical destination for
// the selected request's HTTP rate admission. Both are sensitive: hash only with
// the rate owner's existing keyed projection; never log or disclose the mailbox.
// Exact retained input is read before live source lookup, so spent-proof retries
// remain countable. An absent mapping permits bounded original-source reads only:
// no durable mapping/command allocation, provider assessment, signing, counter charge,
// consumption, delivery or transaction runs. Ephemeral candidate IDs are not
// returned or retained. Corrupt/conflicting history never falls back to fresh
// source. Returned metadata grants no current session or mutation authority;
// execution independently fences those owners in the existing transaction.
// Pool and credentials stay borrowed, earlier cancellation wins, immutable
// composition supports concurrent calls, and any error returns zero metadata.
func (s *KeyedEmailManagementService) RequestRateSource(ctx context.Context, r EmailManagementRequest, key identity.IdempotencyKey, resend bool) (user identity.UserID, address string, err error) {
	if ctx == nil || s == nil || s.native == nil || s.config == nil || resend && (s.native.primary.config.Action != "identity.email.verification-send" || s.native.config().ResendInterval == 0) {
		return "", "", password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, min(s.native.config().MaximumDuration, 20*time.Second))
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			user, address = "", ""
		}
	}()
	intent, err := s.requestIntent(ctx, r, resend)
	if err != nil {
		return "", "", err
	}
	p := &emailManagementPhase{service: s.native, keyed: &keyedEmailInvocation{service: s, request: r, resend: resend}}
	c, _, err := s.coordinator(p)
	if err != nil {
		return "", "", err
	}
	scope, caller, feature := s.requestScope(r, resend, p.Descriptor())
	binding, wire, found, err := c.ReadPreparedRequestKey(ctx, scope, key, intent, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return "", "", err
	}
	if found {
		if err := p.restoreRequestKey(ctx, binding, wire); err != nil {
			return "", "", err
		}
	} else {
		r.Primary.CommandID, err = identity.NewCommandID()
		if err != nil {
			return "", "", password.ErrPasswordWork
		}
		if !resend {
			id, e := identity.NewCommandID()
			if e != nil {
				return "", "", password.ErrPasswordWork
			}
			r.Primary.AddressID = identity.IdentifierID(id)
		}
		p, err = s.native.prepareRequest(ctx, r, s.native.primary.config.Action, resend)
		if err != nil {
			return "", "", err
		}
	}
	return p.link.Binding.UserID, p.link.Payload.CanonicalAddress.Record().Value, nil
}

func (s *KeyedEmailManagementService) requestIntent(ctx context.Context, r EmailManagementRequest, resend bool) (identity.RequestIntent, error) {
	primary := r.Primary
	if ctx.Err() != nil {
		return identity.RequestIntent{}, ctx.Err()
	}
	if primary.CommandID != "" || !resend && primary.AddressID != "" || primary.Caller.Request.Subject.Kind != authorization.SubjectUser || !validEmailPrimaryCaller(primary.Caller) || !reauthenticationText(string(primary.Caller.Request.Subject.ID), 128) || !reauthenticationText(string(primary.TenantID), 128) || len(primary.Session.Token()) == 0 || len(primary.Session.Token()) > 128 || len(r.Address) > 254 || len(r.CallbackURL) == 0 || len(r.CallbackURL) > 2048 || !reauthenticationText(r.Network, 128) {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	if resend {
		if _, err := identity.ParseIdentifierID(string(primary.AddressID)); err != nil {
			return identity.RequestIntent{}, password.ErrPasswordWork
		}
	}
	use := s.proofUse(r, primary.Proof.Proof.IssuedAt)
	if primary.Proof.Validate(use) != nil {
		return identity.RequestIntent{}, identity.ForbiddenError{}
	}
	proof, err := json.Marshal(primary.Proof)
	if err != nil || len(proof) > maximumReauthenticationRecordBytes {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(proof)
	digest := func(purpose string, raw []byte) []byte {
		key := s.config().intentKey()
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("identity-email-request-v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(raw))))
		_, _ = mac.Write(raw)
		return mac.Sum(nil)
	}
	fields := []identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}},
		{Name: "resend", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: resend}},
		{Name: "address-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(primary.AddressID)}},
		{Name: "address", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("address", []byte(r.Address))}},
		{Name: "callback", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("callback", []byte(r.CallbackURL))}},
		{Name: "network", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("network", []byte(r.Network))}},
		{Name: "bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("bearer", []byte(primary.Session.Token()))}},
		{Name: "proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("proof", proof)}},
	}
	switch s.native.primary.config.Transport {
	case session.CredentialCookie:
		state, err := primary.CSRFToken.Digest(s.csrfIntent, session.CSRFBinding{TenantID: primary.TenantID, SessionID: "email-cookie-intent", SessionVersion: 1})
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		b, err := state.Bindings()
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		fields = append(fields, identity.FeatureField{Name: "csrf", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: b.Digest[:]}})
	case session.CredentialBearer:
		if primary.CSRFToken != (session.CSRFToken{}) {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
	default:
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	return identity.NewRequestIntent(fields)
}

func (s *KeyedEmailManagementService) proofUse(r EmailManagementRequest, now time.Time) auth.ReauthenticationUse {
	return auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(r.Primary.TenantID), Subject: string(r.Primary.Caller.Request.Subject.ID), Purpose: "identity.password.verify", Audience: s.native.primary.config.Audience, Now: now}, SessionID: r.Primary.Proof.SessionID, SessionVersion: r.Primary.Proof.SessionVersion, Action: s.native.primary.config.Action, MaximumAge: s.native.primary.config.MaximumAge}
}

// Format redacts borrowed native owners and keyed configuration.
func (KeyedEmailManagementService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.KeyedEmailManagementService(redacted)"))
}

// MarshalJSON refuses sensitive service export.
func (KeyedEmailManagementService) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText refuses sensitive service export.
func (KeyedEmailManagementService) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format redacts independent intent and lookup custody.
func (KeyedEmailManagementConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.KeyedEmailManagementConfig(redacted)"))
}

// MarshalJSON refuses key configuration export.
func (KeyedEmailManagementConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText refuses key configuration export.
func (KeyedEmailManagementConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
