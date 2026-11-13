package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type signinStartInput struct {
	Binding                      rpStoredBinding
	Profile, Flow                [32]byte
	Provider, Network, Device    string
	Callback, ErrorCallback      string
	Started, ValidUntil          time.Time
	GlobalVersion, TenantVersion uint64
	Intent                       []identity.FeatureField
}

type signinStartPhase struct {
	service *SigninService
	request oauth.SigninStartRequest
	flow    session.PreAuthTransaction
	flowSum [32]byte
	input   *signinStartInput
}

func signinFlowDigest(flow session.PreAuthTransaction) ([32]byte, error) {
	spec, err := flow.Bindings()
	if err != nil {
		return [32]byte{}, err
	}
	b, i := spec.Binding, spec.Binding.Intent
	remember, err := i.Remember.Bindings()
	if err != nil || i.Purpose != session.PreAuthSessionIssuance || i.IdentifierBinding != ([32]byte{}) {
		return [32]byte{}, identity.ForbiddenError{}
	}
	// This is an encrypted native commitment to session-owned original data,
	// not a second stored preauth record or permission to consume that record.
	wire, err := json.Marshal(struct {
		ID, Tenant, Action, Origin, Callback, Policy string
		PolicyVersion, Version                       uint64
		Nonce                                        [32]byte
		Remember                                     session.RememberPolicySpec
		IssuedAt, ExpiresAt                          time.Time
		Cookie                                       session.TokenDigest
	}{string(b.ID), string(i.TenantID), i.Action, i.Origin, i.CallbackURL, i.PolicyID, i.PolicyVersion, spec.Version, i.Nonce, remember, b.IssuedAt, b.ExpiresAt, spec.Cookie})
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(wire)
	return sha256.Sum256(wire), nil
}

func (s *SigninService) newStartPhase(ctx context.Context, r oauth.SigninStartRequest) (*signinStartPhase, error) {
	var started, now time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started); err != nil {
		return nil, identity.UnavailableError{}
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), s.config.Session, r.TenantID, r.FlowID)
	if err != nil {
		return nil, err
	}
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, identity.UnavailableError{}
	}
	if now.Before(started) || !now.Before(started.Add(20*time.Second)) || checkSigninBrowser(r, flow, s.config.FlowKeys, s.config.PolicyID, s.config.Coordinator.AdmissionPolicy.PolicyVersion, now.UTC()) != nil {
		return nil, identity.ForbiddenError{}
	}
	digest, err := signinFlowDigest(flow)
	if err != nil {
		return nil, err
	}
	return &signinStartPhase{service: s, request: r, flow: flow, flowSum: digest}, nil
}

func (p *signinStartPhase) requestIntent() (identity.RequestIntent, error) {
	r := p.request
	callback, failure := r.Callback.URL(), r.ErrorCallback.URL()
	caller := r.Caller.Clone()
	caller.Request.Environment.Time = time.Time{}
	wire, err := json.Marshal(struct {
		Flow                      [32]byte
		Provider, Callback, Error string
		Scopes                    []string
		Caller                    authorization.DecisionContext
		Origin, Network, Device   string
	}{p.flowSum, string(r.Provider), callback.String(), failure.String(), r.Scopes.Values(), caller, r.Origin, r.Network, r.Device})
	if err != nil {
		return identity.RequestIntent{}, identity.InvalidInputError{Field: "oauth_signin_intent"}
	}
	defer clear(wire)
	mac := hmac.New(sha256.New, p.service.config.IntentKey[:])
	_, _ = mac.Write([]byte("identity-oauth-signin-start-intent-v1\x00"))
	_, _ = mac.Write(wire)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.service.profile[:]}}, {Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}})
}

func (p *signinStartPhase) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	s, r := p.service, p.request
	if s == nil || k.Feature != p.registration() || k.Namespace != s.requestKey.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != "identity.oauth.signin-start" || k.Scope.TenantID != r.TenantID || k.Scope.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || k.Scope.ActorKind != authorization.SubjectServiceAccount || k.PolicyVersion != s.config.Coordinator.AdmissionPolicy.PolicyVersion || k.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(struct {
		Key     rpStoredKey
		Profile [32]byte
	}{rpStoredKey(k), s.profile})
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-signin-start-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *signinStartPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.inputAAD(k)
	if err != nil {
		return nil, err
	}
	s, r := p.service, p.request
	var now time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, identity.UnavailableError{}
	}
	now = now.UTC()
	if checkSigninBrowser(r, p.flow, s.config.FlowKeys, s.config.PolicyID, s.config.Coordinator.AdmissionPolicy.PolicyVersion, now) != nil {
		return nil, identity.ForbiddenError{}
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.GlobalAuthorityID, TenantID: r.TenantID})
	if err != nil {
		return nil, err
	}
	if !directory.Enabled {
		return nil, identity.ForbiddenError{}
	}
	caller := r.Caller.Clone()
	caller.Request.Environment.Time = now
	decision, err := s.config.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != s.config.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, identity.ForbiddenError{}
	}
	fields, ok := intent.Fields()
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	op := rpSigninStartOperation()
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.FlowID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(k.Admission.CommandID), PolicyID: s.config.PolicyID, PolicyVersion: s.config.Coordinator.AdmissionPolicy.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: string(k.Admission.CommandID)}
	callback, failure := r.Callback.URL(), r.ErrorCallback.URL()
	flow, _ := p.flow.Bindings()
	until := now.Add(20 * time.Second)
	if flow.Binding.ExpiresAt.Before(until) {
		until = flow.Binding.ExpiresAt
	}
	input := signinStartInput{Binding: rpStoredBinding(b), Profile: s.profile, Flow: p.flowSum, Provider: string(r.Provider), Network: r.Network, Device: r.Device, Callback: callback.String(), ErrorCallback: failure.String(), Started: now, ValidUntil: until, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion, Intent: fields}
	plain, err := json.Marshal(input)
	if err != nil || len(plain) > 64<<10 {
		return nil, identity.InvalidInputError{Field: "oauth_signin_input"}
	}
	defer clear(plain)
	return s.seal(ctx, aad, plain)
}

func (p *signinStartPhase) restoreInput(ctx context.Context, key kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.inputAAD(key)
	if err != nil {
		return err
	}
	plain, err := p.service.open(ctx, aad, wire, 128<<10)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input signinStartInput
	if decodeRPOutput(plain, &input) != nil {
		return identity.ForbiddenError{}
	}
	b, c := identity.CommandBinding(input.Binding), p.service.config
	if b.ValidateFor(rpSigninStartOperation()) != nil || b.CommandID != key.Admission.CommandID || b.TenantID != p.request.TenantID || b.AnonymousFlowID != string(p.request.FlowID) || b.ActorID != identity.ActorID(p.request.Caller.Request.Subject.ID) || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != string(b.CommandID) || b.PolicyID != c.PolicyID || b.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || b.CorrelationID != string(b.CommandID) || input.Profile != p.service.profile || input.Flow != p.flowSum || input.GlobalVersion == 0 || input.TenantVersion == 0 || !rpUTCTime(input.Started) || !rpUTCTime(input.ValidUntil) || !input.ValidUntil.After(input.Started) || input.ValidUntil.After(input.Started.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	intent, err := p.requestIntent()
	if err != nil {
		return err
	}
	fields, _ := intent.Fields()
	callback, failure := p.request.Callback.URL(), p.request.ErrorCallback.URL()
	if input.Provider != string(p.request.Provider) || input.Callback != callback.String() || input.ErrorCallback != failure.String() || input.Network != p.request.Network || input.Device != p.request.Device || !reflect.DeepEqual(input.Intent, fields) {
		return identity.ConflictError{}
	}
	p.input = &input
	return nil
}

func (s *SigninService) seal(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	sealed, err := s.envelopes.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config.CurrentEnvelopeKey, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealed.MarshalBinary()
}

func (s *SigninService) open(ctx context.Context, aad envelope.Context, wire []byte, limit int) ([]byte, error) {
	if len(wire) < 1 || len(wire) > limit {
		return nil, identity.ForbiddenError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	plain, err := s.envelopes.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > limit {
		clear(plain)
		return nil, identity.ForbiddenError{}
	}
	return plain, nil
}

// The original preauth intent already selects callback, not signin-start. Its
// cookie commitment cannot be rebound to a different action, callback or
// Remember choice when the browser returns from the provider. This check grants
// no active-record authority; the native phase also requires that exact record
// through session/postgres inside the coordinator's Work.
func checkSigninBrowser(r oauth.SigninStartRequest, flow session.PreAuthTransaction, keys []session.DigestKey, policy string, version uint64, now time.Time) error {
	if r.Validate() != nil {
		return identity.ForbiddenError{}
	}
	callback := r.Callback.URL()
	return checkSigninOriginalBrowser(signinBrowserScope{Tenant: r.TenantID, FlowID: r.FlowID, Cookie: r.FlowCookie, Remember: r.Remember, Origin: r.Origin, Callback: callback.String()}, flow, keys, policy, version, now)
}

// The same session-owned intent authenticates start and callback without
// synthesizing a start request or a replacement idempotency key at callback.
type signinBrowserScope struct {
	Tenant           identity.TenantID
	FlowID           identity.PreAuthTransactionID
	Cookie           auth.BearerCredential
	Remember         session.RememberPolicy
	Origin, Callback string
}

func checkSigninOriginalBrowser(r signinBrowserScope, flow session.PreAuthTransaction, keys []session.DigestKey, policy string, version uint64, now time.Time) error {
	spec, err := flow.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	b := spec.Binding
	intent := b.Intent
	wantRemember, err := r.Remember.Bindings()
	originalRemember, originalErr := intent.Remember.Bindings()
	if err != nil || originalErr != nil || wantRemember != originalRemember || intent.Purpose != session.PreAuthSessionIssuance || intent.IdentifierBinding != ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	if b.ID != r.FlowID || intent.TenantID != r.Tenant || intent.Action != "identity.oauth.callback" || intent.Origin != r.Origin || intent.CallbackURL != r.Callback || intent.PolicyID != policy || intent.PolicyVersion != version {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	for _, key := range keys {
		digest, err := token.PreAuthDigest(key, b)
		if err == nil && flow.Check(now, b, digest) == nil {
			return nil
		}
	}
	return identity.ForbiddenError{}
}
