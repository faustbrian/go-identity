package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// These explicit private projections occur only inside authenticated encrypted
// native custody. They contain no raw browser bearer or synchronizer token.
type rpStoredBinding identity.CommandBinding
type rpStoredKey kernel.RequestKeyPreparationBinding

type rpStartInput struct {
	Schema                  uint8
	Binding                 rpStoredBinding
	Provider                string
	Network                 string
	Callback, ErrorCallback string
	Session                 []identity.FeatureField
	Intent                  []identity.FeatureField
	Profile                 [32]byte
	Started, ValidUntil     time.Time
	FactorVersion           uint64
}

func (i rpStartInput) binding() identity.CommandBinding { return identity.CommandBinding(i.Binding) }

type rpStartPhase struct {
	service         *LinkService
	request         oauth.LinkStartRequest
	input           *rpStartInput
	counterVersions []uint32
}

func (*rpStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}
}
func (*rpStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{rpLinkStartOperation()}
}
func (p *rpStartPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: rpLinkStartOperation()}
}
func rpLinkStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *LinkService) startIntent(r oauth.LinkStartRequest) (identity.RequestIntent, error) {
	token, err := session.ParseToken(r.Session.Token())
	if err != nil {
		return identity.RequestIntent{}, err
	}
	digest, err := token.Digest(s.intentKey, string(r.TenantID))
	if err != nil {
		return identity.RequestIntent{}, err
	}
	csrf, err := r.CSRFToken.Digest(s.intentCSRF, session.CSRFBinding{TenantID: r.TenantID, SessionID: "oauth-link-start-intent-v1", SessionVersion: 1})
	if err != nil {
		return identity.RequestIntent{}, err
	}
	synchronizer, err := csrf.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	callback, failure := r.Callback.URL(), r.ErrorCallback.URL()
	// Admission time is refreshed by the policy owner on every attempt; it is
	// not a user-selected change to the original idempotent linking intent.
	caller := r.Caller.Clone()
	caller.Request.Environment.Time = time.Time{}
	frame, err := json.Marshal(struct {
		Tenant                    identity.TenantID
		Provider, Callback, Error string
		Scopes                    []string
		SignupDisabled            bool
		Session                   session.TokenDigest
		CSRF                      session.CSRFStateSpec
		Caller                    authorization.DecisionContext
		Origin, Network           string
	}{r.TenantID, string(r.Provider), callback.String(), failure.String(), r.Scopes.Values(), r.SignupDisabled, digest, synchronizer, caller, r.Origin, r.Network})
	if err != nil {
		return identity.RequestIntent{}, identity.InvalidInputError{Field: "oauth_start_intent"}
	}
	defer clear(frame)
	key := s.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-oauth-link-start-intent-v1\x00"))
	_, _ = mac.Write(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}}, {Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}})
}

func (p *rpStartPhase) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	s := p.service
	if k.Feature != p.registration() || k.Namespace != s.requestKey.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != "identity.account.link-start" || k.Scope.TenantID != p.request.TenantID || k.Scope.ActorID != identity.ActorID(p.request.Caller.Request.Subject.ID) || k.Scope.ActorKind != authorization.SubjectUser || k.PolicyVersion != s.requestKey.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_start_key"}
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, err
	}
	frame, err := json.Marshal(struct {
		Key     rpStoredKey
		Profile [32]byte
	}{rpStoredKey(k), s.profile})
	if err != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_start_key"}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-rp-start-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *rpStartPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	s, r, c := p.service, p.request, p.service.config()
	aad, err := p.inputAAD(k)
	if err != nil || r.Validate() != nil {
		return nil, identity.InvalidInputError{Field: "oauth_start_input"}
	}
	var started time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started); err != nil {
		return nil, identity.UnavailableError{}
	}
	started = started.UTC()
	token, err := session.ParseToken(r.Session.Token())
	if err != nil {
		return nil, err
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return nil, err
	}
	observed, err := s.sessions.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
	if err != nil || !observed.Authenticated || observed.ValidateAt(c.Session.Validation.Clock.Now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	record, err := observed.Session.Bindings()
	if err != nil || string(record.UserID) != string(r.Caller.Request.Subject.ID) || !s.possesses(r.TenantID, r.Session, r.CSRFToken, observed.Session) {
		return nil, identity.ForbiddenError{}
	}
	life, err := observed.Session.Lifetime(c.Session.Validation.Clock.Now())
	if err != nil || !life.Fresh {
		return nil, identity.ForbiddenError{}
	}
	caller := r.Caller.Clone()
	caller.Request.Environment.Time = started
	decision, err := c.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, identity.ForbiddenError{}
	}
	factors, err := mfapg.ReadOAuthLinkFactors(ctx, s.pool, r.TenantID, record.UserID, c.Session.Repository.MaximumDuration)
	if err != nil {
		return nil, err
	}
	fields, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil {
		return nil, err
	}
	originalIntent, ok := intent.Fields()
	if !ok {
		return nil, identity.InvalidInputError{Field: "oauth_start_intent"}
	}
	op := rpLinkStartOperation()
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: r.TenantID, UserID: record.UserID, ActorID: identity.ActorID(record.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(k.Admission.CommandID), PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: string(k.Admission.CommandID)}
	callback, failure := r.Callback.URL(), r.ErrorCallback.URL()
	until := started.Add(20 * time.Second)
	if observed.ValidUntil().Before(until) {
		until = observed.ValidUntil()
	}
	input := rpStartInput{Schema: 1, Binding: rpStoredBinding(b), Provider: string(r.Provider), Network: r.Network, Callback: callback.String(), ErrorCallback: failure.String(), Session: fields, Intent: originalIntent, Profile: s.profile, Started: started, ValidUntil: until, FactorVersion: factors.Version()}
	plain, err := json.Marshal(input)
	if err != nil || len(plain) > 256<<10 {
		return nil, identity.InvalidInputError{Field: "oauth_start_input"}
	}
	defer clear(plain)
	sealed, err := s.envelopes.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: c.CurrentEnvelopeKey, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealed.MarshalBinary()
}

func (p *rpStartPhase) openInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (rpStartInput, error) {
	var input rpStartInput
	aad, err := p.inputAAD(k)
	if err != nil || len(wire) == 0 || len(wire) > 1<<20 {
		return input, identity.InvalidInputError{Field: "oauth_start_input"}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return input, identity.ForbiddenError{}
	}
	plain, err := p.service.envelopes.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > 256<<10 {
		return input, identity.ForbiddenError{}
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Schema != 1 || input.Profile != p.service.profile || input.binding().CommandID != k.Admission.CommandID || input.binding().TenantID != k.Scope.TenantID || input.binding().ActorID != k.Scope.ActorID || input.binding().ValidateFor(rpLinkStartOperation()) != nil || input.FactorVersion == 0 || len(input.Session) == 0 || len(input.Session) > 128 || !rpUTCTime(input.Started) || !rpUTCTime(input.ValidUntil) || !input.ValidUntil.After(input.Started) || input.ValidUntil.After(input.Started.Add(20*time.Second)) {
		return rpStartInput{}, identity.ForbiddenError{}
	}
	current, err := p.service.startIntent(p.request)
	if err != nil {
		return rpStartInput{}, err
	}
	actual, _ := current.Fields()
	want, _ := identity.NewRequestIntent(input.Intent)
	expected, ok := want.Fields()
	if !ok || !sameRPFields(actual, expected) {
		return rpStartInput{}, identity.ConflictError{}
	}
	return input, nil
}

func (p *rpStartPhase) originalSession() (session.Session, error) {
	if p.input == nil {
		return session.Session{}, identity.InvalidInputError{Field: "oauth_start_input"}
	}
	b := p.input.binding()
	return sessionpg.OriginalSessionFromFields(b.TenantID, b.UserID, p.input.Session)
}

func (p *rpStartPhase) command() (identity.Command, kernel.CommandCounterPlan, error) {
	if p.input == nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, identity.InvalidInputError{Field: "oauth_start_input"}
	}
	frame, err := json.Marshal(p.input)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, identity.InvalidInputError{Field: "oauth_start_input"}
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	fields := append([]identity.FeatureField(nil), p.input.Session...)
	fields = append(fields, identity.FeatureField{Name: "oauth.input-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, identity.FeatureField{Name: "oauth.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.input.FactorVersion}})
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.input.binding(), Operation: rpLinkStartOperation(), Fields: fields}, p.request.Session)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	original, err := p.originalSession()
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	spec, _ := original.Bindings()
	subject := risk.Subject{User: string(spec.UserID), Session: spec.SessionID, Network: p.input.Network}
	if len(p.counterVersions) != 0 {
		return p.service.counters.PrepareCommandCountersWithRetainedKeys(command, subject, p.input.Started, p.counterVersions)
	}
	return p.service.counters.PrepareCommandCounters(command, subject, p.input.Started)
}

func sameRPFields(a, b []identity.FeatureField) bool {
	x, err := identity.NewRequestIntent(a)
	if err != nil {
		return false
	}
	y, err := identity.NewRequestIntent(b)
	if err != nil {
		return false
	}
	left, _ := x.Fields()
	right, _ := y.Fields()
	l, err := json.Marshal(left)
	if err != nil {
		return false
	}
	r, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(l, r)
}
