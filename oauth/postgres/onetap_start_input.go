package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type oneTapStartPhase struct {
	service       *OneTapStartService
	registry      *kernel.ContributorRegistry
	request       onetap.BrowserStartRequestSpec
	input         *oneTapStartInput
	sessionIssuer *session.PreAuthIssuer
	generated     session.PreparedPreAuthIssuance
	generation    uint64
	applied       bool
	delivery      *identity.CommandResult
}

type oneTapStartInput struct {
	Binding                      rpStoredBinding
	Profile, Intent              [32]byte
	ObservedAt, ValidUntil       time.Time
	GlobalVersion, TenantVersion uint64
}

func (*oneTapStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-initiation", Version: 1}
}

func (*oneTapStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.OneTapStartOperation()}
}

func (p *oneTapStartPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: kernel.OneTapStartOperation()}
}

func (p *oneTapStartPhase) intent() (identity.RequestIntent, error) {
	s := p.service
	options, err := p.request.Options.Projection()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	remember, err := p.request.Remember.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	frame, err := json.Marshal(struct {
		Origin, Network, Device string
		Remember                session.RememberPolicySpec
		Options                 onetap.BrowserStartProjection
	}{p.request.Origin, p.request.Network, p.request.Device, remember, options})
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	defer clear(frame)
	key := s.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-oauth-onetap-start-intent-v1\x00"))
	_, _ = mac.Write(s.profile[:])
	_, _ = mac.Write(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "onetap.start.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}})
}

func oneTapIntentDigest(intent identity.RequestIntent) ([32]byte, error) {
	fields, ok := intent.Fields()
	if !ok || len(fields) != 1 || fields[0].Name != "onetap.start.input" || len(fields[0].Value.Bytes) != sha256.Size || fields[0].Value.Kind != identity.FeatureBytes {
		return [32]byte{}, identity.ForbiddenError{}
	}
	return [32]byte(fields[0].Value.Bytes), nil
}

func (p *oneTapStartPhase) inputAAD(key kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	c := p.service.config()
	scope := kernel.RequestKeyScope{TenantID: c.TenantID, ActorID: c.Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: http.MethodPost, RouteID: oneTapStartOperationID}
	if key.Feature != p.registration() || key.Scope != scope || key.Namespace != p.service.requestKey.Namespace || key.PolicyVersion != c.Issuance.PolicyVersion || key.IntentDigest == ([32]byte{}) || key.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	return oneTapEnvelopeContext("identity-oauth-onetap-start-input-v1", struct {
		Key     rpStoredKey
		Profile [32]byte
	}{rpStoredKey(key), p.service.profile})
}

func (p *oneTapStartPhase) PrepareRequestKey(ctx context.Context, key kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.inputAAD(key)
	if err != nil {
		return nil, err
	}
	intentDigest, err := oneTapIntentDigest(intent)
	if err != nil {
		return nil, err
	}
	c := p.service.config()
	observed := c.Issuance.Clock.Now().UTC().Truncate(time.Microsecond)
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: c.TenantID}
	authority, err := p.service.directory.GetDirectoryAuthority(ctx, query)
	if err != nil {
		return nil, err
	}
	if !authority.Enabled {
		return nil, identity.ForbiddenError{}
	}
	// This opaque handle selects the future row, not browser credentials.
	// Nonce, cookie and callback proof are generated only in the admitted phase.
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		return nil, err
	}
	op := kernel.OneTapStartOperation()
	b := identity.CommandBinding{CommandID: key.Admission.CommandID, TenantID: c.TenantID,
		AnonymousFlowID: string(flow), RecordID: string(flow), CorrelationID: string(key.Admission.CommandID),
		ActorID: c.Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount,
		OperationID: op.OperationID, PolicyID: c.Issuance.PolicyID, PolicyVersion: c.Issuance.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion}
	if b.ValidateFor(op) != nil {
		return nil, identity.ForbiddenError{}
	}
	input := oneTapStartInput{Binding: rpStoredBinding(b), Profile: p.service.profile, Intent: intentDigest,
		ObservedAt: observed, ValidUntil: observed.Add(20 * time.Second), GlobalVersion: authority.GlobalVersion, TenantVersion: authority.TenantVersion}
	return p.service.sealOneTap(ctx, aad, input, 8192)
}

func (p *oneTapStartPhase) restoreInput(ctx context.Context, key kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.inputAAD(key)
	if err != nil {
		return err
	}
	var input oneTapStartInput
	if err := p.service.openOneTap(ctx, aad, wire, 8192, &input); err != nil {
		return err
	}
	b, c := identity.CommandBinding(input.Binding), p.service.config()
	if b.ValidateFor(kernel.OneTapStartOperation()) != nil || b.CommandID != key.Admission.CommandID || b.TenantID != c.TenantID ||
		b.RecordID != b.AnonymousFlowID || b.ActorID != c.Issuance.ActorID || b.ActorKind != authorization.SubjectServiceAccount ||
		b.PolicyID != c.Issuance.PolicyID || b.PolicyVersion != c.Issuance.PolicyVersion || b.CorrelationID != string(b.CommandID) || input.Profile != p.service.profile ||
		!rpUTCTime(input.ObservedAt) || !input.ValidUntil.Equal(input.ObservedAt.Add(20*time.Second)) || input.GlobalVersion == 0 || input.TenantVersion == 0 {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParsePreAuthTransactionID(b.RecordID); err != nil {
		return identity.ForbiddenError{}
	}
	intent, err := p.intent()
	if err != nil {
		return err
	}
	digest, err := oneTapIntentDigest(intent)
	if err != nil || !hmac.Equal(digest[:], input.Intent[:]) {
		return identity.ConflictError{}
	}
	p.input = &input
	return nil
}

func (p *oneTapStartPhase) command(record *session.PreAuthTransaction) (identity.Command, error) {
	if p.input == nil {
		return identity.Command{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(p.input)
	if err != nil {
		return identity.Command{}, identity.UnavailableError{}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	fields := []identity.FeatureField{{Name: "onetap.start.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}
	if record != nil {
		commitment, err := sessionpg.OneTapStartPreAuthField(*record)
		if err != nil {
			return identity.Command{}, err
		}
		fields = append(fields, commitment)
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: identity.CommandBinding(p.input.Binding), Operation: kernel.OneTapStartOperation(), Fields: fields})
}

func oneTapEnvelopeContext(domain string, value any) (envelope.Context, error) {
	frame, err := json.Marshal(value)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": domain, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (s *OneTapStartService) sealOneTap(ctx context.Context, aad envelope.Context, value any, limit int) ([]byte, error) {
	plain, err := json.Marshal(value)
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > limit-1024 {
		return nil, identity.UnavailableError{}
	}
	sealed, err := s.envelopes.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config().CurrentEnvelopeKey, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealed.MarshalBinary()
}

func (s *OneTapStartService) openOneTap(ctx context.Context, aad envelope.Context, wire []byte, limit int, value any) error {
	if len(wire) == 0 || len(wire) > limit {
		return identity.ForbiddenError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return identity.ForbiddenError{}
	}
	plain, err := s.envelopes.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > limit || decodeRPOutput(plain, value) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
