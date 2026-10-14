package reference

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// Explicit native projections live only inside existing authenticated request
// preparation. No raw proof, browser bearer, generated code or new store enters
// this representation. Aliases bypass redacting public marshalers intentionally.
type otpSendStoredFactor mfapg.OTPFactorMetadata
type otpSendStoredCredential kernel.CredentialAdmission
type otpSendStoredRecipientQuery kernel.RecipientQuery
type otpSendStoredRecipient struct {
	Query                                                                        otpSendStoredRecipientQuery
	User                                                                         identity.User
	Identifier                                                                   identity.Identifier
	Verification                                                                 identity.Verification
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
	ObservedAt                                                                   time.Time
}

func storeOTPSendRecipient(r kernel.RecipientRecord) otpSendStoredRecipient {
	return otpSendStoredRecipient{otpSendStoredRecipientQuery(r.Query), r.User, r.Identifier, r.Verification, r.UserAuthorityVersion, r.IdentifierAuthorityVersion, r.CredentialAuthorityVersion, r.ObservedAt}
}
func (r otpSendStoredRecipient) native() kernel.RecipientRecord {
	return kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAt: r.ObservedAt}
}

type passwordOTPSendInput struct {
	Schema                            uint32
	Root                              identity.FeatureCommandSpec
	NativeInput                       []byte
	Factor                            otpSendStoredFactor
	Credential                        otpSendStoredCredential
	PrimaryRecipient                  otpSendStoredRecipient
	AuthorizationVersion              uint64
	ChildIssuedAt, ChildExpiresAt     time.Time
	ChildEnvelopeDigest               [32]byte
	Origin, Callback, Network, Device string
}

func (s *passwordOTPSendState) intent(r mfa.OtpSendRequest) (identity.RequestIntent, error) {
	key := s.config.intentKey()
	defer clear(key[:])
	proof, err := r.Proof.CommandDigest(key, "mfa-otp-login-send-proof-v1", 65536)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("mfa-otp-login-send-cookie-v1\x00"))
	_, _ = mac.Write([]byte(r.Cookie.Token()))
	cookie := mac.Sum(nil)
	defer clear(cookie)
	input, err := json.Marshal(struct {
		Tenant                            identity.TenantID
		Continuation                      mfa.ContinuationID
		Factor                            mfa.FactorID
		Channel                           delivery.Channel
		Flow                              identity.PreAuthTransactionID
		Origin, Callback, Network, Device string
	}{r.TenantID, r.ContinuationID, r.FactorID, r.Channel, r.PreAuthID, r.Origin, r.Callback, r.Network, r.Device})
	if err != nil {
		return identity.RequestIntent{}, invalidPasswordOTPSend()
	}
	defer clear(input)
	mac.Reset()
	_, _ = mac.Write([]byte("mfa-otp-login-send-body-v1\x00"))
	_, _ = mac.Write(input)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "mfa.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}, {Name: "mfa.proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: proof[:]}}, {Name: "mfa.cookie", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: cookie}}, {Name: "mfa.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.identity[:]}}})
}

func (p *passwordOTPSendPhase) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Namespace != p.state.config.RequestKeys.Namespace || k.Scope.RouteID != passwordOTPSendOperation().OperationID || k.Scope.Method != "POST" || k.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: passwordOTPSendOperation()}) || k.PolicyVersion != p.state.config.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.CommandID == "" || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, invalidPasswordOTPSend()
	}
	wire, err := json.Marshal(struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.state.identity})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "reference-password-otp-send-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *passwordOTPSendPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	aad, err := p.inputAAD(k)
	if err != nil {
		return nil, err
	}
	r := p.request
	if k.Scope.TenantID != r.TenantID || k.Scope.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || k.Scope.ActorKind != r.Caller.Request.Subject.Kind {
		return nil, identity.ForbiddenError{}
	}
	input, err := p.captureInput(ctx, k.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	p.input = &input
	defer clear(input.NativeInput)
	p.native, err = p.state.config.Issuance.ReadLoginSend(ctx, mustOTPSendRoot(input.Root, r), input.NativeInput)
	if err != nil {
		return nil, err
	}
	if err = p.buildCommand(); err != nil {
		return nil, err
	}
	root, _ := p.command.Feature()
	input.Root = root
	wire, err := json.Marshal(input)
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	defer clear(wire)
	return p.seal(ctx, aad, wire)
}

// Current source reads are also used for quotas before command allocation.
// No source projection below grants execution or an independent freshness lease.
type passwordOTPCurrentSendSource struct {
	input        passwordOTPSendInput
	primaryID    identity.CommandID
	flow         session.PreAuthTransaction
	continuation mfa.PartialAuthContinuation
	directory    kernel.DirectoryAuthorityAdmission
	recipient    kernel.RecipientRecord
}

func (s *passwordOTPSendState) readSendSource(ctx context.Context, r mfa.OtpSendRequest) (*passwordOTPCurrentSendSource, error) {
	bad := func(err error) (*passwordOTPCurrentSendSource, error) { return nil, err }
	grant, primaryID, _, err := s.issuer.ReadIssuanceOrigin(ctx, s.pool, r.Proof, "identity.mfa.complete")
	if err != nil {
		return bad(err)
	}
	payload := grant.Payload()
	if payload.Issuer != s.config.IssuerURL || payload.Tenant != string(r.TenantID) || payload.ID != string(r.ContinuationID) {
		return bad(identity.ForbiddenError{})
	}
	continuation, err := s.continuation.Read(ctx, grant, s.config.IssuerURL)
	if err != nil {
		return bad(err)
	}
	c, err := continuation.Bindings()
	if err != nil || c.SourcePreAuthID != r.PreAuthID || c.Origin != r.Origin || c.Audience != s.config.Profile.Audience || c.PolicyVersion != s.config.Coordinator.AdmissionPolicy.PolicyVersion || !slices.Contains(c.AllowedMethods, "otp") {
		return bad(identity.ForbiddenError{})
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), s.config.Session, r.TenantID, r.PreAuthID)
	if err != nil {
		return bad(err)
	}
	f, err := flow.Bindings()
	if err != nil || f.Binding.Intent.Origin != r.Origin || f.Binding.Intent.CallbackURL != r.Callback {
		return bad(identity.ForbiddenError{})
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return bad(identity.ForbiddenError{})
	}
	digest, err := token.PreAuthDigest(s.config.CookieKeys[f.Cookie.KeyVersion], f.Binding)
	if err != nil || flow.Check(time.Now().UTC(), f.Binding, digest) != nil {
		return bad(identity.ForbiddenError{})
	}
	primary, err := s.config.Primary.ReadMFAPasswordPrimary(ctx, r.Proof, continuation, flow, r.Caller)
	if err != nil {
		return bad(err)
	}
	if primary.CommandID != primaryID {
		return bad(identity.ForbiddenError{})
	}
	vector, err := primary.Authority.Bindings()
	if err != nil {
		return bad(err)
	}
	snapshot, err := s.factors.Read(ctx, grant, s.config.IssuerURL, string(r.FactorID))
	if err != nil {
		return bad(err)
	}
	meta, err := snapshot.Metadata()
	if err != nil || meta.Channel != r.Channel {
		return bad(identity.ForbiddenError{})
	}
	recipient, err := snapshot.Recipient()
	if err != nil || recipient.User.ID != primary.Recipient.User.ID || recipient.UserAuthorityVersion != vector.User.Version || recipient.IdentifierAuthorityVersion != vector.Identifier.Version || recipient.CredentialAuthorityVersion != vector.Credential.Version {
		return bad(identity.ForbiddenError{})
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.Profile.GlobalAuthorityID, TenantID: r.TenantID})
	if err != nil {
		return bad(err)
	}
	epoch, err := s.policy.Get(ctx, policy.AuthorityScope{TenantID: authorization.TenantID(r.TenantID), SubjectID: authorization.SubjectID(recipient.User.ID), PolicyNamespace: s.config.Profile.PolicyNamespace})
	if err != nil {
		return bad(identity.UnavailableError{})
	}
	if !directory.Enabled || directory.GlobalVersion != vector.Global.Version || directory.TenantVersion != vector.Tenant.Version || epoch.Version != vector.Authorization.Version {
		return bad(identity.ForbiddenError{})
	}
	selected := r.Caller.Clone()
	selected.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(recipient.User.ID)}
	selected.Request.Environment.Time = time.Now().UTC()
	decision, err := s.config.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, selected)
	if err != nil {
		return bad(identity.UnavailableError{})
	}
	if decision.Outcome != authorization.Allow || decision.Revision != selected.PolicyRevision {
		return bad(identity.ForbiddenError{})
	}
	credential := kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(primary.Authentication.CredentialID), TenantID: r.TenantID, UserID: recipient.User.ID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: primary.Authentication.CredentialVersion}, UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version}
	return &passwordOTPCurrentSendSource{primaryID: primaryID, flow: flow, continuation: continuation, recipient: recipient, directory: kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}, input: passwordOTPSendInput{Schema: 1, Factor: otpSendStoredFactor(meta), Credential: otpSendStoredCredential(credential), PrimaryRecipient: storeOTPSendRecipient(primary.Recipient), AuthorizationVersion: epoch.Version, ChildIssuedAt: c.IssuedAt, ChildExpiresAt: c.ExpiresAt, ChildEnvelopeDigest: grant.EnvelopeDigest(), Origin: r.Origin, Callback: r.Callback, Network: r.Network, Device: r.Device}}, nil
}

func (p *passwordOTPSendPhase) captureInput(ctx context.Context, id identity.CommandID) (passwordOTPSendInput, error) {
	bad := func(err error) (passwordOTPSendInput, error) { return passwordOTPSendInput{}, err }
	s, r := p.state, p.request
	source, err := s.readSendSource(ctx, r)
	if err != nil {
		return bad(err)
	}
	c, err := source.continuation.Bindings()
	if err != nil {
		return bad(err)
	}
	f, err := source.flow.Bindings()
	if err != nil {
		return bad(err)
	}
	meta := mfapg.OTPFactorMetadata(source.input.Factor)
	recipient, primaryID := source.recipient, source.primaryID
	var at time.Time
	if err = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return bad(identity.UnavailableError{})
	}
	at = at.UTC().Round(0)
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: passwordOTPSendOperation().OperationID, SchemaID: passwordOTPSendOperation().SchemaID, SchemaVersion: 1, PolicyID: s.config.PolicyID, PolicyVersion: s.config.Coordinator.AdmissionPolicy.PolicyVersion, RecordID: string(r.FactorID), CorrelationID: string(id)}
	root := identity.FeatureCommandSpec{Binding: b, Operation: passwordOTPSendOperation(), Fields: []identity.FeatureField{{Name: "factor.parent-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(primaryID)}}}}
	command, err := identity.NewFeaturePreAuthCommand(root, r.Cookie)
	if err != nil {
		return bad(err)
	}
	authorizationFlow, err := otp.NewMFAFlowAuthorization(source.flow, otp.MFAFlowBinding{PrimaryCommandID: primaryID, ContinuationID: identity.CommandID(c.ID), SubjectID: recipient.User.ID, ScopeDigest: meta.ScopeDigest})
	if err != nil {
		return bad(err)
	}
	destination, err := otp.NewDestinationInput(recipient.Identifier.CanonicalValue)
	if err != nil {
		return bad(err)
	}
	channel := otp.ChannelEmail
	if r.Channel == delivery.ChannelSMS {
		channel = otp.ChannelSMS
	}
	challenge, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(r.TenantID), SubjectID: string(recipient.User.ID), Purpose: otp.PurposeMFA, Channel: channel, Destination: destination, ChallengeID: string(id), TargetID: string(c.ID), PolicyVersion: b.PolicyVersion, Generation: 1}, authorizationFlow, f.Binding.Intent.Remember)
	if err != nil {
		return bad(err)
	}
	native := otppg.MFALoginSendInput{Continuation: challenge, Authority: otppg.AttemptAuthority{Directory: source.directory}, Recipient: recipient, IssuedAt: at, ExpiresAt: c.ExpiresAt}
	wire, err := s.config.Issuance.PrepareLoginSend(ctx, command, native)
	if err != nil {
		return bad(err)
	}
	source.input.Root, source.input.NativeInput = root, wire
	return source.input, nil
}

func (p *passwordOTPSendPhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.inputAAD(k)
	if err != nil {
		return err
	}
	plain, err := p.open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var input passwordOTPSendInput
	if decodePasswordOTPSendJSON(plain, &input) != nil {
		return invalidPasswordOTPSend()
	}
	r := p.request
	b := input.Root.Binding
	if input.Schema != 1 || b.CommandID != k.Admission.CommandID || b.TenantID != r.TenantID || b.AnonymousFlowID != string(r.PreAuthID) || b.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || b.ActorKind != r.Caller.Request.Subject.Kind || b.RecordID != string(r.FactorID) || input.Root.Operation != passwordOTPSendOperation() || b.PolicyID != p.state.config.PolicyID || b.PolicyVersion != p.state.config.Coordinator.AdmissionPolicy.PolicyVersion || input.Origin != r.Origin || input.Callback != r.Callback || input.Network != r.Network || input.Device != r.Device || input.AuthorizationVersion == 0 || input.ChildEnvelopeDigest == ([32]byte{}) || input.PrimaryRecipient.native().Validate() != nil {
		clear(input.NativeInput)
		return identity.ForbiddenError{}
	}
	native, err := p.state.config.Issuance.ReadLoginSend(ctx, mustOTPSendRoot(input.Root, r), input.NativeInput)
	if err != nil {
		clear(input.NativeInput)
		return err
	}
	meta := mfapg.OTPFactorMetadata(input.Factor)
	cont, err := native.Continuation.Bindings()
	if err != nil || meta.TenantID != r.TenantID || meta.UserID != native.Recipient.User.ID || meta.FactorID != string(r.FactorID) || meta.Channel != r.Channel || meta.ContinuationID != r.ContinuationID || cont.Scope.TargetID != string(r.ContinuationID) || meta.ScopeDigest == ([32]byte{}) || meta.ContinuationVersion == 0 || native.ExpiresAt.After(input.ChildExpiresAt) || input.ChildExpiresAt.Sub(input.ChildIssuedAt) > 5*time.Minute {
		clear(input.NativeInput)
		return identity.ForbiddenError{}
	}
	p.input = &input
	p.native = native
	return nil
}
func mustOTPSendRoot(s identity.FeatureCommandSpec, r mfa.OtpSendRequest) identity.Command {
	c, _ := identity.NewFeaturePreAuthCommand(s, r.Cookie)
	return c
}

func (p *passwordOTPSendPhase) seal(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	if ctx == nil || len(plain) == 0 || len(plain) > 65536 {
		return nil, invalidPasswordOTPSend()
	}
	sealed, err := p.state.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, Context: aad, KeyReference: p.state.config.ActiveEnvelopeKeyID})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > 65536 {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	if err = ctx.Err(); err != nil {
		clear(wire)
		return nil, err
	}
	return wire, nil
}
func (p *passwordOTPSendPhase) open(ctx context.Context, aad envelope.Context, wire []byte) ([]byte, error) {
	if ctx == nil || len(wire) == 0 || len(wire) > 65536 {
		return nil, invalidPasswordOTPSend()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	plain, err := p.state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if ctx.Err() != nil {
		clear(plain)
		return nil, ctx.Err()
	}
	if err != nil || len(plain) == 0 || len(plain) > 65536 {
		clear(plain)
		return nil, identity.UnavailableError{}
	}
	return plain, nil
}
func decodePasswordOTPSendJSON(wire []byte, target any) error {
	if len(wire) == 0 || len(wire) > 65536 {
		return invalidPasswordOTPSend()
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return invalidPasswordOTPSend()
	}
	canonical, err := json.Marshal(target)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, wire) {
		return invalidPasswordOTPSend()
	}
	return nil
}

// Exact original projections are compared before a current read can become an
// observation. Repeated checks never replace epochs, recipient or absolute time.
func (p *passwordOTPSendPhase) refreshSource(ctx context.Context) error {
	if p.input == nil {
		return invalidPasswordOTPSend()
	}
	if !p.observedUntil.IsZero() {
		if !time.Now().Before(p.observedUntil) {
			return identity.ForbiddenError{}
		}
		if p.sourceChecked {
			return ctx.Err()
		}
	} else {
		p.observedUntil = time.Now().Add(p.state.config.MaximumDuration)
	}
	current, err := p.captureInput(ctx, p.input.Root.Binding.CommandID)
	if err != nil {
		return err
	}
	defer clear(current.NativeInput)
	if !reflect.DeepEqual(current.Factor, p.input.Factor) || current.Credential != p.input.Credential || current.AuthorizationVersion != p.input.AuthorizationVersion || current.ChildEnvelopeDigest != p.input.ChildEnvelopeDigest || !current.ChildIssuedAt.Equal(p.input.ChildIssuedAt) || !current.ChildExpiresAt.Equal(p.input.ChildExpiresAt) {
		return identity.ForbiddenError{}
	}
	a, b := current.PrimaryRecipient.native(), p.input.PrimaryRecipient.native()
	a.ObservedAt = b.ObservedAt
	if a != b {
		return identity.ForbiddenError{}
	}
	p.sourceChecked = true
	return ctx.Err()
}
