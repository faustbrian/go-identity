package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type phoneSigninProfile struct {
	policy        *phone.NumberPolicy
	identifierKey [32]byte
	configuration [32]byte
}

func (p *phoneSigninProfile) requireOriginalTarget(ctx context.Context, tenant identity.TenantID, r sendInitiatingRequest, flow session.PreAuthBinding) error {
	if p == nil || p.policy == nil || tenant != flow.Intent.TenantID ||
		r.userID != "" || r.flowKind != otp.FlowAuthorizationPreAuthTransaction ||
		r.purpose != otp.PurposeSignin || r.channel != otp.ChannelSMS ||
		r.target != "identity.phone.signin" || flow.Intent.Action != "identity.phone.signin" ||
		flow.Intent.IdentifierBinding == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	number, err := p.policy.Canonicalize(ctx, r.destination.Value())
	if err != nil {
		return identity.ForbiddenError{}
	}
	record, err := number.Record()
	if err != nil || record.E164 != r.destination.Value() {
		return identity.ForbiddenError{}
	}
	want, err := phone.OTPSigninIdentifierBinding(number, tenant, p.identifierKey[:])
	if err != nil || !hmac.Equal(want[:], flow.Intent.IdentifierBinding[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}

// PhoneSigninConfig selects one existing-account SMS-code signin profile over
// the ordinary native OTP and session owners. Send must use PurposeSignin,
// pre-auth action identity.phone.signin, no authenticated-session selection and
// consuming-only code policy. Its IdentifierKey derives the original canonical
// target commitment as well as separate domain-bound risk attribution. Policy
// is immutable borrowed number policy. Signin always enforces the actual native
// known-empty factor generation; caller policy cannot disable that fence.
// Install selected native histories before Initialize/use. No field enables
// signup, password login, MFA continuation, HTTP or automatic migrations.
type PhoneSigninConfig struct {
	Policy *phone.NumberPolicy
	Send   SendConfig
	Signin SigninConfig
}

// PhoneSigninService composes phone canonical scope with native OTP issuance,
// attempts, encrypted SMS delivery and atomic session effects. It borrows the
// pool/envelope/policies, starts no goroutine and owns no second transaction,
// store or journal. Calls are concurrent-safe and bounded by original context
// and Send.Timeout. The configured owners must outlive calls; zero denies.
type PhoneSigninService struct {
	sender  *SendService
	signin  *SigninService
	profile *phoneSigninProfile
}

var _ phone.SigninService = (*PhoneSigninService)(nil)
var _ otp.SigninSourceService = (*PhoneSigninService)(nil)

// NewPhoneSigninService freezes pure native composition without SQL, entropy,
// callbacks or provider access. Dependencies are genuine native owners, not
// application-supplied workflow implementations. Native factor, exact stored
// profile and original target checks remain mandatory inside the actual path.
func NewPhoneSigninService(pool *database.Pool, c PhoneSigninConfig, crypto *envelope.Service) (*PhoneSigninService, error) {
	policy, checks, err := c.Send.Policy.Bindings()
	if err != nil || policy.Purpose != otp.PurposeSignin || checks.Enabled || c.Policy == nil ||
		c.Policy.Profile() != phone.CurrentNumberProfile() || c.Send.Session != nil ||
		c.Send.PreAuthAction != "identity.phone.signin" || c.Send.IdentifierKey == ([32]byte{}) {
		return nil, ErrInvalidConfiguration
	}
	profile := c.Policy.Profile()
	frame := []byte("identity-phone-otp-signin-configuration-v1\x00")
	for _, text := range []string{profile.ID, profile.MetadataVersion} {
		frame = appendAuthorityText(frame, text)
	}
	frame = binary.BigEndian.AppendUint32(frame, profile.Version)
	frame = append(frame, c.Send.IdentifierKey[:]...)
	p := &phoneSigninProfile{policy: c.Policy, identifierKey: c.Send.IdentifierKey, configuration: sha256.Sum256(frame)}
	clear(frame)
	sender, err := newSendService(pool, c.Send, crypto, nil, nil, p)
	if err != nil {
		return nil, err
	}
	c.Signin.RequireKnownEmptyFactors = true
	signin, err := NewSigninService(sender, c.Signin)
	if err != nil {
		return nil, err
	}
	return &PhoneSigninService{sender: sender, signin: signin, profile: p}, nil
}

// Initialize binds retained OTP key metadata, not schema, accounts, phones or
// factor authority. Exact startup retry is idempotent; unknown startup denies
// until an identical retry reconciles. The borrowed pool remains caller-owned.
func (s *PhoneSigninService) Initialize(ctx context.Context) error {
	if s == nil || s.sender == nil {
		return ErrInvalidConfiguration
	}
	return s.sender.Initialize(ctx)
}

// SendSignin preserves the phone owner's canonical number and original public
// pre-auth flow. Acceptance is enumeration-safe queued/suppressed status, never
// proof of a recipient, delivery, ownership or authentication. Native preparation
// compares the original target before recipient discovery and risk/code work.
func (s *PhoneSigninService) SendSignin(ctx context.Context, request phone.SigninSendRequest) (otp.SendResult, error) {
	if s == nil || s.sender == nil || s.profile == nil {
		return otp.SendResult{}, ErrInvalidCommand
	}
	r, err := request.Bindings()
	if err != nil {
		return otp.SendResult{}, err
	}
	record, err := r.Number.Record()
	if err != nil || record.Profile != s.profile.policy.Profile() {
		return otp.SendResult{}, identity.ForbiddenError{}
	}
	destination, err := otp.NewDestinationInput(record.E164)
	if err != nil {
		return otp.SendResult{}, ErrInvalidCommand
	}
	return s.sender.Send(ctx, otp.SendRequest{TenantID: r.TenantID, Caller: r.Caller, Flow: r.Flow,
		Channel: otp.ChannelSMS, Destination: destination, Purpose: otp.PurposeSignin,
		TargetID: "identity.phone.signin", Network: r.Network, Device: r.Device, IdempotencyKey: r.IdempotencyKey})
}

// ResolveSigninSource authenticates original phone SendSignin and pre-auth
// possession for trusted transport rate admission. It returns only the native
// owner's retained SMS destination, never caller-selected discovery input or
// clearance. Current phone/account/factor authority is required. No code is
// compared, attempt charged, command reserved or credential issued; Signin
// independently checks and consumes. Do not expose this as a discovery route.
func (s *PhoneSigninService) ResolveSigninSource(ctx context.Context, request otp.SigninSourceRequest) (otp.SigninSource, error) {
	if s == nil || s.signin == nil || request.UserID != "" || request.Caller.Request.Action != "identity.phone.signin" {
		return otp.SigninSource{}, identity.ForbiddenError{}
	}
	return s.signin.ResolveSigninSource(ctx, request)
}

// Signin is one new code submission against the original phone SendSignin.
// It never accepts a password or caller-selected remember/user identity. Only
// exact fresh commitment can deliver session/CSRF custody; ambiguity requires
// RecoverSignin with the original returned correlation and no code retry.
func (s *PhoneSigninService) Signin(ctx context.Context, request otp.SigninRequest) (otp.SigninResult, error) {
	if s == nil || s.signin == nil || request.UserID != "" || request.Caller.Request.Action != "identity.phone.signin" {
		return otp.SigninResult{}, identity.ForbiddenError{}
	}
	return s.signin.Signin(ctx, request)
}

// RecoverSignin observes original history under current disclosure policy and
// original flow possession. It never compares a code, creates another attempt,
// renews custody or redelivers a session, synchronizer or SMS.
func (s *PhoneSigninService) RecoverSignin(ctx context.Context, request otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	if s == nil || s.signin == nil || request.UserID != "" || request.Caller.Request.Action != "identity.phone.signin.recover" {
		return otp.SigninResult{}, identity.ForbiddenError{}
	}
	return s.signin.RecoverSignin(ctx, request)
}

// Format redacts borrowed native configuration for every verb.
func (*PhoneSigninService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneSigninService(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (*PhoneSigninService) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit configuration export and map-key use.
func (*PhoneSigninService) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts deployment keys and configuration for every verb.
func (PhoneSigninConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneSigninConfig(redacted)"))
}

// MarshalJSON denies implicit export of deployment keys.
func (PhoneSigninConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit export of deployment keys or map-key use.
func (PhoneSigninConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
