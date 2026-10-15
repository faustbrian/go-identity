package email

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// ManagedVerificationSpec retains the exact authenticated request, original
// session and pending address versions for a delivered management link. Request
// actor/user must be the same human; administration and anonymous signup are
// distinct profiles. Payload.Version is the positive token generation, not a
// directory or session epoch. This metadata is sensitive intent, not admission.
type ManagedVerificationSpec struct {
	Binding                                identity.CommandBinding
	IdentifierID                           identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	Payload                                CapabilityPayload
	IssuedAt, ExpiresAt                    time.Time
	SessionID                              string
	SessionVersion                         uint64
	// ChangeProfile and Previous are mandatory only for change-request. They
	// conserve old notification intent and policy; verification-send forbids them.
	ChangeProfile ChangeProfile
	Previous      PreviousAddress
}

// ManagedVerificationPolicy owns the exact email management issuance shape,
// not signing, original fresh-password authorization, stores or consumption.
// Its immutable copied configuration is concurrent-safe and owns no resources.
// Verification-send links confirm only verification; change-request links
// confirm only change. Neither profile can authorize anonymous signup or login.
type ManagedVerificationPolicy struct {
	state *registrationVerificationPolicy
}

// NewManagedVerificationPolicy reuses the bounded address/issuer/callback/key
// configuration and parser of registration, with a distinct management frame.
// It performs no IO or callbacks. The selected delivered-link profile supports
// whole-second positive lifetimes through 24h; zero configuration denies.
func NewManagedVerificationPolicy(c RegistrationVerificationConfig) (*ManagedVerificationPolicy, error) {
	base, err := NewRegistrationVerificationPolicy(c)
	if err != nil {
		return nil, err
	}
	return &ManagedVerificationPolicy{state: base.state}, nil
}

// Payload builds unsigned original intent with an empty ID for the configured
// capability issuer. It does not authenticate the session, issue a bearer, send
// mail or mutate the directory. The native owner must first authorize fresh
// action-bound proof and conserve this intent through original-command recovery.
func (p *ManagedVerificationPolicy) Payload(s ManagedVerificationSpec) (capability.Payload, error) {
	if p == nil || p.state == nil || s.Binding.SchemaID == "identity.email.verification-send.resend-v1" {
		return capability.Payload{}, ErrInvalidVerification
	}
	return p.payload(s, p.state.current)
}

// PayloadWithSupersession explicitly selects the signed stable mailbox family
// for native add/resend/change issuance. A fresh authorized request gets its own
// command, key-bound intent and times; it cannot escape predecessor invalidation
// by changing callback/session/key/authority metadata. This is unsigned metadata,
// not signing, resend authorization, cooldown, storage or consumption. Native
// issuance must lock this same family before domain rows and commit replacement,
// supersession and encrypted delivery together. Calls own only bounded temporary
// metadata and are concurrent-safe; input remains immutable.
func (p *ManagedVerificationPolicy) PayloadWithSupersession(s ManagedVerificationSpec) (capability.Payload, error) {
	if p == nil || p.state == nil {
		return capability.Payload{}, ErrInvalidVerification
	}
	payload, err := p.payload(s, p.state.current)
	if err != nil {
		return capability.Payload{}, err
	}
	return managedPayloadSupersession(payload)
}

// Version-one metadata tuple is independently checked by the capability-owned
// adapter. It contains no raw mailbox or bearer and is not a signature authority.
func managedPayloadSupersession(payload capability.Payload) (capability.Payload, error) {
	wire, err := json.Marshal([]string{payload.Issuer, payload.Audiences[0], payload.Tenant, payload.Subject, payload.Resource, payload.Operation, payload.Caveats["email.confirm_operation"]})
	if err != nil {
		return capability.Payload{}, ErrInvalidVerification
	}
	digest := sha256.Sum256(append([]byte("golib.capability.managed-email.supersession.v1\x00"), wire...))
	payload.Caveats["email.supersession"] = hex.EncodeToString(digest[:])
	return payload, nil
}

func (p *ManagedVerificationPolicy) payload(s ManagedVerificationSpec, version uint32) (capability.Payload, error) {
	if p == nil || p.state == nil || p.state.keys[version] == ([32]byte{}) {
		return capability.Payload{}, ErrInvalidVerification
	}
	var confirm string
	switch s.Binding.OperationID {
	case "identity.email.verification-send":
		confirm = "identity.email.verification-confirm"
	case "identity.email.change-request":
		confirm = "identity.email.change-confirm"
	default:
		return capability.Payload{}, ErrInvalidVerification
	}
	var previousFrame []string
	if confirm == "identity.email.change-confirm" {
		old := s.Previous
		parsed, err := p.state.parser.Parse(AddressInput(old.CanonicalAddress))
		if s.ChangeProfile.Validate() != nil || !verificationID(string(old.ID)) || old.ID == s.IdentifierID || old.IdentifierVersion == 0 || old.IdentifierVersion == math.MaxUint64 || old.VerificationVersion == 0 || old.VerificationVersion == math.MaxUint64 || len(old.CanonicalAddress) > 254 || err != nil || parsed.Canonical().Record().Value != old.CanonicalAddress || !old.Primary && s.ChangeProfile.CurrentAddress == RequirePrimaryAddress || old.CanonicalAddress == s.Payload.CanonicalAddress.Record().Value {
			return capability.Payload{}, ErrInvalidVerification
		}
		previousFrame = []string{string(old.ID), old.CanonicalAddress, strconv.FormatUint(old.IdentifierVersion, 10), strconv.FormatUint(old.VerificationVersion, 10), strconv.FormatBool(old.Primary), strconv.FormatUint(uint64(s.ChangeProfile.CurrentAddress), 10), strconv.FormatUint(uint64(s.ChangeProfile.Sessions), 10)}
	} else if s.ChangeProfile != (ChangeProfile{}) || s.Previous != (PreviousAddress{}) {
		return capability.Payload{}, ErrInvalidVerification
	}
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: s.Binding.OperationID, SchemaID: s.Binding.OperationID + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if s.Binding.OperationID == "identity.email.verification-send" && s.Binding.SchemaID == "identity.email.verification-send.resend-v1" {
		op.SchemaID = s.Binding.SchemaID
	}
	redirect, valid := verificationURL(&s.Payload.Redirect, 2048)
	if !valid || s.Binding.ValidateFor(op) != nil || s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) || string(s.Binding.UserID) != string(s.Payload.SubjectID) || s.Binding.RecordID != string(s.IdentifierID) || s.Binding.TenantID != s.Payload.TenantID || !verificationID(string(s.IdentifierID)) || !verificationID(s.SessionID) || s.SessionVersion == 0 || s.SessionVersion == math.MaxUint64 || s.IdentifierVersion == 0 || s.IdentifierVersion == math.MaxUint64 || s.VerificationVersion == 0 || s.VerificationVersion == math.MaxUint64 || s.Payload.Version == 0 || s.Payload.Purpose != "identity.identifier.verify" || !p.state.redirect[redirect] || s.IssuedAt.IsZero() || s.IssuedAt.Unix() <= 0 || s.IssuedAt.Nanosecond() != 0 || s.ExpiresAt.Nanosecond() != 0 || s.ExpiresAt.UTC().Year() > 9999 || !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > p.state.lifetime {
		return capability.Payload{}, ErrInvalidVerification
	}
	record := s.Payload.CanonicalAddress.Record()
	if len(record.Value) > 254 {
		return capability.Payload{}, ErrInvalidVerification
	}
	address, err := p.state.parser.Parse(AddressInput(record.Value))
	if err != nil || !address.Canonical().Equal(s.Payload.CanonicalAddress) {
		return capability.Payload{}, ErrInvalidVerification
	}
	key := p.state.keys[version]
	h := hmac.New(sha256.New, key[:])
	_, _ = io.WriteString(h, "golib.identity.email.managed-verification.v1\x00")
	// Frame exact versioned mailbox and original actor/session intent. These are
	// keyed commitments, not public address hashes or a second proof authority.
	frame := []string{string(s.Binding.TenantID), string(s.Binding.UserID), string(s.IdentifierID), record.Value, string(record.ProfileID), strconv.FormatUint(uint64(record.ProfileVersion), 10), string(s.Payload.Purpose), redirect, strconv.FormatUint(s.Payload.Version, 10), strconv.FormatUint(s.IdentifierVersion, 10), strconv.FormatUint(s.VerificationVersion, 10), string(s.Binding.CommandID), s.Binding.OperationID, s.Binding.SchemaID, strconv.FormatUint(uint64(s.Binding.SchemaVersion), 10), string(s.Binding.ActorID), string(s.Binding.ActorKind), string(s.Binding.PolicyID), strconv.FormatUint(s.Binding.PolicyVersion, 10), s.Binding.CorrelationID, s.SessionID, strconv.FormatUint(s.SessionVersion, 10)}
	for _, value := range append(frame, previousFrame...) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = h.Write(length[:])
		_, _ = io.WriteString(h, value)
	}
	return capability.Payload{Version: 1, Issuer: p.state.issuer, Audiences: []string{p.state.audience}, Subject: string(s.Payload.SubjectID), Resource: string(s.IdentifierID), Operation: string(s.Payload.Purpose), Tenant: string(s.Payload.TenantID), CorrelationID: s.Binding.CorrelationID, IssuedAt: s.IssuedAt.UTC(), NotBefore: s.IssuedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(), MaxUses: 1, Caveats: map[string]string{"email.confirm_operation": confirm, "email.profile": "management-v1", "email.intent": hex.EncodeToString(h.Sum(nil)), "email.binding_key_version": strconv.FormatUint(uint64(version), 10)}}, nil
}

// Authorize matches a cryptographically authenticated grant to immutable
// original intent and exclusive expiry. It performs no IO, current-state check,
// renewal or one-time consumption. Confirmation must separately repeat current
// primary/factor/policy admission and atomically consume through existing owners.
func (p *ManagedVerificationPolicy) Authorize(grant capability.Grant, s ManagedVerificationSpec, now time.Time) error {
	g := grant.Payload()
	version, err := strconv.ParseUint(g.Caveats["email.binding_key_version"], 10, 32)
	expected, shapeErr := p.payload(s, uint32(version))
	if _, selected := g.Caveats["email.supersession"]; selected && shapeErr == nil {
		expected, shapeErr = managedPayloadSupersession(expected)
	} else if s.Binding.SchemaID == "identity.email.verification-send.resend-v1" {
		return ErrInvalidVerification
	}
	if err != nil || shapeErr != nil || !verificationID(g.ID) || now.IsZero() || now.Before(g.NotBefore) || !now.Before(g.ExpiresAt) || g.Version != 1 || g.Issuer != expected.Issuer || g.Bearer || g.MaxUses != 1 || len(g.Audiences) != 1 || len(g.Caveats) != len(expected.Caveats) || !g.IssuedAt.Equal(expected.IssuedAt) || !g.NotBefore.Equal(expected.NotBefore) || !g.ExpiresAt.Equal(expected.ExpiresAt) || g.CorrelationID != expected.CorrelationID {
		return ErrInvalidVerification
	}
	if grant.Authorize(capability.Use{Issuer: expected.Issuer, Audience: p.state.audience, Subject: expected.Subject, Resource: expected.Resource, Operation: expected.Operation, Tenant: expected.Tenant, Caveats: expected.Caveats}) != nil {
		return ErrInvalidVerification
	}
	return nil
}

// Format omits original mailbox, session and request correlation.
func (ManagedVerificationSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ManagedVerificationSpec(redacted)")
}

// MarshalJSON denies implicit sensitive intent export.
func (ManagedVerificationSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit sensitive text or map-key export.
func (ManagedVerificationSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured diagnostics.
func (ManagedVerificationSpec) LogValue() slog.Value {
	return slog.StringValue("email.ManagedVerificationSpec(redacted)")
}

// Format omits copied parser and cryptographic configuration.
func (ManagedVerificationPolicy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "email.ManagedVerificationPolicy(redacted)")
}

// MarshalJSON denies implicit private policy export.
func (ManagedVerificationPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit private policy export.
func (ManagedVerificationPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue redacts structured policy diagnostics.
func (ManagedVerificationPolicy) LogValue() slog.Value {
	return slog.StringValue("email.ManagedVerificationPolicy(redacted)")
}
