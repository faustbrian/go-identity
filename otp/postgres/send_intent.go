package postgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	auth "github.com/faustbrian/go-authentication"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// This private composition profile binds configuration, not current authority.
// The two dedicated keys must not be reused for lookup, envelope or risk keys.
type sendInitiationConfig struct {
	policyID, preAuthAction  string
	policyVersion            uint64
	intentKey, identifierKey [32]byte
	maximumDuration          time.Duration
}

func (sendInitiationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.sendInitiationConfig(redacted)"))
}

type sendInitiationProfile struct {
	config        sendInitiationConfig
	configuration [32]byte
	pool          *database.Pool
	kernel        *kernel.Repository
	authorization *authoritypg.AuthorityStore
	sessions      *sessionpg.Repository
}

func (sendInitiationProfile) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.sendInitiationProfile(redacted)"))
}

func newSendInitiationProfile(base [32]byte, c sendInitiationConfig) (*sendInitiationProfile, error) {
	if !initiationText(c.policyID, 128) || !initiationText(c.preAuthAction, 128) || c.policyVersion == 0 || c.intentKey == ([32]byte{}) || c.identifierKey == ([32]byte{}) || c.intentKey == c.identifierKey || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	frame := append([]byte("identity-otp-native-initiation-configuration-v1\x00"), base[:]...)
	frame = appendAuthorityText(frame, c.policyID)
	frame = appendAuthorityText(frame, c.preAuthAction)
	frame = binary.BigEndian.AppendUint64(frame, c.policyVersion)
	frame = binary.BigEndian.AppendUint64(frame, uint64(c.maximumDuration))
	// Key identities are retained only inside a domain-separated configuration
	// digest. A rotation changes request intent without exporting key material.
	frame = append(frame, c.intentKey[:]...)
	frame = append(frame, c.identifierKey[:]...)
	digest := sha256.Sum256(frame)
	clear(frame)
	return &sendInitiationProfile{config: c, configuration: digest}, nil
}

// Trusted owners canonicalize destination and network before construction.
// User selection remains explicit; recipient resolution cannot change it.
type sendInitiatingRequest struct {
	userID                  identity.UserID
	flowKind                otp.FlowAuthorizationKind
	flowID                  string
	purpose                 otp.Purpose
	channel                 otp.Channel
	destination             otp.DestinationInput
	target, network, device string
}

func (sendInitiatingRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.sendInitiatingRequest(redacted)"))
}

func (r sendInitiatingRequest) valid() bool {
	if r.userID != "" && !initiationText(string(r.userID), 128) || !initiationText(r.flowID, 128) || !initiationText(r.target, 256) || !initiationText(r.device, 128) {
		return false
	}
	if _, err := otp.NewDestinationInput(r.destination.Value()); err != nil {
		return false
	}
	address, err := netip.ParseAddr(r.network)
	if err != nil || address.Zone() != "" || address.String() != r.network {
		return false
	}
	if r.channel != otp.ChannelEmail && r.channel != otp.ChannelSMS {
		return false
	}
	switch r.purpose {
	case otp.PurposeSignin, otp.PurposeEmailVerification, otp.PurposePasswordReset, otp.PurposeEmailChange, otp.PurposeMFA, otp.PurposeStepUp:
	default:
		return false
	}
	switch r.flowKind {
	case otp.FlowAuthorizationPreAuthTransaction:
		_, err = identity.ParsePreAuthTransactionID(r.flowID)
		return err == nil
	case otp.FlowAuthorizationAuthenticatedSession:
		if r.userID == "" {
			return false
		}
		for _, c := range []byte(r.flowID) {
			if c < 33 || c > 126 {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// A commitment correlates possession input; it does not authenticate the
// bearer. Restoration must independently verify the separately submitted
// credential against the complete original session/pre-auth record.
func (p *Contributor) sendRequestIntent(r sendInitiatingRequest, bearer auth.BearerCredential) (identity.RequestIntent, error) {
	if p == nil || p.send == nil || p.initiation == nil || !r.valid() {
		return identity.RequestIntent{}, ErrInvalidCommand
	}
	if _, err := session.ParseToken(bearer.Token()); err != nil {
		return identity.RequestIntent{}, ErrInvalidCommand
	}
	m := hmac.New(sha256.New, p.initiation.config.intentKey[:])
	_, _ = m.Write([]byte("identity-otp-initiating-bearer-v1\x00"))
	_, _ = m.Write([]byte(bearer.Token()))
	commitment := m.Sum(nil)
	defer clear(commitment)
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	return identity.NewRequestIntent([]identity.FeatureField{
		text("subject.user", string(r.userID)), text("flow.id", r.flowID),
		{Name: "flow.kind", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(r.flowKind)}},
		text("purpose", string(r.purpose)), text("channel", string(r.channel)),
		text("destination", r.destination.Value()), text("target", r.target),
		text("risk.network", r.network), text("risk.device", r.device),
		{Name: "bearer.commitment", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: commitment}},
		{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.initiation.configuration[:]}},
	})
}

func (p *Contributor) readSendRequestIntent(intent identity.RequestIntent) (sendInitiatingRequest, error) {
	bad := func() (sendInitiatingRequest, error) { return sendInitiatingRequest{}, ErrInvalidCommand }
	if p == nil || p.send == nil || p.initiation == nil {
		return bad()
	}
	fields, ok := intent.Fields()
	if !ok || len(fields) != 11 {
		return bad()
	}
	var r sendInitiatingRequest
	for _, field := range fields {
		v := field.Value
		switch field.Name {
		case "flow.kind":
			if v.Kind != identity.FeatureUint64 || v.Uint64 < 1 || v.Uint64 > 2 {
				return bad()
			}
			r.flowKind = otp.FlowAuthorizationKind(v.Uint64)
		case "configuration":
			if v.Kind != identity.FeatureBytes || !hmac.Equal(v.Bytes, p.initiation.configuration[:]) {
				return bad()
			}
		case "bearer.commitment":
			if v.Kind != identity.FeatureBytes || len(v.Bytes) != sha256.Size {
				return bad()
			}
			var nonzero byte
			for _, b := range v.Bytes {
				nonzero |= b
			}
			if nonzero == 0 {
				return bad()
			}
		default:
			if v.Kind != identity.FeatureText {
				return bad()
			}
			switch field.Name {
			case "subject.user":
				r.userID = identity.UserID(v.Text)
			case "flow.id":
				r.flowID = v.Text
			case "purpose":
				r.purpose = otp.Purpose(v.Text)
			case "channel":
				r.channel = otp.Channel(v.Text)
			case "destination":
				var err error
				r.destination, err = otp.NewDestinationInput(v.Text)
				if err != nil {
					return bad()
				}
			case "target":
				r.target = v.Text
			case "risk.network":
				r.network = v.Text
			case "risk.device":
				r.device = v.Text
			default:
				return bad()
			}
		}
	}
	if !r.valid() {
		return bad()
	}
	return r, nil
}
