package session

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// PreAuthProviderMode selects the initiating provider's browser delivery mode.
// Zero and unrecognized modes are not provider-bound continuation authority.
type PreAuthProviderMode uint8

// PreAuthProviderCallback selects the One Tap JavaScript callback without a
// redirect URL. Other modes require their own explicit composition.
const PreAuthProviderCallback PreAuthProviderMode = 1

// PreAuthProviderBinding is an exact startup-selected provider, positive
// provider version, client and browser delivery mode. ProviderID and ClientID
// are 1..128 and 1..1024 visible ASCII bytes respectively. Persist only via
// the trusted flow adapter. Configuration matches do not verify a credential.
type PreAuthProviderBinding struct {
	ProviderID      string
	ProviderVersion uint64
	ClientID        string
	Mode            PreAuthProviderMode
}

// ProviderPreAuthTransactionSpec retains all original transaction fields plus
// the selected provider profile. This private projection is not a wire value.
type ProviderPreAuthTransactionSpec struct {
	Transaction PreAuthTransactionSpec
	Provider    PreAuthProviderBinding
}

// NewProviderPreAuthTransaction freezes a validated One Tap callback profile
// without issuing or persisting a flow. It cannot confer primary authority or
// consume a flow. The durable owner must use ProviderBindings and must not
// reconstruct this selected flow from a legacy projection.
func NewProviderPreAuthTransaction(s ProviderPreAuthTransactionSpec) (PreAuthTransaction, error) {
	if !validProviderPreAuthProfile(s.Transaction.Binding.Intent, s.Provider) {
		return PreAuthTransaction{}, ErrInvalidPreAuthTransaction
	}
	p, err := NewPreAuthTransaction(s.Transaction)
	if err != nil {
		return PreAuthTransaction{}, err
	}
	selected := s.Provider
	selected.ProviderID = strings.Clone(selected.ProviderID)
	selected.ClientID = strings.Clone(selected.ClientID)
	p.state.provider = selected
	return p, nil
}

// ProviderBindings returns the full trusted storage projection without
// renewing original evidence. Ordinary flows return ErrInvalidPreAuthTransaction.
func (p PreAuthTransaction) ProviderBindings() (ProviderPreAuthTransactionSpec, error) {
	if p.state == nil || p.state.provider.Mode == 0 {
		return ProviderPreAuthTransactionSpec{}, ErrInvalidPreAuthTransaction
	}
	return ProviderPreAuthTransactionSpec{Transaction: p.state.spec, Provider: p.state.provider}, nil
}

// CheckProvider applies Check's structural and temporal guarantees to the
// exact original provider/client/mode as well. It denies ordinary flows and
// configuration substitution. It does not authenticate or reserve a flow.
func (p PreAuthTransaction) CheckProvider(now time.Time, expected PreAuthBinding, selected PreAuthProviderBinding, cookie TokenDigest) error {
	if p.state == nil || p.state.provider.Mode == 0 || p.state.provider != selected {
		return ErrPreAuthDenied
	}
	return p.state.check(now, expected, cookie)
}

// ProviderPreAuthDigest derives the flow cookie lookup for an original One Tap
// callback. It uses PreAuthDigest's framing with the separate domain
// golib-preauth-cookie-provider-v1 NUL, then appends length-prefixed provider
// ID and client ID, uint64 provider version and uint8 mode before token size
// and bytes. It never issues, verifies, or renews a cookie by itself.
func (t Token) ProviderPreAuthDigest(k DigestKey, binding PreAuthBinding, selected PreAuthProviderBinding) (TokenDigest, error) {
	if t.state == nil {
		return TokenDigest{}, ErrInvalidToken
	}
	if !validProviderPreAuthProfile(binding.Intent, selected) {
		return TokenDigest{}, ErrInvalidPreAuthTransaction
	}
	return t.preAuthDigest(k, binding, selected)
}

func validProviderPreAuthProfile(intent PreAuthIntent, selected PreAuthProviderBinding) bool {
	return selected.Mode == PreAuthProviderCallback && selected.ProviderVersion != 0 &&
		authorityKey(selected.ProviderID, 128) && authorityKey(selected.ClientID, 1024) &&
		intent.Action == "identity.oauth.onetap-start" && intent.Purpose == PreAuthSessionIssuance &&
		intent.CallbackURL == "" && intent.IdentifierBinding == ([32]byte{})
}

// Format redacts the original provider context.
func (PreAuthProviderBinding) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "session.PreAuthProviderBinding(redacted)")
}

// MarshalJSON denies automatic private flow export.
func (PreAuthProviderBinding) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies automatic private flow export.
func (PreAuthProviderBinding) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts the complete original flow context.
func (ProviderPreAuthTransactionSpec) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "session.ProviderPreAuthTransactionSpec(redacted)")
}

// MarshalJSON denies automatic private flow export.
func (ProviderPreAuthTransactionSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrSecretSerialization
}

// MarshalText denies automatic private flow export.
func (ProviderPreAuthTransactionSpec) MarshalText() ([]byte, error) {
	return nil, ErrSecretSerialization
}
