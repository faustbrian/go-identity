package session

import (
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// PreAuthProviderMode selects the initiating provider's browser delivery mode.
// Zero and unrecognized modes are not provider-bound continuation authority.
type PreAuthProviderMode uint8

const (
	// PreAuthProviderCallback selects the One Tap JavaScript callback without a
	// redirect URL.
	PreAuthProviderCallback PreAuthProviderMode = 1
	// PreAuthProviderRedirect selects the separately configured One Tap button
	// redirect and its exact same-origin HTTPS endpoint. It is not an issuer.
	PreAuthProviderRedirect PreAuthProviderMode = 2
)

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

// NewProviderPreAuthTransaction freezes a validated One Tap browser profile
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

// ProviderPreAuthDigest derives the original One Tap flow cookie lookup. It
// uses PreAuthDigest's framing with the separate domain
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
	if selected.ProviderVersion == 0 || !authorityKey(selected.ProviderID, 128) || !authorityKey(selected.ClientID, 1024) ||
		intent.Action != "identity.oauth.onetap-start" || intent.Purpose != PreAuthSessionIssuance || intent.IdentifierBinding != ([32]byte{}) {
		return false
	}
	switch selected.Mode {
	case PreAuthProviderCallback:
		return intent.CallbackURL == ""
	case PreAuthProviderRedirect:
		return validOneTapRedirectTarget(intent.Origin, intent.CallbackURL)
	default:
		return false
	}
}

// A browser must serialize the same literal origin and path that bind the
// original cookie. This stricter rule is only for the new redirect mode.
func validOneTapRedirectTarget(origin, callback string) bool {
	endpoint, exact := strings.CutPrefix(callback, origin)
	if !exact || !strings.HasPrefix(origin, "https://") || !preAuthURL(origin, true) || !preAuthURL(callback, false) ||
		!strings.HasPrefix(endpoint, "/") || path.Clean(endpoint) != endpoint || strings.ContainsAny(endpoint, "%?#\\;") ||
		(&url.URL{Path: endpoint}).EscapedPath() != endpoint {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host != strings.ToLower(u.Host) {
		return false
	}
	host, port := u.Hostname(), u.Port()
	if len(host) > 253 || port == "" && u.Host != host {
		return false
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || n == 443 || strconv.FormatUint(n, 10) != port || u.Host != host+":"+port {
			return false
		}
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	// Browsers treat a final numeric label as an IPv4 candidate, including
	// hexadecimal and short forms. Only the canonical dotted address is valid.
	last := host[strings.LastIndexByte(host, '.')+1:]
	if hex, prefixed := strings.CutPrefix(last, "0x"); strings.Trim(last, "0123456789") == "" ||
		prefixed && strings.Trim(hex, "0123456789abcdef") == "" {
		addr, err := netip.ParseAddr(host)
		return err == nil && addr.Is4() && addr.String() == host
	}
	return true
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
