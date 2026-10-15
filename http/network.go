package identityhttp

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	identityidentifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
)

// NetworkRealm distinguishes an explicitly allowed public host from a tenant
// host. Zero is invalid; absence of a tenant never implies public admission.
type NetworkRealm uint8

const (
	// RealmPublic admits only an explicitly allowlisted public host.
	RealmPublic NetworkRealm = iota + 1
	// RealmTenant admits only a host bound to one configured tenant.
	RealmTenant
)

// TenantHost binds one exact canonical host to a tenant. Host has no port;
// DNS names are lowercase UTS46 ASCII, IPv4 is canonical dotted decimal and
// IPv6 is canonical bracketed text. Noncanonical configuration is rejected,
// not silently merged. TenantID is nonempty, case-sensitive and <=128 UTF-8 bytes.
type TenantHost struct {
	Host     string
	TenantID identity.TenantID
}

// NetworkConfig is copied by NewNetworkResolver. Limits are all explicit.
// MaximumForwardedHops is 1..16 (reference composition selects 8). At most 128
// distinct canonical masked proxy prefixes and 1024 total exact host bindings
// are accepted. Empty prefixes trust none; overlaps are an explicit set union.
// At least one tenant or public binding is required. Public and tenant hosts
// must not overlap; there is no suffix, wildcard or unknown-host fallback.
// Reloading means constructing/replacing a complete validated snapshot.
type NetworkConfig struct {
	Limits               Limits
	TrustedProxyCIDRs    []netip.Prefix
	MaximumForwardedHops uint8
	TenantHosts          []TenantHost
	PublicHosts          []string
}

// NetworkResolver owns immutable copied deployment policy. Zero is invalid.
// Independent requests may resolve concurrently; callers must not mutate a
// request during resolution. No DNS, body reads, callbacks or goroutines occur.
type NetworkResolver struct {
	decoder *RequestDecoder
	profile identityidentifier.NormalizationProfile
	proxies []netip.Prefix
	maxHops int
	hosts   map[string]networkBinding
}

type networkBinding struct {
	realm  NetworkRealm
	tenant identity.TenantID
}

// NetworkFacts is an immutable resolved snapshot, not an authentication proof.
// Zero cannot admit a realm. Only Resolve constructs a valid value; copies
// preserve it. Ordinary formatting/logging is redacted and serialization denied.
// Explicit getters disclose validated network/tenant metadata to trusted code.
// Facts do not bind an arbitrary future request: routing must resolve once for
// its own request and must not accept caller-submitted or cached facts as input.
type NetworkFacts struct {
	client           netip.Addr
	host, authority  string
	scheme           string
	binding          networkBinding
	forwarded, valid bool
}

// Valid reports successful resolution, not authentication or future validity.
func (f NetworkFacts) Valid() bool { return f.valid }

// ClientIP returns the full canonical unicast address; mapped IPv6 is unmapped.
func (f NetworkFacts) ClientIP() netip.Addr { return f.client }

// Host returns the canonical exact host-map key without a port.
func (f NetworkFacts) Host() string { return f.host }

// Authority returns canonical host and any explicit validated decimal port.
func (f NetworkFacts) Authority() string { return f.authority }

// Scheme returns http/https selected from actual TLS or the trusted boundary.
func (f NetworkFacts) Scheme() string { return f.scheme }

// Realm returns an explicit public or tenant discriminator, or zero if invalid.
func (f NetworkFacts) Realm() NetworkRealm { return f.binding.realm }

// TenantID returns the mapped tenant only for RealmTenant; public/zero is empty.
func (f NetworkFacts) TenantID() identity.TenantID { return f.binding.tenant }

// Forwarded reports successful trusted-chain selection, not arbitrary headers.
func (f NetworkFacts) Forwarded() bool { return f.forwarded }

// Origin returns canonical effective origin, omitting the scheme's default port.
func (f NetworkFacts) Origin() string {
	if !f.valid {
		return ""
	}
	authority := f.authority
	if f.scheme == "https" && authority == f.host+":443" || f.scheme == "http" && authority == f.host+":80" {
		authority = f.host
	}
	return f.scheme + "://" + authority
}

// Format redacts network and tenant metadata for every diagnostic verb.
func (NetworkFacts) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identityhttp.NetworkFacts(redacted)")
}

// LogValue redacts network and tenant metadata in ordinary structured logs.
func (NetworkFacts) LogValue() slog.Value {
	return slog.StringValue("identityhttp.NetworkFacts(redacted)")
}

// MarshalJSON rejects implicit projection of internal network/tenant facts.
func (NetworkFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText rejects implicit text/map-key projection of internal facts.
func (NetworkFacts) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// NewNetworkResolver validates/copies one complete policy without IO. Invalid
// bounds, noncanonical prefixes/hosts, duplicate/overlapping host bindings and
// invalid tenants return redacted ErrInvalidInput. Prefix overlap is harmless
// explicit union; duplicate or IPv4-mapped prefixes are rejected as ambiguous.
// Host normalization reuses identifier's fixed Unicode15.1 nontransitional
// UTS46 implementation under identity.http.host.uts46-15.1/version1.
func NewNetworkResolver(config NetworkConfig) (*NetworkResolver, error) {
	decoder, err := NewRequestDecoder(config.Limits)
	if err != nil || config.MaximumForwardedHops < 1 || config.MaximumForwardedHops > 16 || len(config.TrustedProxyCIDRs) > 128 || len(config.TenantHosts) > 1024 || len(config.PublicHosts) > 1024 || len(config.TenantHosts)+len(config.PublicHosts) == 0 || len(config.TenantHosts)+len(config.PublicHosts) > 1024 {
		return nil, ErrInvalidInput
	}
	profile, err := identityidentifier.NewNormalizationProfile(identityidentifier.NormalizationProfileSpec{
		ID: "identity.http.host.uts46-15.1", Version: 1,
		Unicode: identityidentifier.UnicodeNormalizationNone, IDNA: true, MaximumBytes: 253,
	})
	if err != nil {
		return nil, ErrInvalidInput
	}
	resolver := &NetworkResolver{decoder: decoder, profile: profile, proxies: slices.Clone(config.TrustedProxyCIDRs), maxHops: int(config.MaximumForwardedHops), hosts: make(map[string]networkBinding)}
	seen := make(map[netip.Prefix]bool)
	for _, prefix := range resolver.proxies {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || seen[prefix] {
			return nil, ErrInvalidInput
		}
		seen[prefix] = true
	}
	for _, binding := range config.TenantHosts {
		if !networkTenant(binding.TenantID) || !resolver.addHost(binding.Host, networkBinding{realm: RealmTenant, tenant: binding.TenantID}) {
			return nil, ErrInvalidInput
		}
	}
	for _, host := range config.PublicHosts {
		if !resolver.addHost(host, networkBinding{realm: RealmPublic}) {
			return nil, ErrInvalidInput
		}
	}
	return resolver, nil
}

func networkTenant(tenant identity.TenantID) bool {
	if len(tenant) == 0 || len(tenant) > 128 || !utf8.ValidString(string(tenant)) {
		return false
	}
	for _, r := range tenant {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (n *NetworkResolver) addHost(raw string, binding networkBinding) bool {
	host, authority, ok := n.authority(raw)
	if !ok || raw != host || authority != host {
		return false
	}
	if _, exists := n.hosts[host]; exists {
		return false
	}
	n.hosts[strings.Clone(host)] = binding
	return true
}

// Resolve bounds/validates the parsed request envelope before deriving facts.
// An untrusted socket peer ignores all forwarding semantics and uses Host/TLS.
// A trusted peer requires one Forwarded field/value, fully validated under the
// closed RFC7239 subset (at most 16 parameters per element, concrete for/by,
// no empty pairs/elements or whitespace around '=', unique case-insensitive
// names, token/quoted values; unknown extensions are syntax-only), then walks
// right-to-left to the first
// untrusted for-address. Its trusted sender's element supplies BOTH host/proto;
// no direct fallback or left-of-boundary field borrowing is permitted.
// X-Forwarded-* never supplies facts. Invalid peer/chain or exhausted trusted
// chain returns ErrUnavailable; invalid envelope/unknown host returns DecodeError.
// Cancellation preserves the context error. Every failure returns zero facts.
// RemoteAddr/Host/TLS/header custody belongs to server/trusted composition:
// arbitrary in-process requests or middleware mutations cannot prove provenance.
func (n *NetworkResolver) Resolve(r *http.Request) (NetworkFacts, error) {
	facts, err := n.resolve(r)
	if err != nil {
		return NetworkFacts{}, err
	}
	if facts.binding.realm == 0 {
		return NetworkFacts{}, DecodeError{}
	}
	return facts, nil
}

// Preserve unknown-host classification for the router without changing
// Resolve's public zero-facts/DecodeError contract or repeating proxy parsing.
func (n *NetworkResolver) resolve(r *http.Request) (NetworkFacts, error) {
	var zero NetworkFacts
	if n == nil || n.decoder == nil || r == nil {
		return zero, ErrInvalidInput
	}
	if err := n.decoder.envelope(r); err != nil {
		return zero, err
	}
	client, ok := socketPeer(r.RemoteAddr)
	if !ok {
		return zero, ErrUnavailable
	}
	facts := NetworkFacts{client: client, scheme: "http"}
	if r.TLS != nil {
		facts.scheme = "https"
	}
	if n.trusted(client) {
		value, present, valid := forwardedHeader(r.Header)
		if !present || !valid {
			return zero, ErrUnavailable
		}
		elements, ok := n.forwardedElements(value)
		if !ok {
			return zero, ErrUnavailable
		}
		found := false
		for i := len(elements) - 1; i >= 0; i-- {
			element := elements[i]
			client = element.client
			if n.trusted(client) {
				continue
			}
			if element.host == "" || element.scheme == "" {
				return zero, ErrUnavailable
			}
			facts.client, facts.host, facts.authority, facts.scheme = client, element.host, element.authority, element.scheme
			facts.forwarded, found = true, true
			break
		}
		if !found {
			return zero, ErrUnavailable
		}
	} else {
		facts.host, facts.authority, ok = n.authority(r.Host)
		if !ok {
			return zero, DecodeError{}
		}
	}
	facts.binding = n.hosts[facts.host]
	if err := r.Context().Err(); err != nil {
		return zero, err
	}
	facts.valid = true
	return facts, nil
}

func (n *NetworkResolver) trusted(address netip.Addr) bool {
	for _, prefix := range n.proxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func networkAddress(raw string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(raw)
	// Unmap removes a mapped IPv6 address's zone. Reject it first so
	// normalization cannot turn forbidden input into an admitted address.
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	return a, a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

func networkPort(raw string) (string, bool) {
	if len(raw) < 1 || len(raw) > 5 {
		return "", false
	}
	for i := range raw {
		if raw[i] < '0' || raw[i] > '9' {
			return "", false
		}
	}
	p, err := strconv.ParseUint(raw, 10, 16)
	return strconv.FormatUint(p, 10), err == nil && p != 0
}

func socketPeer(raw string) (netip.Addr, bool) {
	if len(raw) > 128 {
		return netip.Addr{}, false
	}
	ap, err := netip.ParseAddrPort(raw)
	if err != nil || ap.Port() == 0 {
		return netip.Addr{}, false
	}
	return networkAddress(ap.Addr().String())
}

func (n *NetworkResolver) authority(raw string) (string, string, bool) {
	if len(raw) == 0 || len(raw) > 4096 || strings.ContainsAny(raw, " /\\?#@%\t\r\n") {
		return "", "", false
	}
	host, port := raw, ""
	if raw[0] == '[' {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", "", false
		}
		a, ok := networkAddress(raw[1:end])
		if !ok || !strings.Contains(raw[1:end], ":") {
			return "", "", false
		}
		host = a.String()
		if a.Is6() {
			host = "[" + host + "]"
		}
		if end+1 < len(raw) {
			if raw[end+1] != ':' {
				return "", "", false
			}
			port = raw[end+2:]
			if port == "" {
				return "", "", false
			}
		}
	} else {
		if strings.ContainsAny(raw, "[]") || strings.Count(raw, ":") > 1 {
			return "", "", false
		}
		if i := strings.IndexByte(raw, ':'); i >= 0 {
			host, port = raw[:i], raw[i+1:]
			if port == "" {
				return "", "", false
			}
		}
		if a, err := netip.ParseAddr(host); err == nil {
			if _, ok := networkAddress(host); !ok || !a.Is4() {
				return "", "", false
			}
			host = a.String()
		} else {
			canonical, err := identityidentifier.Normalize(identityidentifier.Input(host), n.profile)
			if err != nil {
				return "", "", false
			}
			host = canonical.Record().Value
			// Browsers reinterpret numeric final labels as legacy IPv4 forms.
			// DNS routing must not disagree with that interpretation.
			last := host[strings.LastIndexByte(host, '.')+1:]
			numeric := last != ""
			for i := range last {
				numeric = numeric && last[i] >= '0' && last[i] <= '9'
			}
			if host == "" || strings.HasSuffix(host, ".") || numeric || strings.HasPrefix(last, "0x") {
				return "", "", false
			}
		}
	}
	authority := host
	if port != "" {
		var ok bool
		port, ok = networkPort(port)
		if !ok {
			return "", "", false
		}
		authority += ":" + port
	}
	return host, authority, true
}

func forwardedHeader(headers http.Header) (string, bool, bool) {
	value, present := "", false
	for name, values := range headers {
		if !strings.EqualFold(name, "Forwarded") {
			continue
		}
		if present || len(values) != 1 || values[0] == "" {
			return "", true, false
		}
		value, present = values[0], true
	}
	return value, present, true
}

type forwardedElement struct {
	client                  netip.Addr
	host, authority, scheme string
}

func forwardedToken(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}

// forwardedValue advances over one bounded token or quoted string. Separators
// inside quotes are data, not chain boundaries. Controls are never accepted.
func forwardedValue(raw string, at int) (string, int, bool) {
	if at >= len(raw) {
		return "", at, false
	}
	if raw[at] != '"' {
		start := at
		for at < len(raw) && forwardedToken(raw[at]) {
			at++
		}
		return raw[start:at], at, at > start
	}
	at++
	var value strings.Builder
	for at < len(raw) {
		c := raw[at]
		at++
		if c == '"' {
			return value.String(), at, value.Len() > 0 && utf8.ValidString(value.String())
		}
		if c == '\\' {
			if at == len(raw) {
				return "", at, false
			}
			c, at = raw[at], at+1
		}
		if c < 32 || c == 127 {
			return "", at, false
		}
		value.WriteByte(c)
	}
	return "", at, false
}

func forwardedNode(raw string) (netip.Addr, bool) {
	if len(raw) == 0 || len(raw) > 128 {
		return netip.Addr{}, false
	}
	if raw[0] == '[' {
		end := strings.IndexByte(raw, ']')
		if end < 0 || !strings.Contains(raw[1:end], ":") {
			return netip.Addr{}, false
		}
		if end+1 < len(raw) {
			if raw[end+1] != ':' {
				return netip.Addr{}, false
			}
			if _, ok := networkPort(raw[end+2:]); !ok {
				return netip.Addr{}, false
			}
		}
		return networkAddress(raw[1:end])
	}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		if _, ok := networkPort(raw[i+1:]); !ok {
			return netip.Addr{}, false
		}
		raw = raw[:i]
	}
	a, ok := networkAddress(raw)
	return a, ok && a.Is4()
}

func (n *NetworkResolver) forwardedElements(raw string) ([]forwardedElement, bool) {
	if len(raw) == 0 || len(raw) > int(n.decoder.limits.MaximumHeaderBytes) {
		return nil, false
	}
	var elements []forwardedElement
	at := 0
	space := func() {
		for at < len(raw) && (raw[at] == ' ' || raw[at] == '\t') {
			at++
		}
	}
	for len(elements) < n.maxHops {
		var element forwardedElement
		seen := make(map[string]bool)
		for {
			space()
			start := at
			for at < len(raw) && forwardedToken(raw[at]) {
				at++
			}
			if at == start || at >= len(raw) || raw[at] != '=' || len(seen) == 16 {
				return nil, false
			}
			name := strings.ToLower(raw[start:at])
			if seen[name] {
				return nil, false
			}
			seen[name] = true
			value, next, ok := forwardedValue(raw, at+1)
			if !ok {
				return nil, false
			}
			at = next
			switch name {
			case "for":
				element.client, ok = forwardedNode(value)
			case "by":
				_, ok = forwardedNode(value)
			case "host":
				element.host, element.authority, ok = n.authority(value)
			case "proto":
				element.scheme = strings.ToLower(value)
				ok = element.scheme == "http" || element.scheme == "https"
			}
			if !ok {
				return nil, false
			}
			space()
			if at < len(raw) && raw[at] == ';' {
				at++
				continue
			}
			break
		}
		if !element.client.IsValid() {
			return nil, false
		}
		elements = append(elements, element)
		if at == len(raw) {
			return elements, true
		}
		if raw[at] != ',' {
			return nil, false
		}
		at++
	}
	return nil, false
}
