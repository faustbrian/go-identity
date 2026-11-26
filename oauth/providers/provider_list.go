package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

// ProviderMode describes a configured authentication input, not token output.
type ProviderMode string

// AuthorizationCodeMode is the selected browser code/query/S256 flow. It does
// not advertise native ID/access-token signin, signup, refresh or remote logout.
const AuthorizationCodeMode ProviderMode = "authorization_code"

// ProviderListInvalidRequestError rejects malformed input or unsupported startup
// configuration without retaining provider facts, credentials or cursor bytes.
type ProviderListInvalidRequestError struct{}

func (ProviderListInvalidRequestError) Error() string {
	return "providers: invalid provider-list request"
}

// ProviderListAuthorizationDeniedError is the operation's stable denial type.
// The public immutable catalog requires no actor and does not issue this error.
type ProviderListAuthorizationDeniedError struct{}

func (ProviderListAuthorizationDeniedError) Error() string {
	return "providers: provider-list authorization denied"
}

// ProviderListUnavailableError indicates an uninitialized catalog. RetryAfter is
// absent when zero; this local implementation performs no IO or automatic retry.
type ProviderListUnavailableError struct{ RetryAfter time.Duration }

func (ProviderListUnavailableError) Error() string { return "providers: provider-list unavailable" }

// Cursor is an opaque, immutable continuation. Zero selects the first page;
// replay only with the same configured catalog snapshot, deployment key and limit.
type Cursor struct{ value string }

// ParseCursor validates the bounded canonical wire representation, not its
// authority. ProviderList authenticates its catalog scope before using it.
func ParseCursor(value string) (Cursor, error) {
	if value == "" {
		return Cursor{}, nil
	}
	if len(value) > 512 {
		return Cursor{}, ProviderListInvalidRequestError{}
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(wire) != providerListCursorBytes || base64.RawURLEncoding.EncodeToString(wire) != value {
		return Cursor{}, ProviderListInvalidRequestError{}
	}
	return Cursor{value: value}, nil
}

// String returns only the opaque continuation wire value, empty at exhaustion.
func (c Cursor) String() string { return c.value }

// MarshalJSON preserves the opaque continuation without exposing catalog state.
func (c Cursor) MarshalJSON() ([]byte, error) { return json.Marshal(c.value) }

// PageLimit is an immutable validated result bound; zero is invalid.
type PageLimit struct{ value int }

// NewPageLimit selects 1..100 results. This local bound keeps every public call
// finite; it is not a provider capability or a claim of full catalog support.
func NewPageLimit(value int) (PageLimit, error) {
	if value < 1 || value > 100 {
		return PageLimit{}, ProviderListInvalidRequestError{}
	}
	return PageLimit{value: value}, nil
}

// SafeProvider owns exactly public ID, display name and configured modes. It
// never retains an OAuth provider, endpoint, client ID, secret or raw profile.
type SafeProvider struct {
	id, displayName string
	modes           []ProviderMode
}

// ID is the exact selected canonical catalog ID, never an alias.
func (p SafeProvider) ID() string { return p.id }

// DisplayName is the built-in catalog label, never deployment-supplied text.
func (p SafeProvider) DisplayName() string { return p.displayName }

// SupportedModes returns an independent copy of actual configured modes.
func (p SafeProvider) SupportedModes() []ProviderMode { return slices.Clone(p.modes) }

// MarshalJSON emits only the three safe public facts.
func (p SafeProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID, DisplayName string
		SupportedModes  []ProviderMode
	}{p.id, p.displayName, p.SupportedModes()})
}

// ProviderListPage is an immutable bounded page. A constructed empty catalog
// yields a valid empty page; a zero page occurs only in a zero failure result.
type ProviderListPage struct{ providers []SafeProvider }

// Providers returns independent provider and mode slices in canonical ID order.
func (p ProviderListPage) Providers() []SafeProvider {
	items := slices.Clone(p.providers)
	for i := range items {
		items[i].modes = slices.Clone(items[i].modes)
	}
	return items
}

// MarshalJSON emits the safe ordered page, including [] for an empty catalog.
func (p ProviderListPage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Providers()) }

// ProviderListRequest is the complete direct request. A zero cursor starts;
// Limit must be constructed with NewPageLimit. There are no caller mode flags.
type ProviderListRequest struct {
	Cursor Cursor
	Limit  PageLimit
}

// ProviderListResult owns a safe page and an optional opaque continuation.
type ProviderListResult struct {
	Page       ProviderListPage
	NextCursor Cursor
}

// Catalog is the direct identity.oauth.provider-list operation boundary.
type Catalog interface {
	ProviderList(context.Context, ProviderListRequest) (ProviderListResult, error)
}

// CatalogConfig selects already-configured built-in provider owners. Use the
// exact same selected set as native OAuth composition; construction snapshots
// their immutable facts without borrowing them or calling protocol operations.
// CursorKey is exactly 32 nonzero-in-aggregate deployment-secret bytes, copied
// at construction. Share it across equivalent instances for stable pagination;
// rotating it deliberately invalidates existing cursors. Clear source key bytes.
type CatalogConfig struct {
	Providers []oauth.Provider
	CursorKey []byte
}

// Format prevents credential/key disclosure in nested startup diagnostics.
func (CatalogConfig) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON refuses implicit startup configuration disclosure.
func (CatalogConfig) MarshalJSON() ([]byte, error) { return nil, ProviderListInvalidRequestError{} }

// MarshalText refuses implicit startup configuration disclosure.
func (CatalogConfig) MarshalText() ([]byte, error) { return nil, ProviderListInvalidRequestError{} }

// CatalogImpl owns only safe facts, a configuration digest and a copied cursor
// key. It is immutable, safe for concurrent calls and starts no goroutine or IO.
// Rebuild it when native configuration changes; Version must change for supplier
// inputs absent from ProviderProfile, including trusted signing-key rotation.
type CatalogImpl struct {
	providers []SafeProvider
	scope     [sha256.Size]byte
	key       [sha256.Size]byte
	ready     bool
}

// Format redacts cursor-key custody, including through enclosing values.
func (CatalogImpl) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON refuses implicit cursor-key owner serialization.
func (CatalogImpl) MarshalJSON() ([]byte, error) { return nil, ProviderListInvalidRequestError{} }

// MarshalText refuses implicit cursor-key owner serialization.
func (CatalogImpl) MarshalText() ([]byte, error) { return nil, ProviderListInvalidRequestError{} }

// NewCatalog snapshots the currently implemented Google/Keycloak OIDC and
// GitHub/GitLab OAuth2 browser owners. Unknown IDs, duplicate IDs, nil owners,
// unselected variants and more than the required 43 catalog entries deny.
// This is startup projection, not provider authentication: trusted composition
// must supply the actual built-in builders and the exact native-selected set.
// It does not grant account/session admission or qualify provider interoperability.
func NewCatalog(config CatalogConfig) (*CatalogImpl, error) {
	if len(config.CursorKey) != sha256.Size || len(config.Providers) > 43 {
		return nil, ProviderListInvalidRequestError{}
	}
	c := &CatalogImpl{providers: make([]SafeProvider, 0, len(config.Providers))}
	copy(c.key[:], config.CursorKey)
	if c.key == ([sha256.Size]byte{}) {
		return nil, ProviderListInvalidRequestError{}
	}
	// The required goal's provider-catalog-v1 has 43 rows. Snapshot only selected
	// committed protocol variants, never the broader planned capability matrix.
	type configuredFacts struct {
		Profile oauth.ProviderProfile
		Details oauth.OAuth2UserInfoDetails
		Policy  oauth.OAuth2TokenPolicy
	}
	facts := make([]configuredFacts, 0, len(config.Providers))
	seen := make(map[string]bool, len(config.Providers))
	for _, owner := range config.Providers {
		var fact configuredFacts
		switch p := owner.(type) {
		case *oauth.OIDCProvider:
			fact.Profile = p.Profile()
			if fact.Profile.ID != "keycloak" && (fact.Profile.ID != "google" || !fact.Profile.GoogleAccounts) {
				return nil, ProviderListInvalidRequestError{}
			}
		case *oauth.OAuth2UserInfoProvider:
			profile := p.OAuth2Profile()
			fact.Profile, fact.Details, fact.Policy = profile.Profile, profile.Details, p.OAuth2TokenPolicy()
			if fact.Profile.ID != "github" && fact.Profile.ID != "gitlab" {
				return nil, ProviderListInvalidRequestError{}
			}
		default:
			return nil, ProviderListInvalidRequestError{}
		}
		profile := fact.Profile
		if profile.Version == 0 || profile.ResponseMode != "query" || profile.PKCEMethod != "S256" || seen[profile.ID] {
			return nil, ProviderListInvalidRequestError{}
		}
		seen[profile.ID] = true
		facts = append(facts, fact)
		name := map[string]string{"google": "Google", "keycloak": "Keycloak", "github": "GitHub", "gitlab": "GitLab"}[profile.ID]
		c.providers = append(c.providers, SafeProvider{id: profile.ID, displayName: name, modes: []ProviderMode{AuthorizationCodeMode}})
	}
	slices.SortFunc(c.providers, func(a, b SafeProvider) int { return strings.Compare(a.id, b.id) })
	slices.SortFunc(facts, func(a, b configuredFacts) int { return strings.Compare(a.Profile.ID, b.Profile.ID) })
	encoded, err := json.Marshal(facts)
	if err != nil {
		return nil, ProviderListInvalidRequestError{}
	}
	c.scope = sha256.Sum256(encoded)
	c.ready = true
	return c, nil
}

const providerListCursorBytes = 5 + sha256.Size

// ProviderList returns a deterministic bounded snapshot with no external calls.
// Invalid requests/cursors and unavailable catalogs return typed errors and a
// zero result; canceled contexts return their standard context error. A cursor
// is replayable unchanged, never a credential or authorization capability.
func (c *CatalogImpl) ProviderList(ctx context.Context, request ProviderListRequest) (ProviderListResult, error) {
	if ctx == nil || request.Limit.value < 1 || request.Limit.value > 100 {
		return ProviderListResult{}, ProviderListInvalidRequestError{}
	}
	if err := ctx.Err(); err != nil {
		return ProviderListResult{}, err
	}
	if c == nil || !c.ready {
		return ProviderListResult{}, ProviderListUnavailableError{}
	}
	start := 0
	if request.Cursor.value != "" {
		wire, err := base64.RawURLEncoding.Strict().DecodeString(request.Cursor.value)
		if err != nil || len(wire) != providerListCursorBytes || wire[0] != 1 || int(binary.BigEndian.Uint16(wire[3:5])) != request.Limit.value || !hmac.Equal(wire[5:], c.cursorMAC(wire[:5])) {
			return ProviderListResult{}, ProviderListInvalidRequestError{}
		}
		start = int(binary.BigEndian.Uint16(wire[1:3]))
		if start == 0 || start >= len(c.providers) || start%request.Limit.value != 0 {
			return ProviderListResult{}, ProviderListInvalidRequestError{}
		}
	}
	end := min(start+request.Limit.value, len(c.providers))
	page := ProviderListPage{providers: c.providers[start:end]}.Providers()
	result := ProviderListResult{Page: ProviderListPage{providers: page}}
	if end < len(c.providers) {
		wire := make([]byte, 5, providerListCursorBytes)
		wire[0] = 1
		binary.BigEndian.PutUint16(wire[1:3], uint16(end))
		binary.BigEndian.PutUint16(wire[3:5], uint16(request.Limit.value))
		wire = append(wire, c.cursorMAC(wire)...)
		result.NextCursor = Cursor{value: base64.RawURLEncoding.EncodeToString(wire)}
	}
	return result, nil
}

func (c *CatalogImpl) cursorMAC(position []byte) []byte {
	mac := hmac.New(sha256.New, c.key[:])
	_, _ = mac.Write([]byte("identity.oauth.provider-list:v1\x00"))
	_, _ = mac.Write(c.scope[:])
	_, _ = mac.Write(position)
	return mac.Sum(nil)
}
