package providers

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-identity/oauth"
)

// ErrKeycloakConfiguration rejects invalid startup configuration without
// retaining metadata, credentials, URLs or collaborator diagnostics.
var ErrKeycloakConfiguration = errors.New("providers: invalid Keycloak configuration")

// KeycloakConfig selects one existing-account Keycloak browser profile.
// Metadata is the exact reviewed realm discovery response, at most 64 KiB;
// MetadataSHA256 is its separately configured, nonzero SHA-256 pin. A digest
// proves configured byte identity, not provider authenticity: the deployment
// owner obtains the document over authenticated HTTPS and reviews its origin.
// Issuer is exact, and all selected endpoints must remain inside that realm.
// KeySet is the existing explicit trusted, concurrency-safe signature seam;
// the caller provisions keys from the pinned jwks_uri. No discovery or key
// refresh happens here. Version must change when the trusted profile changes.
// ClientSecret and Scopes are copied; callers clear their source secret.
// Clock/HTTPClient and resource limits have GoogleConfig's ownership/defaults.
type KeycloakConfig struct {
	Version                       uint64
	Issuer, ClientID, RedirectURI string
	ClientSecret                  []byte
	Metadata                      []byte
	MetadataSHA256                [sha256.Size]byte
	Scopes                        []string
	KeySet                        oauth.SigningKeySet
	Clock                         oauth.Clock
	HTTPClient                    *http.Client
	Timeout, ClockSkew            time.Duration
	MaxResponseBytes              int64
	MaxTokenBytes, MaxCodeBytes   int
}

// Format redacts configuration even in enclosing/pointer diagnostics.
func (KeycloakConfig) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON refuses implicit credential/metadata serialization.
func (KeycloakConfig) MarshalJSON() ([]byte, error) { return nil, ErrKeycloakConfiguration }

// MarshalText refuses implicit serialization, including map keys.
func (KeycloakConfig) MarshalText() ([]byte, error) { return nil, ErrKeycloakConfiguration }

// NewKeycloak constructs the existing OAuth owner without external operations.
// It derives endpoints only from exact pinned realm metadata and selects stable
// ID keycloak, code/query/S256/nonce/RS256 and client_secret_basic. Nil Scopes
// selects openid,profile,email; a unique subset must retain openid. Metadata
// must advertise every selected capability, including RFC9207 callback issuer.
// Unknown metadata extensions are not identity claims or capabilities.
//
// Native state/link/session owners remain mandatory. This constructor adds no
// signup, implicit link, native-token, UserInfo enrichment, refresh, revocation
// or remote logout operation. Close the returned provider after admitted calls
// finish; caller-owned keys and source transport remain caller-owned. Failure
// returns nil,ErrKeycloakConfiguration, never underlying diagnostics.
func NewKeycloak(c KeycloakConfig) (*oauth.OIDCProvider, error) {
	if len(c.Metadata) == 0 || len(c.Metadata) > 64<<10 || c.MetadataSHA256 == ([sha256.Size]byte{}) || sha256.Sum256(c.Metadata) != c.MetadataSHA256 || !utf8.Valid(c.Metadata) {
		return nil, ErrKeycloakConfiguration
	}
	fields, err := keycloakMetadataFields(c.Metadata)
	if err != nil {
		return nil, ErrKeycloakConfiguration
	}
	issuer, valid := keycloakMetadataString(fields, "issuer")
	if !valid || issuer != c.Issuer || !keycloakHTTPS(issuer) || strings.HasSuffix(issuer, "/") {
		return nil, ErrKeycloakConfiguration
	}
	endpoints := make(map[string]string, 4)
	for _, name := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		endpoint, ok := keycloakMetadataString(fields, name)
		if !ok || !keycloakRealmEndpoint(issuer, endpoint) {
			return nil, ErrKeycloakConfiguration
		}
		endpoints[name] = endpoint
	}
	for name, required := range map[string]string{
		"response_types_supported": "code", "response_modes_supported": "query",
		"id_token_signing_alg_values_supported": "RS256", "token_endpoint_auth_methods_supported": "client_secret_basic",
		"code_challenge_methods_supported": "S256", "subject_types_supported": "public",
	} {
		values, ok := keycloakMetadataStrings(fields, name)
		if !ok || !slices.Contains(values, required) {
			return nil, ErrKeycloakConfiguration
		}
	}
	if !bytes.Equal(bytes.TrimSpace(fields["authorization_response_iss_parameter_supported"]), []byte("true")) {
		return nil, ErrKeycloakConfiguration
	}
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{"openid", "profile", "email"}
	}
	advertised, ok := keycloakMetadataStrings(fields, "scopes_supported")
	if !ok || len(scopes) < 1 || len(scopes) > 3 || !slices.Contains(scopes, "openid") {
		return nil, ErrKeycloakConfiguration
	}
	seen := make(map[string]bool, 3)
	for _, scope := range scopes {
		if scope != "openid" && scope != "profile" && scope != "email" || seen[scope] || !slices.Contains(advertised, scope) {
			return nil, ErrKeycloakConfiguration
		}
		seen[scope] = true
	}
	p, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "keycloak", Version: c.Version, Issuer: issuer,
		AuthorizationEndpoint: endpoints["authorization_endpoint"], TokenEndpoint: endpoints["token_endpoint"],
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, ClientAuthentication: oauth.ClientSecretBasic,
		RedirectURI: c.RedirectURI, Scopes: scopes, Algorithms: []string{"RS256"},
		KeySet: c.KeySet, Clock: c.Clock, HTTPClient: c.HTTPClient, Timeout: c.Timeout, ClockSkew: c.ClockSkew,
		MaxResponseBytes: c.MaxResponseBytes, MaxTokenBytes: c.MaxTokenBytes, MaxCodeBytes: c.MaxCodeBytes,
	})
	if err != nil {
		return nil, ErrKeycloakConfiguration
	}
	return p, nil
}

// Discovery allows extension members. Decode only bounded raw values, rejecting
// duplicate top-level names so no security decision can depend on decoder order.
func keycloakMetadataFields(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrKeycloakConfiguration
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		name, err := d.Token()
		if err != nil || len(fields) >= 128 {
			return nil, ErrKeycloakConfiguration
		}
		key, ok := name.(string)
		if !ok || len(key) > 256 || fields[key] != nil {
			return nil, ErrKeycloakConfiguration
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, ErrKeycloakConfiguration
		}
		fields[key] = value
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') {
		return nil, ErrKeycloakConfiguration
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrKeycloakConfiguration
	}
	return fields, nil
}

func keycloakMetadataString(fields map[string]json.RawMessage, name string) (string, bool) {
	var value string
	err := json.Unmarshal(fields[name], &value)
	return value, err == nil && value != "" && len(value) <= 2048
}

func keycloakMetadataStrings(fields map[string]json.RawMessage, name string) ([]string, bool) {
	var values []string
	if json.Unmarshal(fields[name], &values) != nil || len(values) == 0 || len(values) > 64 {
		return nil, false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || len(value) > 256 || seen[value] {
			return nil, false
		}
		seen[value] = true
	}
	return values, true
}

func keycloakHTTPS(raw string) bool {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\\#*%") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.String() == raw
}

func keycloakRealmEndpoint(issuer, endpoint string) bool {
	if !keycloakHTTPS(endpoint) || !strings.HasPrefix(endpoint, issuer+"/") {
		return false
	}
	u, _ := url.Parse(endpoint)
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." || segment == "" && u.Path != "/" && strings.Contains(u.Path, "//") {
			return false
		}
	}
	return true
}
