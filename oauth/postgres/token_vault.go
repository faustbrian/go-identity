package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const rpTokenVaultHeader = "OITV1"
const rpMaximumTokenCiphertext = 65536

// Account and social-link versions refer to the identity owner's exact newly
// linked state, not independently advanced authority in this adapter.
type rpTokenVaultBinding struct {
	TenantID                                                identity.TenantID
	UserID                                                  identity.UserID
	AccountID                                               identity.AccountID
	ProviderID, Issuer, ClientID                            string
	ConfigurationVersion, AccountVersion, SocialLinkVersion uint64
}

// This explicit private ciphertext/metadata projection is encoded only inside
// native authenticated preparation. It contains no bearer bytes, PKCE or state
// proof. Every field other than Ciphertext is authenticated as envelope AAD.
type rpPreparedTokenSet struct {
	Schema                           uint8
	Binding                          rpTokenVaultBinding
	Ciphertext                       []byte
	RequestedScopes, GrantedScopes   []string
	ScopeReported                    bool
	ReceivedAt, AccessExpiresAt      time.Time
	Version, SocialConnectionVersion uint64
}

func (rpTokenVaultBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.rpTokenVaultBinding(redacted)"))
}
func (rpPreparedTokenSet) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.rpPreparedTokenSet(redacted)"))
}

func rpTokenVaultFailure(ctx context.Context, unavailable bool) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if unavailable {
		return identity.UnavailableError{}
	}
	return identity.ForbiddenError{}
}

func rpTokenVaultScopes(scopes []string) bool {
	if len(scopes) < 1 || len(scopes) > 32 {
		return false
	}
	for i, scope := range scopes {
		if !rpASCII(scope, 1, 128) || strings.ContainsAny(scope, " \"\\") || slices.Contains(scopes[:i], scope) {
			return false
		}
	}
	return true
}

// The existing three-slot frame remains byte-for-byte unchanged. OAuth2's
// authenticated variant requires an empty ID-token slot, not an invented JWT;
// the original OIDC profile still requires its original nonempty token bytes.
func (s *LinkService) tokenVaultIDTokenSize(profile oauth.ProviderProfile, size uint64) bool {
	if details, selected := s.oauth2Profiles[profile.ID]; selected {
		facts := oauth.OAuth2UserInfoProfile{Profile: profile, Details: details}
		return facts.Validate() == nil && size == 0
	}
	return size > 0 && size <= uint64(profile.MaxTokenBytes)
}

func (s *LinkService) tokenVaultProfile(b rpTokenVaultBinding) (oauth.ProviderProfile, error) {
	if s == nil || s.config == nil || s.envelopes == nil || !rpSchemaName(s.config().Schema) {
		return oauth.ProviderProfile{}, identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	if _, err := identity.ParseIdentifierID(string(b.TenantID)); err != nil {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseIdentifierID(string(b.UserID)); err != nil {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseAccountID(string(b.AccountID)); err != nil {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	p, ok := s.profiles[b.ProviderID]
	if !ok || !rpProviderID(b.ProviderID) || b.ProviderID != p.ID || b.Issuer != p.Issuer || b.ClientID != p.ClientID || b.ConfigurationVersion != p.Version || b.ConfigurationVersion == 0 || b.AccountVersion == 0 || b.SocialLinkVersion == 0 || !rpASCII(b.Issuer, 1, 1024) || !rpASCII(b.ClientID, 1, 1024) || p.MaxTokenBytes < 256 || p.MaxTokenBytes > 16<<10 || !rpTokenVaultScopes(p.Scopes) {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	return p, nil
}

func (s *LinkService) tokenVaultMetadata(p rpPreparedTokenSet) (oauth.ProviderProfile, error) {
	profile, err := s.tokenVaultProfile(p.Binding)
	if err != nil {
		return oauth.ProviderProfile{}, err
	}
	if p.Schema != 1 || p.Version != 1 || p.SocialConnectionVersion != 1 || !rpTokenVaultScopes(p.RequestedScopes) || !rpTokenVaultScopes(p.GrantedScopes) || !slices.Equal(p.RequestedScopes, profile.Scopes) || !rpUTCTime(p.ReceivedAt) || !rpUTCTime(p.AccessExpiresAt) || !p.AccessExpiresAt.After(p.ReceivedAt) || p.AccessExpiresAt.Sub(p.ReceivedAt) > 365*24*time.Hour || p.AccessExpiresAt.Sub(p.ReceivedAt)%time.Second != 0 || !p.ScopeReported && !slices.Equal(p.RequestedScopes, p.GrantedScopes) {
		return oauth.ProviderProfile{}, identity.ForbiddenError{}
	}
	for _, scope := range p.GrantedScopes {
		if !slices.Contains(p.RequestedScopes, scope) {
			return oauth.ProviderProfile{}, identity.ForbiddenError{}
		}
	}
	return profile, nil
}

func rpTokenVaultAAD(p rpPreparedTokenSet) (envelope.Context, error) {
	metadata := p
	metadata.Ciphertext = nil
	plain, err := json.Marshal(metadata)
	if err != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	b := p.Binding
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-token-vault-v1", "tenant": string(b.TenantID), "user": string(b.UserID), "account": string(b.AccountID), "provider": b.ProviderID, "issuer": b.Issuer, "client_id": b.ClientID, "configuration_version": strconv.FormatUint(b.ConfigurationVersion, 10), "account_version": strconv.FormatUint(b.AccountVersion, 10), "social_link_version": strconv.FormatUint(b.SocialLinkVersion, 10), "metadata": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// sealProviderTokens consumes original shared TokenSet custody on every path.
// The actual core owner clears its synchronous borrowed token slices; this
// method clears the one bounded frame and destroys all original token aliases.
// It performs no SQL, network, provider protocol, journal or authority mutation.
func (s *LinkService) sealProviderTokens(ctx context.Context, b rpTokenVaultBinding, tokens oauth.TokenSet) (out rpPreparedTokenSet, err error) {
	defer tokens.Destroy()
	defer func() {
		if recover() != nil {
			out = rpPreparedTokenSet{}
			err = rpTokenVaultFailure(ctx, true)
		}
	}()
	if ctx == nil {
		return out, identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	p := rpPreparedTokenSet{Schema: 1, Binding: b, RequestedScopes: tokens.RequestedScopes(), GrantedScopes: tokens.GrantedScopes(), ScopeReported: tokens.ScopeReported(), ReceivedAt: tokens.ReceivedAt().UTC(), AccessExpiresAt: tokens.ExpiresAt().UTC(), Version: 1, SocialConnectionVersion: 1}
	profile, err := s.tokenVaultMetadata(p)
	if err != nil {
		return out, err
	}
	aad, err := rpTokenVaultAAD(p)
	if err != nil {
		return out, err
	}
	err = tokens.Use(ctx, func(ctx context.Context, tokens oauth.TokenBytes) error {
		if len(tokens.AccessToken) < 1 || len(tokens.AccessToken) > profile.MaxTokenBytes || len(tokens.RefreshToken) > profile.MaxTokenBytes || !s.tokenVaultIDTokenSize(profile, uint64(len(tokens.IDToken))) {
			return identity.ForbiddenError{}
		}
		// OIDCConfig bounds each token to16KiB. Allocate once so append cannot
		// abandon a backing array that still contains a bearer copy.
		length := len(rpTokenVaultHeader) + 12 + len(tokens.AccessToken) + len(tokens.RefreshToken) + len(tokens.IDToken)
		frame := make([]byte, 0, length)
		defer func() { clear(frame) }()
		frame = append(frame, rpTokenVaultHeader...)
		for _, value := range [][]byte{tokens.AccessToken, tokens.RefreshToken, tokens.IDToken} {
			frame = binary.BigEndian.AppendUint32(frame, uint32(len(value)))
			frame = append(frame, value...)
		}
		var e error
		p.Ciphertext, e = s.sealRP(ctx, aad, frame)
		if e != nil {
			return rpTokenVaultFailure(ctx, true)
		}
		if len(p.Ciphertext) == 0 || len(p.Ciphertext) > rpMaximumTokenCiphertext {
			return identity.ForbiddenError{}
		}
		return nil
	})
	if err != nil {
		return out, rpTokenVaultFailure(ctx, true)
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return p, nil
}

// Validation is local authenticated restoration, not token revelation or
// account/session admission. It never creates replacement tokens or expiry.
func (s *LinkService) validatePreparedProviderTokens(ctx context.Context, p rpPreparedTokenSet) (err error) {
	defer func() {
		if recover() != nil {
			err = rpTokenVaultFailure(ctx, true)
		}
	}()
	if ctx == nil {
		return identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	profile, err := s.tokenVaultMetadata(p)
	if err != nil {
		return err
	}
	if len(p.Ciphertext) == 0 || len(p.Ciphertext) > rpMaximumTokenCiphertext {
		return identity.ForbiddenError{}
	}
	aad, err := rpTokenVaultAAD(p)
	if err != nil {
		return identity.ForbiddenError{}
	}
	plain, err := s.openRP(ctx, aad, p.Ciphertext, rpMaximumTokenCiphertext)
	defer clear(plain)
	if err != nil {
		return rpTokenVaultFailure(ctx, false)
	}
	if len(plain) < len(rpTokenVaultHeader)+12 || string(plain[:len(rpTokenVaultHeader)]) != rpTokenVaultHeader {
		return identity.ForbiddenError{}
	}
	remaining := plain[len(rpTokenVaultHeader):]
	for i := range 3 {
		if len(remaining) < 4 {
			return identity.ForbiddenError{}
		}
		n := binary.BigEndian.Uint32(remaining)
		remaining = remaining[4:]
		if n > uint32(profile.MaxTokenBytes) || uint64(n) > uint64(len(remaining)) || i == 0 && n == 0 || i == 2 && !s.tokenVaultIDTokenSize(profile, uint64(n)) {
			return identity.ForbiddenError{}
		}
		remaining = remaining[int(n):]
	}
	if len(remaining) != 0 {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

// The kernel has already inserted/advanced the authoritative account when its
// FinalizeAccountLink invocation reaches this method. This owner writes only
// token custody, in that same sealed Work. It cannot insert or adopt a link.
func (s *LinkService) persistProviderTokens(ctx context.Context, w kernel.AccountLinkWork, owner kernel.AccountLinkContributor, p rpPreparedTokenSet) error {
	if ctx == nil {
		return identity.InvalidInputError{Field: "oauth_token_vault"}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	command, terminal, err := w.Command(owner)
	if err != nil {
		return err
	}
	b, a := p.Binding, command.Change.Account
	if !terminal || command.Change.Mode != identity.AccountLinkExplicit || command.Binding.OperationID != "identity.account.link-token" || command.Binding.TenantID != b.TenantID || command.Binding.UserID != b.UserID || command.Binding.RecordID != string(b.AccountID) || a.ID != b.AccountID || a.TenantID != b.TenantID || a.UserID != b.UserID || a.Provider != b.ProviderID || a.Issuer != b.Issuer || a.Version != b.AccountVersion || command.Change.ExpectedAccountVersion == ^uint64(0) || a.Version != command.Change.ExpectedAccountVersion+1 || command.Change.ExpectedSocialLinkVersion == ^uint64(0) || b.SocialLinkVersion != command.Change.ExpectedSocialLinkVersion+1 {
		return identity.ForbiddenError{}
	}
	if err := s.validatePreparedProviderTokens(ctx, p); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT user_id,provider,issuer,subject,version::text,social_link_version::text,linked FROM identity.accounts WHERE tenant_id=$1 AND account_id=$2 FOR SHARE`, string(b.TenantID), string(b.AccountID))
	if err != nil {
		return err
	}
	var user, provider, issuer, subject, accountVersion, socialVersion string
	var linked bool
	valid := rows.Next() && rows.Scan(&user, &provider, &issuer, &subject, &accountVersion, &socialVersion, &linked) == nil
	extra := rows.Next()
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return identity.UnavailableError{}
	}
	if !valid || extra || !linked || user != string(b.UserID) || provider != b.ProviderID || issuer != b.Issuer || subject != a.Subject || accountVersion != strconv.FormatUint(b.AccountVersion, 10) || socialVersion != strconv.FormatUint(b.SocialLinkVersion, 10) {
		return identity.ForbiddenError{}
	}
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(command.Binding.CommandID))
	if err != nil || len(origin) != 16 {
		return identity.ForbiddenError{}
	}
	// Work deliberately accepts bounded scalars, not driver-controlled array
	// encoders. RFC 6749 section 3.3 forbids spaces inside scope tokens, so this
	// validated, order-preserving encoding round-trips without broadening Work.
	n, err := w.Exec(ctx, strings.ReplaceAll(rpTokenVaultInsert, "@schema@", rpQuotedSchema(s.config().Schema)), string(b.TenantID), string(b.UserID), string(b.AccountID), b.ProviderID, b.Issuer, b.ClientID, b.ConfigurationVersion, b.AccountVersion, b.SocialLinkVersion, strings.Join(p.RequestedScopes, " "), strings.Join(p.GrantedScopes, " "), p.ScopeReported, p.ReceivedAt.Unix(), p.ReceivedAt.Nanosecond(), p.AccessExpiresAt.Unix(), p.AccessExpiresAt.Nanosecond(), p.Ciphertext, origin)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return ctx.Err()
}

const rpTokenVaultInsert = `INSERT INTO @schema@.token_sets(tenant_id,user_id,account_id,provider_id,issuer,client_id,configuration_version,account_version,social_link_version,version,social_connection_version,requested_scopes,granted_scopes,scope_reported,received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext,origin_operation,origin_command_id) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9::numeric,1,1,string_to_array($10,' '),string_to_array($11,' '),$12,$13,$14,$15,$16,$17,'identity.account.link-token',$18) ON CONFLICT DO NOTHING`
