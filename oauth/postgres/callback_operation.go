package postgres

import (
	"context"
	"encoding/base64"
	"reflect"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

// CallbackOperation resolves the original link/signin initiation operation from
// the configured RP's keyed state commitment. It accepts no browser-selected
// mode and performs no credential read, reservation, decryption, exchange or
// mutation. A match is routing metadata, not browser authentication or admission:
// the selected native callback must repeat every original browser, provider,
// policy and current-authority check before any protected effect. Terminal
// metadata remains routable only within its original state lifetime.
//
// The caller owns Callback custody and destroys it after the entire bounded
// callback. The service borrows the primary pool; calls share no mutable state.
// Missing, foreign, expired or ambiguous state denies without a fallback route.
func (s *LinkService) CallbackOperation(ctx context.Context, tenant identity.TenantID, callback oauth.Callback) (operation string, err error) {
	if ctx == nil || s == nil || s.pool == nil || s.pool.Raw() == nil || s.config == nil || !rpDirectoryID(string(tenant)) {
		return "", identity.InvalidInputError{Field: "oauth_callback_operation"}
	}
	c := s.config()
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			operation, err = "", identity.UnavailableError{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	profile := callback.Profile()
	configured, selected := s.profiles[profile.ID]
	if !selected || !reflect.DeepEqual(profile, configured) {
		return "", identity.ForbiddenError{}
	}
	var raw []byte
	err = useRPCallbackState(ctx, callback, func(_ context.Context, state []byte) error {
		var decodeErr error
		raw, decodeErr = base64.RawURLEncoding.Strict().DecodeString(string(state))
		if decodeErr != nil || len(raw) != 32 {
			return identity.ForbiddenError{}
		}
		return nil
	})
	defer clear(raw)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", identity.ForbiddenError{}
	}
	versions := make([]int64, 0, len(c.StateKeys))
	for version := range c.StateKeys {
		versions = append(versions, int64(version))
	}
	slices.Sort(versions)
	digests := make([][]byte, len(versions))
	for index, version := range versions {
		sum := rpStateDigest(c.StateKeys[uint32(version)], uint32(version), tenant, profile.ID, raw)
		digests[index] = sum[:]
	}
	rows, err := s.pool.Raw().Query(ctx, strings.ReplaceAll(callbackOperationSQL, "@schema@", rpQuotedSchema(c.Schema)), string(tenant), profile.ID, versions, digests, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI)
	if err != nil {
		return "", identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return "", identity.UnavailableError{}
		}
		return "", identity.ForbiddenError{}
	}
	if rows.Scan(&operation) != nil {
		return "", identity.UnavailableError{}
	}
	if rows.Next() {
		return "", identity.ForbiddenError{}
	}
	if rows.Err() != nil {
		return "", identity.UnavailableError{}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if operation != "identity.account.link-start" && operation != "identity.oauth.signin-start" {
		return "", identity.ForbiddenError{}
	}
	return operation, nil
}

// Match retained version/digest pairs, not their Cartesian product. The existing
// tenant/state-version/state-digest unique index bounds each selected key lookup.
const callbackOperationSQL = `SELECT t.operation
 FROM @schema@.transactions t JOIN unnest($3::bigint[],$4::bytea[]) AS selected(key_version,digest)
 ON t.state_key_version=selected.key_version AND t.state_digest=selected.digest
 WHERE t.tenant_id=$1 AND t.provider_id=$2 AND t.configuration_version=$5::numeric
 AND t.issuer=$6 AND t.client_id=$7 AND t.redirect_uri=$8 AND t.response_mode='query'
 AND t.issued_at<=clock_timestamp() AND t.expires_at>clock_timestamp() LIMIT 2`
