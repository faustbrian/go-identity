package postgres

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type providerRefreshVaultRow interface{ Scan(...any) error }

func providerRefreshVaultReadSQL(schema string) string {
	return strings.ReplaceAll(`SELECT provider_id,issuer,client_id,configuration_version::text,
 account_version::text,social_link_version::text,version::text,social_connection_version::text,
 array_to_string(requested_scopes,' '),array_to_string(granted_scopes,' '),scope_reported,
 received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext
 FROM @schema@.token_sets WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3`, "@schema@", rpQuotedSchema(schema))
}

// The row carries no independent grant authority: the authenticated envelope
// must match this exact owner, profile, versions, scopes, and times before use.
func scanProviderRefreshVault(row providerRefreshVaultRow, tenant identity.TenantID, user identity.UserID, account identity.AccountID) (rpPreparedTokenSet, error) {
	b := rpTokenVaultBinding{TenantID: tenant, UserID: user, AccountID: account}
	var configuration, accountVersion, link, version, connection, requested, granted string
	var receivedSec int64
	var receivedNanos int32
	// Work's closed row codec admits nullable int64, not nullable int32.
	// pgx widens the int4 column losslessly; no raw driver handle is needed.
	var expiresSec, expiresNanos *int64
	p := rpPreparedTokenSet{Schema: 1}
	if err := row.Scan(&b.ProviderID, &b.Issuer, &b.ClientID, &configuration, &accountVersion, &link, &version, &connection,
		&requested, &granted, &p.ScopeReported, &receivedSec, &receivedNanos, &expiresSec, &expiresNanos, &p.Ciphertext); err != nil {
		return rpPreparedTokenSet{}, err
	}
	for _, field := range []struct {
		source string
		value  *uint64
	}{
		{configuration, &b.ConfigurationVersion}, {accountVersion, &b.AccountVersion}, {link, &b.SocialLinkVersion},
		{version, &p.Version}, {connection, &p.SocialConnectionVersion},
	} {
		n, err := strconv.ParseUint(field.source, 10, 64)
		if err != nil || n == 0 {
			return rpPreparedTokenSet{}, identity.UnavailableError{}
		}
		*field.value = n
	}
	if (expiresSec == nil) != (expiresNanos == nil) {
		return rpPreparedTokenSet{}, identity.UnavailableError{}
	}
	if p.Version > 1 {
		p.Schema = 2
	}
	p.Binding = b
	p.RequestedScopes = strings.Split(requested, " ")
	p.GrantedScopes = strings.Split(granted, " ")
	p.ReceivedAt = time.Unix(receivedSec, int64(receivedNanos)).UTC()
	if expiresSec != nil {
		p.AccessExpiresAt = time.Unix(*expiresSec, *expiresNanos).UTC()
	}
	return p, nil
}

// The caller enlists this CAS in the same Work as the kernel-owned social
// link increment. Match authenticated predecessor bytes as well as its exact
// versions, and keep the immutable link command attribution intact.
func compareAndSetProviderRefreshVault(ctx context.Context, exec func(context.Context, string, ...any) (int64, error), schema string, original, next rpPreparedTokenSet) error {
	if ctx == nil || exec == nil || !rpSchemaName(schema) || !providerRefreshVaultTransition(original, next) {
		return identity.InvalidInputError{Field: "oauth_refresh_vault"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b := original.Binding
	statement := strings.ReplaceAll(providerRefreshVaultUpdate, "@schema@", rpQuotedSchema(schema))
	n, err := exec(ctx, statement, string(b.TenantID), string(b.UserID), string(b.AccountID), b.ProviderID, b.Issuer, b.ClientID,
		b.ConfigurationVersion, b.AccountVersion, b.SocialLinkVersion, original.Version, original.SocialConnectionVersion, original.Ciphertext,
		next.Binding.SocialLinkVersion, next.Version, next.SocialConnectionVersion, strings.Join(next.RequestedScopes, " "),
		strings.Join(next.GrantedScopes, " "), next.ScopeReported, next.ReceivedAt.Unix(), next.ReceivedAt.Nanosecond(),
		next.AccessExpiresAt.Unix(), next.AccessExpiresAt.Nanosecond(), next.Ciphertext)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// Definitive invalid_grant retires the old ciphertext, without claiming remote
// revocation. Keep the versioned row so the existing exact unlink path can
// erase it; missing access expiry makes the row ineligible for any token use.
func retireRejectedProviderRefreshVault(ctx context.Context, exec func(context.Context, string, ...any) (int64, error), schema string, original rpPreparedTokenSet, linkVersion uint64) error {
	if ctx == nil || exec == nil || !rpSchemaName(schema) || linkVersion == 0 {
		return identity.InvalidInputError{Field: "oauth_refresh_retirement"}
	}
	b := original.Binding
	if b.TenantID == "" || b.UserID == "" || b.AccountID == "" || b.AccountVersion == 0 ||
		b.SocialLinkVersion == 0 || b.SocialLinkVersion == math.MaxUint64 || linkVersion != b.SocialLinkVersion+1 ||
		original.Version == 0 || original.Version == math.MaxUint64 || original.SocialConnectionVersion != original.Version ||
		len(original.Ciphertext) == 0 || len(original.Ciphertext) > rpMaximumTokenCiphertext || original.AccessExpiresAt.IsZero() {
		return identity.InvalidInputError{Field: "oauth_refresh_retirement"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	statement := strings.ReplaceAll(providerRefreshVaultRetirement, "@schema@", rpQuotedSchema(schema))
	n, err := exec(ctx, statement, string(b.TenantID), string(b.UserID), string(b.AccountID), b.ProviderID, b.Issuer,
		b.ClientID, b.ConfigurationVersion, b.AccountVersion, b.SocialLinkVersion, original.Version,
		original.SocialConnectionVersion, original.Ciphertext, linkVersion, original.Version+1)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func providerRefreshVaultTransition(original, next rpPreparedTokenSet) bool {
	b := original.Binding
	if b.TenantID == "" || b.UserID == "" || b.AccountID == "" || b.AccountVersion == 0 ||
		b.SocialLinkVersion == 0 || b.SocialLinkVersion == math.MaxUint64 || original.Version == 0 ||
		original.Version == math.MaxUint64 || original.SocialConnectionVersion != original.Version || next.Schema != 2 {
		return false
	}
	b.SocialLinkVersion++
	return next.Binding == b && next.Version == original.Version+1 && next.SocialConnectionVersion == next.Version &&
		rpTokenVaultScopes(next.RequestedScopes) && rpTokenVaultScopes(next.GrantedScopes) &&
		rpUTCTime(next.ReceivedAt) && rpUTCTime(next.AccessExpiresAt) && next.AccessExpiresAt.After(next.ReceivedAt) &&
		len(original.Ciphertext) > 0 && len(original.Ciphertext) <= rpMaximumTokenCiphertext &&
		len(next.Ciphertext) > 0 && len(next.Ciphertext) <= rpMaximumTokenCiphertext
}

const providerRefreshVaultUpdate = `UPDATE @schema@.token_sets
 SET social_link_version=$13::numeric,version=$14::numeric,social_connection_version=$15::numeric,
 requested_scopes=string_to_array($16,' '),granted_scopes=string_to_array($17,' '),scope_reported=$18,
 received_at_seconds=$19,received_at_nanoseconds=$20,access_expires_at_seconds=$21,
 access_expires_at_nanoseconds=$22,token_ciphertext=$23
 WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND provider_id=$4 AND issuer=$5 AND client_id=$6
 AND configuration_version=$7::numeric AND account_version=$8::numeric AND social_link_version=$9::numeric
 AND version=$10::numeric AND social_connection_version=$11::numeric AND token_ciphertext=$12`

const providerRefreshVaultRetirement = `UPDATE @schema@.token_sets
 SET social_link_version=$13::numeric,version=$14::numeric,social_connection_version=$14::numeric,
 access_expires_at_seconds=NULL,access_expires_at_nanoseconds=NULL,token_ciphertext=decode('00','hex')
 WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND provider_id=$4 AND issuer=$5 AND client_id=$6
 AND configuration_version=$7::numeric AND account_version=$8::numeric AND social_link_version=$9::numeric
 AND version=$10::numeric AND social_connection_version=$11::numeric AND token_ciphertext=$12`
