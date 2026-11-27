package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// The callback does not yet have a tenant identifier. This keyed lookup is
// scoped by the deployment and immutable provider configuration; the single
// matching row supplies the tenant, which still must be authenticated by AAD.
func proxyLookupDigest(key [32]byte, keyVersion uint32, production, provider string, providerVersion uint64, state [32]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-oauth-proxy-lookup-v1\x00"))
	var frame [16]byte
	binary.BigEndian.PutUint32(frame[:4], keyVersion)
	binary.BigEndian.PutUint64(frame[4:12], providerVersion)
	binary.BigEndian.PutUint16(frame[12:14], uint16(len(production)))
	binary.BigEndian.PutUint16(frame[14:], uint16(len(provider)))
	mac.Write(frame[:])
	mac.Write([]byte(production))
	mac.Write([]byte(provider))
	mac.Write(state[:])
	var out [32]byte
	mac.Sum(out[:0])
	return out
}

type proxyLookupSelection struct {
	production, provider, callback string
	providerVersion                uint64
	state                          [32]byte
}

type proxyLookupRow struct {
	tenant, transaction            string
	originCommand, callbackCommand []byte
	lookupDigest                   []byte
	stateKey                       uint32
	issued, expires, observed      time.Time
	version                        string
	binding, proof, verifier       []byte
}

func (proxyLookupRow) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth postgres proxy lookup (redacted)"))
}

func (row *proxyLookupRow) clear() {
	clear(row.binding)
	clear(row.proof)
	clear(row.verifier)
	*row = proxyLookupRow{}
}

type proxyLookupQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func proxyLookupSQL(schema string) string {
	// One equality probe for each retained key. The unique index guarantees at
	// most one inner row; two hits across retained keys are still ambiguous.
	return `SELECT t.tenant_id,t.transaction_id,t.origin_command_id,t.callback_command_id,t.state_key_version,t.state_lookup_digest,
 t.binding_ciphertext,t.state_proof_ciphertext,t.pkce_ciphertext,t.issued_at,t.expires_at,t.version::text,statement_timestamp()
 FROM unnest($5::bigint[],$6::bytea[]) AS k(version,digest)
 JOIN LATERAL (
  SELECT tenant_id,transaction_id,origin_command_id,callback_command_id,state_key_version,state_lookup_digest,
   binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version
  FROM ` + rpQuotedSchema(schema) + `.proxy_transactions
  WHERE production_deployment=$1 AND provider_id=$2 AND configuration_version=$3::numeric AND production_callback_uri=$4
   AND state_key_version=k.version AND state_lookup_digest=k.digest LIMIT 1
 ) AS t ON TRUE LIMIT 2`
}

func readProxyLookup(ctx context.Context, query proxyLookupQueryer, schema string, keys map[uint32][32]byte, in proxyLookupSelection) (row proxyLookupRow, err error) {
	if ctx == nil || query == nil || !rpSchemaName(schema) || !rpProviderID(in.production) || !rpProviderID(in.provider) ||
		!rpASCII(in.callback, 1, 2048) || in.providerVersion == 0 || in.state == ([32]byte{}) || len(keys) == 0 || len(keys) > 32 {
		return row, identity.InvalidInputError{Field: "oauth_proxy_lookup"}
	}
	defer func() {
		if err != nil {
			row.clear()
		}
	}()
	versions := make([]int64, 0, len(keys))
	for version, key := range keys {
		if version == 0 || key == ([32]byte{}) {
			return row, identity.InvalidInputError{Field: "oauth_proxy_lookup"}
		}
		versions = append(versions, int64(version))
	}
	slices.Sort(versions)
	digests := make([][]byte, len(versions))
	for i, version := range versions {
		digest := proxyLookupDigest(keys[uint32(version)], uint32(version), in.production, in.provider, in.providerVersion, in.state)
		digests[i] = digest[:]
	}
	rows, err := query.Query(ctx, proxyLookupSQL(schema), in.production, in.provider, in.providerVersion, in.callback, versions, digests)
	if err != nil {
		return row, identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return row, identity.UnavailableError{}
		}
		return row, identity.ForbiddenError{}
	}
	if rows.Scan(&row.tenant, &row.transaction, &row.originCommand, &row.callbackCommand, &row.stateKey, &row.lookupDigest,
		&row.binding, &row.proof, &row.verifier, &row.issued, &row.expires, &row.version, &row.observed) != nil || rows.Next() || rows.Err() != nil {
		return row, identity.UnavailableError{}
	}
	row.issued, row.expires, row.observed = row.issued.UTC(), row.expires.UTC(), row.observed.UTC()
	if row.observed.Before(row.issued) || !row.observed.Before(row.expires) || (row.version != "1" && row.version != "2") {
		return row, identity.ForbiddenError{}
	}
	return row, nil
}
