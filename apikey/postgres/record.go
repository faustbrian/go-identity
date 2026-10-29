// Package postgres owns API-key persistence and native workflows through the
// existing identity coordinator. Reading a stored record is not authentication.
package postgres

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// Bound before parsing. This covers the root's bounded metadata/grants even
// when JSON escapes every permitted ASCII HTML metacharacter sixfold. Records
// are retained as canonical bytes, never JSONB-reformatted credential payloads.
const maximumRecordBytes = 64 << 10

// Verification envelopes repeat bounded records and grants. A snapshot has
// base64(64KiB record), at most 64KiB escaped permissions and <16KiB metadata;
// an effect adds another base64 record, grant and metadata. These separate
// bounds cover the core's 64 x 128-byte permissions even with sixfold JSON
// escaping, without relaxing individual records or the kernel's 1MiB cap.
const (
	maximumVerificationSnapshotBytes = 192 << 10
	maximumCommandEffectBytes        = 384 << 10
)

// Deliberate scalar projection: core Owner/Record custody is not implicitly
// serializable, and no field here can carry a raw or encrypted API-key secret.
type ownerRecord struct {
	TenantID       identity.TenantID
	Kind           apikey.OwnerKind
	UserID         identity.UserID
	OrganizationID apikey.OrganizationID
	Version        uint64
}

type keyRecord struct {
	Schema                        uint16
	ID                            apikey.KeyID
	Owner                         ownerRecord
	Version, AuthorityVersion     uint64
	ConfigurationID               string
	ConfigurationRevision         uint64
	Name                          string
	Status                        apikey.KeyStatus
	Grant                         []string
	CreatedAt, ExpiresAt          time.Time
	RootID                        apikey.KeyID
	RootVersion                   uint64
	PreviousID                    apikey.KeyID
	Issuer, Environment, Audience string
}

func encodeRecord(r apikey.Record, c apikey.Configuration) ([]byte, error) {
	owner := r.Owner.Spec()
	if r.Validate(c) != nil || !utf8.ValidString(r.Name) || !exactTime(r.CreatedAt) || !r.ExpiresAt.IsZero() && !exactTime(r.ExpiresAt) {
		return nil, apikey.ErrInvalid
	}
	grant := append([]string{}, r.Grant...)
	v := keyRecord{Schema: 1, ID: r.ID, Owner: ownerRecord{owner.TenantID, owner.Kind, owner.UserID, owner.OrganizationID, owner.Version}, Version: r.Version, AuthorityVersion: r.AuthorityVersion, ConfigurationID: r.ConfigurationID, ConfigurationRevision: r.ConfigurationRevision, Name: r.Name, Status: r.Status, Grant: grant, CreatedAt: r.CreatedAt.UTC(), ExpiresAt: r.ExpiresAt.UTC(), RootID: r.RootID, RootVersion: r.RootVersion, PreviousID: r.PreviousID, Issuer: r.Issuer, Environment: r.Environment, Audience: r.Audience}
	wire, err := json.Marshal(v)
	if err != nil || len(wire) > maximumRecordBytes {
		return nil, apikey.ErrInvalid
	}
	return wire, nil
}

func decodeRecord(wire []byte, c apikey.Configuration) (apikey.Record, error) {
	if len(wire) == 0 || len(wire) > maximumRecordBytes || !utf8.Valid(wire) {
		return apikey.Record{}, apikey.ErrInvalid
	}
	var v keyRecord
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) != nil || v.Schema != 1 {
		return apikey.Record{}, apikey.ErrInvalid
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return apikey.Record{}, apikey.ErrInvalid
	}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: v.Owner.TenantID, Kind: v.Owner.Kind, UserID: v.Owner.UserID, OrganizationID: v.Owner.OrganizationID, Version: v.Owner.Version})
	if err != nil {
		return apikey.Record{}, apikey.ErrInvalid
	}
	r := apikey.Record{ID: v.ID, Owner: owner, Version: v.Version, AuthorityVersion: v.AuthorityVersion, ConfigurationID: v.ConfigurationID, ConfigurationRevision: v.ConfigurationRevision, Name: v.Name, Status: v.Status, Grant: append([]string{}, v.Grant...), CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, RootID: v.RootID, RootVersion: v.RootVersion, PreviousID: v.PreviousID, Issuer: v.Issuer, Environment: v.Environment, Audience: v.Audience}
	canonical, err := encodeRecord(r, c)
	if err != nil || !bytes.Equal(canonical, wire) {
		return apikey.Record{}, apikey.ErrInvalid
	}
	return r, nil
}

func exactTime(value time.Time) bool {
	u := value.UTC()
	return !u.IsZero() && u.Year() >= 1 && u.Year() <= 9999 && u.Nanosecond()%1000 == 0
}
