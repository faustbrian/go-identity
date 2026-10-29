package apikey

import (
	"context"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// UpdateRequest is one exact keyed replacement of a key's name and permission
// ceiling. Name is mandatory, 1..128 UTF-8 bytes. Permissions must be nonnil,
// bytewise sorted and duplicate-free, with at most 64 entries: an explicit empty
// slice removes every permission, while nil is invalid rather than inheritance.
// To rename only, supply the unchanged grant. Native current authority must
// admit every retained permission; the requested grant can never expand the
// existing immutable ceiling or restore a permission that current policy denies.
//
// Empty OrganizationID selects the actual bearer's self-owned key. A nonempty
// target explicitly selects organization ownership and requires current native
// membership and management permission. The key ID and target grant neither.
// The native owner must require the original fresh human credential proof and
// exact ExpectedVersion, preserving all earlier primary/proof deadlines.
//
// Credential bytes/digest, owner identity, configuration, lineage, status,
// creation time and expiry (including selected absent legacy expiry) cannot be
// selected or changed here. Revoked or expired keys cannot be updated. Network
// has CreateRequest's trusted canonical transport provenance, not a body claim.
type UpdateRequest struct {
	Authentication  Authentication
	OrganizationID  OrganizationID
	IdempotencyKey  identity.IdempotencyKey
	KeyID           KeyID
	ExpectedVersion uint64
	Name            string
	Permissions     []string
	CorrelationID   string
	Network         string
}

// UpdateResult retains the existing coordinator's exact command outcome. A
// Record and ConfigurationAuthority are present only for a proven committed
// update, never for an unknown, conflicting or uncommitted outcome. The record
// is a copied original post-update metadata snapshot, not fresh authentication
// or effective current authority; use MetadataService for a current safe read.
//
// A name-only update advances Record.Version for optimistic concurrency but
// does not advance the credential AuthorityVersion, RootVersion or shared
// configuration authority. Permission narrowing advances those existing
// security dimensions exactly once; it creates no new key, credential root or
// lineage. Required counters, audit and attributable lifecycle effects belong
// to the same sole protected transaction as the update.
//
// Matching replay/recovery can return the original terminal result only after
// current human/owner authorization. An uncertain result retains Receipt's
// original recovery binding and cannot execute another intent, reveal material
// or manufacture a committed snapshot. No result carries a key secret/digest.
type UpdateResult struct {
	Receipt                identity.CommandResult
	Record                 *Record
	ConfigurationAuthority *ConfigurationAuthorityBinding
}

// Updater is the optional finite native name/permission-management extension.
// Service remains source-compatible. Calls require a bounded context, current
// fresh real human authority and one stable nonzero idempotency key. Applications
// supply configuration and bounded policy, never missing stores or a separate
// transaction/replay authority. No secret is generated, revealed or reconstructed.
type Updater interface {
	Update(context.Context, UpdateRequest) (UpdateResult, error)
}

// Validate checks bounded request shape, never current human/owner authority.
func (r UpdateRequest) Validate() error {
	if r.Authentication.Validate() != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.ExpectedVersion == 0 || r.ExpectedVersion == ^uint64(0) || len(r.Name) == 0 || len(r.Name) > 128 || !utf8.ValidString(r.Name) || r.Permissions == nil || !validPermissions(r.Permissions) || r.OrganizationID != "" && !scope(string(r.OrganizationID), 128) || len(r.CorrelationID) > 128 || !canonicalNetwork(r.Network) {
		return ErrInvalid
	}
	_, err := ParseKeyID(string(r.KeyID))
	return err
}

// Validate checks a trusted adapter's outcome projection, never commitment.
func (r UpdateResult) Validate(c Configuration) error {
	b, f := r.Receipt.Binding, r.Receipt.Feature
	if c.Validate() != nil || r.Receipt.Validate() != nil || f == nil || f.Operation.Owner != "identity/apikey" || b.OperationID != "identity.apikey.update" || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(b.UserID) {
		return ErrInvalid
	}
	schema := "apikey-update-v1"
	if b.SchemaID == "apikey-update-organization-v1" {
		schema = b.SchemaID
	}
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if f.Operation != op || b.ValidateFor(op) != nil {
		return ErrInvalid
	}
	if r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		if r.Record != nil || r.ConfigurationAuthority != nil {
			return ErrInvalid
		}
		return nil
	}
	if r.Record == nil || r.ConfigurationAuthority == nil || f.BeforeVersion == 0 {
		return ErrInvalid
	}
	record := r.Record
	owner := record.Owner.spec
	if record.Validate(c) != nil || record.ID != KeyID(b.RecordID) || record.Version != f.AfterVersion || record.Status != KeyActive || len(record.Name) == 0 || !utf8.ValidString(record.Name) || owner.TenantID != b.TenantID || r.ConfigurationAuthority.Validate(b.TenantID, c.spec.ID) != nil {
		return ErrInvalid
	}
	if schema == "apikey-update-organization-v1" {
		if owner.Kind != OwnerOrganization {
			return ErrInvalid
		}
	} else if owner.Kind != OwnerUser || owner.UserID != b.UserID {
		return ErrInvalid
	}
	return nil
}

func (UpdateRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.UpdateRequest(redacted)")
}
func (UpdateRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (UpdateResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.UpdateResult(redacted)")
}
func (UpdateResult) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
