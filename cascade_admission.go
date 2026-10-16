package identity

import (
	"fmt"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
)

// LifecycleCascadeKind names a selected identity-owned cascade, not completion.
// Unknown kinds deny until their exact scope and consumer contract is supported.
type LifecycleCascadeKind string

const (
	// IdentifierRemovalCascade starts cleanup after the identifier authority
	// mutation. Old-address authentication must already deny at admission.
	IdentifierRemovalCascade LifecycleCascadeKind = "lifecycle.cascade.identifier_remove"
)

// LifecycleCascadeAdmission is a historical pending owner admission, never
// authentication authority or asynchronous completion. Generation is initially
// one; AuthorityVersion is the identifier dimension for IdentifierRemovalCascade.
// Owners retains the exact manifest including unavailable consumers. Scope IDs
// are pseudonymous personal data; explicit JSON is for protected receipt storage
// or authorized projection. Treat values as immutable; Clone copies collections.
type LifecycleCascadeAdmission struct {
	CascadeID           CascadeID
	Generation          uint64
	Kind                LifecycleCascadeKind
	TenantID            TenantID
	UserID              UserID
	IdentifierID        IdentifierID
	AuthorityVersion    uint64
	ManifestVersion     string
	Status              RevocationStatus
	Owners              []RevocationOwnerReceipt
	ExternalLimitations []PolicyReason
}

// IdentifierRemovalConsumers returns the complete ordered version-one semantic
// consumer set. Missing adapters remain pending, never implicitly not-applicable.
// The caller owns this new slice; mutation cannot change the retained manifest.
func IdentifierRemovalConsumers() []string {
	return []string{"identity/password", "identity/email", "identity/phone", "identity/magiclink", "identity/otp", "organization", "identity/delivery", "sso", "identity/risk", "audit"}
}

// Validate checks exact pending admission shape and command scope, not database
// durability, current authority or consumer acknowledgement. Self and explicitly
// authorized administrative removal retain the target's scope, not the actor's.
// Native command admission owns authorization of a distinct human actor. Noncommitted
// outcomes must not carry this receipt; CommandResult enforces that distinction.
func (r LifecycleCascadeAdmission) Validate(b CommandBinding) error {
	invalid := InvalidInputError{Field: "cascade_admission"}
	op := FeatureOperation{Owner: "identity/email", OperationID: "identity.email.address-remove", SchemaID: "identity.email.address-remove.native-v1", SchemaVersion: 1, RecordRequirement: FeatureRecordRequired}
	if b.ValidateFor(op) != nil {
		return invalid
	}
	if _, err := ParseCascadeID(string(r.CascadeID)); err != nil {
		return invalid
	}
	if r.Generation != 1 || r.Kind != IdentifierRemovalCascade || r.TenantID != b.TenantID || r.UserID != b.UserID || string(r.IdentifierID) != b.RecordID || r.AuthorityVersion <= 1 || r.ManifestVersion != "identity-lifecycle-consumers-v1" || r.Status != RevocationPending || len(r.ExternalLimitations) != 0 || b.OperationID != "identity.email.address-remove" || b.SchemaID != "identity.email.address-remove.native-v1" || b.SchemaVersion != 1 || b.ActorKind != authorization.SubjectUser {
		return invalid
	}
	for _, id := range []string{string(r.TenantID), string(r.UserID), string(r.IdentifierID)} {
		if !validDirectoryID(id) {
			return invalid
		}
	}
	consumers := IdentifierRemovalConsumers()
	if len(r.Owners) != len(consumers) {
		return invalid
	}
	for i, owner := range r.Owners {
		if owner.Owner != consumers[i] || owner.Status != RevocationPending {
			return invalid
		}
	}
	return nil
}

// Clone returns caller-owned collections without changing admission identity.
func (r LifecycleCascadeAdmission) Clone() LifecycleCascadeAdmission {
	r.Owners = slices.Clone(r.Owners)
	r.ExternalLimitations = slices.Clone(r.ExternalLimitations)
	return r
}

// Format omits pseudonymous scope and historical command correlation.
func (LifecycleCascadeAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.LifecycleCascadeAdmission(redacted)"))
}
