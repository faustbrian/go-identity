package apikey

import (
	"context"
	"fmt"
	"io"
)

// GetRequest selects safe stored metadata, never credential verification.
// An empty OrganizationID means the actual bearer's own user; a nonempty one
// selects that organization explicitly and requires current native membership
// and management permission. Neither selection grants authority by itself.
type GetRequest struct {
	Authentication Authentication
	OrganizationID OrganizationID
	KeyID          KeyID
	CorrelationID  string
}

// Validate checks bounded shape only; the native service must authenticate and
// authorize the current real human, tenant, owner and stored configuration.
func (r GetRequest) Validate() error {
	if r.Authentication.Validate() != nil || r.OrganizationID != "" && !scope(string(r.OrganizationID), 128) || len(r.CorrelationID) > 128 {
		return ErrInvalid
	}
	_, err := ParseKeyID(string(r.KeyID))
	return err
}

// GetResult contains only a copied stored record. Revoked and expired records
// may be returned to an authorized manager. Grant is the stored immutable
// ceiling, not effective current permission; this result is not authentication,
// a VerificationResult, a reusable authorization decision or a session.
type GetResult struct {
	Record Record
}

// ListRequest selects one real owner and an optional exact configuration set.
// Empty ConfigurationIDs means all profiles selected by the native deployment;
// nonempty IDs must be bytewise sorted, duplicate-free and actually selected.
// Cursor is an opaque, scope-bound paging position, never an authorization
// credential. Limit is mandatory and ranges from 1 through 200.
type ListRequest struct {
	Authentication   Authentication
	OrganizationID   OrganizationID
	ConfigurationIDs []string
	Cursor           string
	Limit            uint16
	CorrelationID    string
}

// Validate bounds input before native decoding, lookup or allocation. Current
// configuration IDs follow ConfigurationSpec's existing 1..128-byte contract.
func (r ListRequest) Validate() error {
	if r.Authentication.Validate() != nil || r.OrganizationID != "" && !scope(string(r.OrganizationID), 128) || len(r.CorrelationID) > 128 || len(r.ConfigurationIDs) > 16 || len(r.Cursor) > 512 || r.Limit < 1 || r.Limit > 200 {
		return ErrInvalid
	}
	for i, id := range r.ConfigurationIDs {
		if !scope(id, 128) || i > 0 && r.ConfigurationIDs[i-1] >= id {
			return ErrInvalid
		}
	}
	return nil
}

// ListResult is a bounded, owned page in bytewise ascending KeyID order. Each
// record has GetResult's metadata-only meaning. NextCursor is absent at the end.
// Native keyset paging is a live view, not a historical snapshot: concurrent
// inserts behind the cursor are omitted and inserts ahead may appear. Existing
// keys are not repeated; no transaction is held between pages. Current human,
// owner and configuration authority must be checked independently on every page.
type ListResult struct {
	Records    []Record
	NextCursor string
}

// MetadataService is an additive read-only native extension. Service stays
// source-compatible for existing implementations. Reads require bounded
// contexts, never verify/debit a key or mutate its state, and return no secret
// or digest. Missing and unauthorized targets both return ErrDenied. Invalid
// input returns ErrInvalid; unavailable authority fails closed. These reads do
// not require a new sensitive-change proof and cannot supply one to mutations.
type MetadataService interface {
	Get(context.Context, GetRequest) (GetResult, error)
	List(context.Context, ListRequest) (ListResult, error)
}

func (GetRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.GetRequest(redacted)")
}
func (GetRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (ListRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.ListRequest(redacted)")
}
func (ListRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
