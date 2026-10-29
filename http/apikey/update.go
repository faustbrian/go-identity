package apikeyhttp

import (
	"net/http"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

type updateBody struct {
	OrganizationID apikey.OrganizationID
	Name           string
	Permissions    *[]string
}

func (in *input) updateRequest() apikey.UpdateRequest {
	var permissions []string
	if in.update.Permissions != nil {
		permissions = *in.update.Permissions
	}
	return apikey.UpdateRequest{Authentication: in.auth, OrganizationID: in.update.OrganizationID, IdempotencyKey: in.key, KeyID: in.mutation.KeyID, ExpectedVersion: in.mutation.ExpectedVersion, Name: in.update.Name, Permissions: permissions, Network: in.facts.ClientIP().String()}
}

// Keep the update response separate from issuance: no secret-bearing field can
// be populated, and the shared metadata projection preserves absent legacy expiry.
type updateResponse struct {
	Committed     bool               `json:"committed"`
	CommitOutcome string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	Recovery      *recoveryScope     `json:"recovery,omitempty"`
	Key           *metadataKeyView   `json:"key,omitempty"`
	Error         string             `json:"error,omitempty"`
}

func writeUpdate(w http.ResponseWriter, r *http.Request, in *input, result apikey.UpdateResult, err error, now func() time.Time) {
	if result.Receipt.Binding == (identity.CommandBinding{}) {
		reject(w, r, nonNil(err, failure{status: 503, code: "unavailable"}))
		return
	}
	status, receipt := projectReceipt(in, result.Receipt, err)
	out := updateResponse{Committed: receipt.Committed, CommitOutcome: receipt.CommitOutcome, CommandID: receipt.CommandID, Recovery: receipt.Recovery, Error: receipt.Error}
	invalid := func() { writeJSON(w, 503, updateResponse{CommitOutcome: "unknown", Error: "unavailable"}) }
	if !receipt.Committed {
		if result.Record != nil || result.ConfigurationAuthority != nil {
			invalid()
			return
		}
		writeJSON(w, status, out)
		return
	}
	if result.Record == nil || result.ConfigurationAuthority == nil || r.Context().Err() != nil || in.observed.ValidateAt(now()) != nil {
		// Retain the safe original recovery binding even if response authority
		// expired after commitment; do not disclose its private snapshot.
		out.Committed, out.CommitOutcome, out.Error = false, "unknown", "unavailable"
		writeJSON(w, 503, out)
		return
	}
	record := *result.Record
	metadata := &metadataInput{get: apikey.GetRequest{Authentication: in.auth, OrganizationID: in.update.OrganizationID, KeyID: in.mutation.KeyID}, actor: in.actor}
	view, viewErr := metadataView(metadata, record)
	if viewErr != nil || record.ID != in.mutation.KeyID || record.Version != result.Receipt.Feature.AfterVersion || record.Status != apikey.KeyActive || record.Name != in.update.Name || !slices.Equal(record.Grant, *in.update.Permissions) || result.ConfigurationAuthority.Validate(in.auth.TenantID, record.ConfigurationID) != nil {
		invalid()
		return
	}
	out.Key = &view
	writeJSON(w, status, out)
}
