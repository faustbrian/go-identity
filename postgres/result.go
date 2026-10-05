package postgres

import (
	"bytes"
	"encoding/json"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// The core bounds every nested receipt before encoding. This conservative
// limit includes escaped scalar/list attributes and their typed JSON overhead.
// This is protected replay storage, never an HTTP response or diagnostic.
const maxJournalResultBytes = 8 << 20

func encodeJournalResult(q claimRequest, r identity.CommandResult) ([]byte, error) {
	if r.Validate() != nil || (r.Outcome != identity.CommitOutcomeCommitted && r.Outcome != identity.CommitOutcomeNotCommitted) || !matchesResultFeature(q, r) || !matchesPrivacyResultIntent(q, r) || !bytes.Equal(q.safeFields, commandSafeFields(r.Binding, q.feature)) {
		return nil, identity.InvalidInputError{Field: "command_result"}
	}
	if r.Profile != nil {
		profile := *r.Profile
		profile.AdditionalFields = slices.Clone(profile.AdditionalFields)
		for i := range profile.AdditionalFields {
			value := &profile.AdditionalFields[i].Value
			if value.Kind == identity.AttributeTime {
				if !postgresExactTime(value.Scalar.Time) {
					return nil, identity.InvalidInputError{Field: "command_result_time"}
				}
				// JSON offsets have minute precision. UTC preserves instants from
				// historical or custom second-offset zones without caller mutation.
				value.Scalar.Time = value.Scalar.Time.UTC()
			}
		}
		r.Profile = &profile
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > maxJournalResultBytes {
		return nil, identity.UnavailableError{}
	}
	return b, nil
}

func matchesResultFeature(q claimRequest, r identity.CommandResult) bool {
	if q.feature == nil {
		return r.Feature == nil
	}
	return r.Feature != nil && r.Feature.Operation == *q.feature
}

// Request-bearing admission/replay retains the exact intent, not just its
// public scope. Scope-only journal observation stays structural: the service
// separately verifies the recorded snapshot MAC against its retained key.
// This comparison must not require a live proof or renew its lifetime.
func matchesPrivacyResultIntent(q claimRequest, r identity.CommandResult) bool {
	if r.PrivacyExport == nil || q.source == nil {
		return true
	}
	c, ok := q.source.RequestPrivacyExport()
	if !ok {
		return false
	}
	p := r.PrivacyExport
	digest, err := identity.PrivacyExportIntentDigest(c)
	if err != nil || r.Binding != c.Binding || p.IntentDigest != digest || p.ExpectedAuthorityVersion != c.ExpectedAuthorityVersion || p.ExpectedPrivacyEpoch != c.ExpectedPrivacyEpoch || p.Snapshot.IdentityVersion != c.ExpectedIdentityVersion || p.MaximumBytes != c.MaximumBytes || p.ArtifactTTL != c.ArtifactTTL || len(p.Snapshot.Contributors) != len(c.Projections) {
		return false
	}
	for i, projection := range c.Projections {
		if p.Snapshot.Contributors[i].ContributorID != projection.ContributorID || p.Snapshot.Contributors[i].ProjectionID != projection.ProjectionID {
			return false
		}
	}
	return true
}

func decodeJournalResult(q claimRequest, b []byte) (identity.CommandResult, error) {
	if len(b) == 0 || len(b) > maxJournalResultBytes {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	var r identity.CommandResult
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	canonical, e := encodeJournalResult(q, r)
	// Require the owned representation exactly: duplicate keys, trailing values,
	// unknown fields, lossy JSON numbers and alternate spellings fail closed.
	if e != nil || !bytes.Equal(b, canonical) {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	return r, nil
}
