package postgres

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// persistPrivacyExportAllocation stores immutable admission metadata in the
// same Work that allocated its epoch. No caller can enlist this private phase.
// MAC verification establishes integrity only: the eventual protected owner
// must capture all cuts and enforce native session/proof/policy plus required
// audit/lifecycle effects before the sole coordinator may commit. Staging this
// row alone must never unlock a worker. No bearer or secret is stored here.
func persistPrivacyExportAllocation(ctx context.Context, w Work, c identity.PrivacyExportRequestCommand, snapshot identity.PrivacyExportSnapshotV1, key identity.PrivacyExportEvidenceKey) (identity.PrivacyExportRequestReceipt, error) {
	zero := identity.PrivacyExportRequestReceipt{}
	if err := w.usable(); err != nil {
		return zero, err
	}
	fail := func(err error) (identity.PrivacyExportRequestReceipt, error) { return zero, w.fail(w.state.ctx, err) }
	if ctx == nil || c.Binding != w.state.binding || w.state.privacyAllocation == nil || w.state.privacyReceipt != nil {
		return fail(invalidWork())
	}
	a := w.state.privacyAllocation
	digest, err := identity.PrivacyExportIntentDigest(c)
	if err != nil || digest != a.intentDigest || !snapshot.Valid() {
		return fail(invalidWork())
	}
	record := snapshot.Record()
	if _, err := key.VerifySnapshotV1(record); err != nil {
		return fail(invalidWork())
	}
	if record.ExportID != a.exportID || record.TenantID != c.Binding.TenantID || record.SubjectID != c.Binding.UserID || record.CommandID != c.Binding.CommandID || record.IdentityVersion != a.identityVersion || record.PrivacyEpoch != a.privacyEpoch || record.RequestedAtMicroseconds != a.requestedAtMicroseconds {
		return fail(invalidWork())
	}
	for i, projection := range c.Projections {
		if record.Contributors[i].ContributorID != projection.ContributorID || record.Contributors[i].ProjectionID != projection.ProjectionID {
			return fail(invalidWork())
		}
	}
	receipt := identity.PrivacyExportRequestReceipt{Status: identity.PrivacyExportQueued, Snapshot: record, ExpectedAuthorityVersion: c.ExpectedAuthorityVersion, ExpectedPrivacyEpoch: c.ExpectedPrivacyEpoch, MaximumBytes: c.MaximumBytes, ArtifactTTL: c.ArtifactTTL, IntentDigest: digest}
	// JSON is a bounded storage representation, not the integrity encoding:
	// the key owner verifies the unchanged deterministic-CBOR snapshot MAC.
	// Bytea avoids JSONB numeric coercion and preserves full uint64 counters.
	wire, err := json.Marshal(receipt)
	if err != nil || len(wire) == 0 || len(wire) > 32768 {
		return fail(identity.UnavailableError{})
	}
	changed, err := w.Exec(ctx, `INSERT INTO identity.privacy_export_jobs(tenant_id,user_id,export_id,command_id,privacy_epoch,status,requested_at,snapshot_digest,receipt)
 SELECT $1,$2,$3,$4,$5::text::numeric,'queued',$6,$7,$8
 FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND privacy_disposition='idle'
 AND version::text=$9 AND authority_version::text=$10 AND privacy_epoch::text=$5`, string(record.TenantID), string(record.SubjectID), string(record.ExportID), string(record.CommandID), strconv.FormatUint(record.PrivacyEpoch, 10), time.UnixMicro(record.RequestedAtMicroseconds).UTC(), record.Digest[:], wire, strconv.FormatUint(a.identityVersion, 10), strconv.FormatUint(a.authorityVersion, 10))
	if err != nil {
		return fail(err)
	}
	if changed != 1 {
		return fail(identity.ConflictError{})
	}
	stored := receipt
	stored.Snapshot = snapshot.Record()
	w.state.privacyReceipt = &stored
	return receipt, nil
}
