package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func isCaptchaOperation(op identity.FeatureOperation) bool {
	return op == CaptchaIssueOperation(identity.FeatureSubjectUser) || op == CaptchaIssueOperation(identity.FeatureSubjectAnonymousFlow)
}

func captchaTransition(p identitypostgres.LifecyclePlan) bool {
	return p.EventType == "identity.captcha.issued.v1" && p.BeforeVersion == 0 && p.AfterVersion == 1
}

func (r *Repository) validateCaptchaFeature(c identity.Command, p identitypostgres.CommandPlan) error {
	s, ok := c.Feature()
	if !ok || !isCaptchaOperation(s.Operation) {
		return risk.ErrInvalidEvidenceExecution
	}
	if _, err := r.restoreCaptcha(c); err != nil {
		return err
	}
	if !p.CaptchaReplayReservation || p.SubjectType != "captcha_evidence" || p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != s.Operation || p.Capability != nil || p.CapabilityIssuance != nil || p.RiskEvidence != nil || p.CommandCounters != nil || p.Delivery != nil || p.Lifecycle == nil || !captchaTransition(*p.Lifecycle) || len(p.Audits) != 1 {
		return risk.ErrInvalidEvidenceExecution
	}
	a := p.Audits[0]
	if a.EventType != "identity.captcha.verify" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 {
		return risk.ErrInvalidEvidenceExecution
	}
	return nil
}

// Domain use compares the locked primary winner against sealed current Work
// linkage, never caller-supplied generation or a signature alone. All original
// aliases/key versions are rechecked before sampling expiry after lock waits.
func (r *Repository) applyCaptcha(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, feature, transition, err := w.FeatureScope(r)
	s, ok := c.Feature()
	if err != nil || !ok || b != s.Binding || feature.Contributor != r.Descriptor() || feature.Operation != s.Operation || !isCaptchaOperation(s.Operation) || !captchaTransition(transition) {
		return identity.FeatureReceipt{}, risk.ErrInvalidEvidenceExecution
	}
	issue, err := r.restoreCaptcha(c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	owner, err := w.CaptchaReplayOwnership(r)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	link := bindingDigest(b)
	rows, err := w.Query(ctx, `SELECT command_fingerprint,generation::text,binding_digest,intent_digest,configuration_digest FROM `+r.schema+`.captcha_replay_winners WHERE tenant_id=$1 AND command_id=$2 FOR UPDATE`, string(b.TenantID), id)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var fingerprint, binding, intent, configuration []byte
	var generation string
	matched := rows.Next() && rows.Scan(&fingerprint, &generation, &binding, &intent, &configuration) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	p := issue.Prepared()
	if !matched || generation != strconv.FormatUint(owner.Generation, 10) || !bytes.Equal(fingerprint, owner.Fingerprint[:]) || !bytes.Equal(binding, link[:]) || !bytes.Equal(intent, p.Binding.IntentDigest[:]) || !bytes.Equal(configuration, p.ConfigurationDigest[:]) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	replay := p.Binding.Replay
	for _, alias := range replay.Keys {
		rows, err := w.Query(ctx, `SELECT a.command_id FROM `+r.schema+`.captcha_replay_aliases a JOIN `+r.schema+`.captcha_replay_alias_versions v USING(tenant_id,provider,site,api_profile,configuration_version,fingerprint) WHERE a.tenant_id=$1 AND a.provider=$2 AND a.site=$3 AND a.api_profile=$4 AND a.configuration_version=$5 AND a.fingerprint=$6 AND v.key_version=$7 FOR UPDATE OF a`, string(b.TenantID), replay.Provider, replay.Site, replay.APIProfile, replay.ConfigurationVersion, alias.Fingerprint, int64(alias.Version))
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		var winner []byte
		matched := rows.Next() && rows.Scan(&winner) == nil
		if rows.Next() || rows.Err() != nil {
			matched = false
		}
		rows.Close()
		if !matched || !bytes.Equal(winner, id) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := issue.Materialize(now)
	if err != nil {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	envelope, err := r.cipher.sealCaptcha(ctx, b, record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(envelope)
	count, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.captcha_issued_evidence(tenant_id,command_id,command_purpose,user_id,anonymous_flow_id,binding_digest,intent_digest,proof_digest,evidence_digest,key_version,hostname,issued_at,expires_at,state,response_envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'issued',$14) ON CONFLICT DO NOTHING`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.AnonymousFlowID, link[:], record.IntentDigest[:], record.ProofDigest[:], record.EvidenceDigest[:], int64(record.KeyVersion), record.Hostname, record.IssuedAt, record.ExpiresAt, envelope)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}

// This initial profile never prunes evidence. Absence proves this participant
// did not commit only under the coordinator's locked primary recovery and exact
// persisted replay owner. Missing/foreign owner or corrupt ciphertext is unknown;
// neither expiry nor elapsed lease time is proof of rollback.
func (r *Repository) recoverCaptcha(ctx context.Context, w identitypostgres.RecoveryWork, b identity.CommandBinding, feature identitypostgres.FeatureRegistration, transition identitypostgres.LifecyclePlan) (identitypostgres.RecoveryStatus, error) {
	unknown := func() (identitypostgres.RecoveryStatus, error) {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	if feature.Contributor != r.Descriptor() || !captchaTransition(transition) {
		return unknown()
	}
	owner, err := w.CaptchaReplayOwnership(r)
	if err != nil {
		return unknown()
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	link := bindingDigest(b)
	rows, err := w.Query(ctx, `SELECT command_fingerprint,generation::text,binding_digest FROM `+r.schema+`.captcha_replay_winners WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return unknown()
	}
	var fingerprint, binding []byte
	var generation string
	matched := rows.Next() && rows.Scan(&fingerprint, &generation, &binding) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched || owner.PreviousGeneration == 0 || generation != strconv.FormatUint(owner.PreviousGeneration, 10) || !bytes.Equal(fingerprint, owner.Fingerprint[:]) || !bytes.Equal(binding, link[:]) {
		return unknown()
	}
	rows, err = w.Query(ctx, `SELECT user_id,anonymous_flow_id,command_purpose,binding_digest,intent_digest,proof_digest,evidence_digest,key_version,hostname,issued_at,expires_at,state,response_envelope FROM `+r.schema+`.captcha_issued_evidence WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return unknown()
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return unknown()
		}
		return r.classifyCaptchaRecovery(ctx, b, nil)
	}
	var row captchaRecoveryRow
	if rows.Scan(&row.user, &row.flow, &row.purpose, &row.binding, &row.intent, &row.proof, &row.lookup, &row.key, &row.record.Hostname, &row.record.IssuedAt, &row.record.ExpiresAt, &row.state, &row.envelope) != nil || rows.Next() || rows.Err() != nil {
		clear(row.envelope)
		return unknown()
	}
	defer clear(row.envelope)
	return r.classifyCaptchaRecovery(ctx, b, &row)
}

type captchaRecoveryRow struct {
	user, flow, purpose, state               string
	binding, intent, proof, lookup, envelope []byte
	key                                      int64
	record                                   risk.CaptchaEvidenceRecord
}

// Pure retained-row classification after the caller has established exact
// sealed primary ownership. No SQL, authority, ownership transfer or response
// disclosure happens here. Nil means the primary read proved row absence; a
// caller without that proving read cannot use this helper as rollback proof.
func (r *Repository) classifyCaptchaRecovery(ctx context.Context, b identity.CommandBinding, row *captchaRecoveryRow) (identitypostgres.RecoveryStatus, error) {
	unknown := func() (identitypostgres.RecoveryStatus, error) {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	if r == nil || ctx == nil {
		return unknown()
	}
	if row == nil {
		return identitypostgres.RecoveryNotCommitted, nil
	}
	link := bindingDigest(b)
	if row.user != string(b.UserID) || row.flow != b.AnonymousFlowID || row.purpose != b.OperationID || !bytes.Equal(row.binding, link[:]) || len(row.intent) != 32 || len(row.proof) != 32 || len(row.lookup) != 32 || row.key < 1 || row.key > 4294967295 || !issuedJournalState(row.state) {
		return unknown()
	}
	record := row.record
	record.IntentDigest, record.ProofDigest, record.EvidenceDigest = [32]byte(row.intent), [32]byte(row.proof), [32]byte(row.lookup)
	record.KeyVersion = uint32(row.key)
	record.IssuedAt, record.ExpiresAt = record.IssuedAt.UTC(), record.ExpiresAt.UTC()
	if _, err := r.cipher.openCaptcha(ctx, b, record, row.envelope); err != nil {
		return unknown()
	}
	return identitypostgres.RecoveryCommitted, nil
}
