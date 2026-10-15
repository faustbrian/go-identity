package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type preAuthIssueProfile struct {
	actor                            identity.ActorID
	action, origin, callback, policy string
	version                          uint64
}

func (p *preAuthIssueProfile) matches(b identity.CommandBinding, record session.PreAuthTransaction) bool {
	s, err := record.Bindings()
	if p == nil || err != nil {
		return false
	}
	i := s.Binding.Intent
	return b.ActorKind == authorization.SubjectServiceAccount && b.ActorID == p.actor && b.PolicyID == p.policy && b.PolicyVersion == p.version && i.Action == p.action && i.Origin == p.origin && i.CallbackURL == p.callback
}

func (r *Repository) validatePreAuthIssuePlan(command identity.Command, p kernel.CommandPlan) error {
	b, record, err := nativePreAuthIssue(command)
	if err != nil || r == nil || !r.preAuthIssue.matches(b, record) || p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != preAuthIssueOperation() || p.SubjectType != "preauth_transaction" || p.Lifecycle == nil || p.Lifecycle.EventType != "session.preauth-issued.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 1 || len(p.Audits) != 1 || p.Capability != nil || p.OTP != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CommandCounters != nil || p.Delivery != nil || p.CapabilityIssuance != nil || p.IdentifierAdmission != nil || p.CaptchaReplayReservation {
		return session.ErrInvalidPreAuthTransaction
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.preauth-issue" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" {
		return session.ErrInvalidPreAuthTransaction
	}
	return nil
}

func (r *Repository) applyPreAuthIssue(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	b, record, err := nativePreAuthIssue(command)
	if ctx == nil || err != nil || r == nil || !r.preAuthIssue.matches(b, record) {
		return identity.FeatureReceipt{}, session.ErrInvalidPreAuthTransaction
	}
	bound, feature, transition, err := w.FeatureScope(r)
	if err != nil || bound != b || feature.Operation != preAuthIssueOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return identity.FeatureReceipt{}, session.ErrInvalidPreAuthTransaction
	}
	config := Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}
	if err = InsertPreAuth(ctx, w, config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Admission uses locked primary time and the exact original commitment. An
	// expired/changed flow aborts issuance and its retained evidence together.
	if err = RequirePreAuth(ctx, w, config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	payload, err := encodePreAuth(record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	original := sha256.Sum256(payload)
	id, digest := preAuthIssueEvidence(b, original)
	n, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.preauth_issuances(tenant_id,command_id,purpose,flow_id,record_digest,binding_digest) VALUES($1,$2,$3,$4,$5,$6)`, string(b.TenantID), id, b.OperationID, b.RecordID, original[:], digest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: preAuthIssueOperation(), AfterVersion: 1}, nil
}

// Retained evidence is a native atomic effect, not a journal or live flow. It
// survives payload retirement so a missing cookie/flow cannot fabricate rollback.
func preAuthIssueEvidence(b identity.CommandBinding, record [32]byte) ([]byte, [32]byte) {
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	data, _ := json.Marshal(struct {
		Binding identity.CommandBinding
		Record  [32]byte
	}{b, record})
	return id, sha256.Sum256(append([]byte("identity-session-preauth-issuance-v1\x00"), data...))
}

func (r *Repository) recoverPreAuthIssue(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || r.preAuthIssue == nil || b.ActorKind != authorization.SubjectServiceAccount || b.ActorID != r.preAuthIssue.actor || b.PolicyID != r.preAuthIssue.policy || b.PolicyVersion != r.preAuthIssue.version || feature.Operation != preAuthIssueOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return kernel.RecoveryUnknown, session.ErrInvalidPreAuthTransaction
	}
	id, _ := preAuthIssueEvidence(b, [32]byte{})
	rows, err := w.Query(ctx, `SELECT purpose,flow_id,record_digest,binding_digest FROM `+r.schema+`.preauth_issuances WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var purpose, flow string
	var original, digest []byte
	if err = rows.Scan(&purpose, &flow, &original, &digest); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil || purpose != b.OperationID || flow != b.RecordID || len(original) != 32 {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	var record [32]byte
	copy(record[:], original)
	_, expected := preAuthIssueEvidence(b, record)
	if record == ([32]byte{}) || subtle.ConstantTimeCompare(digest, expected[:]) != 1 {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}
