package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

var _ mfapg.TOTPURIPrimarySource = (*MFAEnablePrimarySource)(nil)
var _ mfapg.TOTPConfirmationPrimarySource = (*MFAEnablePrimarySource)(nil)
var _ mfapg.TOTPURIPrimary = MFAEnableAdmission{}

type mfaURIPrimaryCustody struct {
	parent       identity.CommandID
	rowVersion   uint64
	token        session.CSRFToken
	key          session.CSRFKey
	confirmation bool
	otpSend      bool
	otpConfirm   bool
}

func (s mfaEnablePrimaryCustody) operation() identity.FeatureOperation {
	if s.uri == nil {
		return mfaEnableOperation()
	}
	if s.uri.confirmation {
		return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	if s.uri.otpConfirm {
		return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	if s.uri.otpSend {
		return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-uri", SchemaID: "mfa-totp-uri", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s mfaEnablePrimaryCustody) lifecycle(event string, before, after uint64) bool {
	if s.uri == nil {
		return event == "factor.enrollment-created.v1" && before == 0 && after == 1
	}
	if s.uri.confirmation || s.uri.otpConfirm {
		return event == "factor.enrolled.v1" && before == s.uri.rowVersion && after == before+1
	}
	if s.uri.otpSend {
		return event == "otp.sent.v1" && before == s.uri.rowVersion && after == before+1
	}
	return event == "factor.uri-revealed.v1" && before == s.uri.rowVersion && after == before+1
}

// RestoreEnrollmentForOTPConfirmation authenticates the retained enable
// provenance and original session/CSRF under the distinct OTP confirmation
// schema. It performs no comparison, primary consumption or freshness renewal.
func (s *MFAEnablePrimarySource) RestoreEnrollmentForOTPConfirmation(ctx context.Context, r mfa.OtpVerifyRequest, parent identity.CommandID, rowVersion uint64, wire []byte) (mfapg.TOTPURIPrimary, error) {
	if r.Enrollment == nil || r.Validate() != nil || r.TrustDevice {
		return nil, identity.InvalidInputError{Field: "mfa_otp_verify"}
	}
	input := mfa.TotpUriRequest{TenantID: r.TenantID, EnrollmentID: mfa.EnrollmentID(r.FactorID), CommandID: r.CommandID, Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}
	base, err := s.restoreEnrollmentManagement(ctx, input, parent, rowVersion, wire, false)
	if err != nil {
		return nil, err
	}
	a, ok := base.(MFAEnableAdmission)
	if !ok || a.custody == nil {
		return nil, identity.ForbiddenError{}
	}
	c := a.custody()
	u := *c.uri
	u.otpConfirm = true
	c.uri = &u
	return MFAEnableAdmission{custody: func() mfaEnablePrimaryCustody { return c }}, nil
}

// RestoreEnrollmentForURI reconstructs exact original enrollment custody for a
// separate URI command after the MFA owner authenticates its retained encrypted
// input. It performs no IO, lookup, proof renewal or state mutation. It verifies
// original bearer possession and synchronizer against the same original session;
// missing retained keys/state deny, never falling back to bearer-only admission.
// Protected Admit independently fences current owners and the parent proof-use
// marker. Neither naked snapshots nor a successful restore authorize disclosure.
func (s *MFAEnablePrimarySource) RestoreEnrollmentForURI(ctx context.Context, r mfa.TotpUriRequest, parent identity.CommandID, rowVersion uint64, wire []byte) (mfapg.TOTPURIPrimary, error) {
	if r.Validate() != nil {
		return nil, identity.InvalidInputError{Field: "mfa_totp_uri"}
	}
	return s.restoreEnrollmentManagement(ctx, r, parent, rowVersion, wire, false)
}

// RestoreEnrollmentForOTPSend restores only the authenticated pending OTP
// variant under its actual send schema. It does not consume enable proof again,
// generate a code, select a recipient or renew original authentication age.
func (s *MFAEnablePrimarySource) RestoreEnrollmentForOTPSend(ctx context.Context, r mfa.OtpSendRequest, assigned, parent identity.CommandID, rowVersion uint64, wire []byte) (mfapg.TOTPURIPrimary, error) {
	if r.Enrollment == nil || r.Validate() != nil {
		return nil, identity.InvalidInputError{Field: "mfa_otp_send"}
	}
	input := mfa.TotpUriRequest{TenantID: r.TenantID, EnrollmentID: mfa.EnrollmentID(r.FactorID), CommandID: assigned, Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}
	base, err := s.restoreEnrollmentManagement(ctx, input, parent, rowVersion, wire, false)
	if err != nil {
		return nil, err
	}
	a, ok := base.(MFAEnableAdmission)
	if !ok || a.custody == nil {
		return nil, identity.ForbiddenError{}
	}
	c := a.custody()
	u := *c.uri
	u.otpSend = true
	c.uri = &u
	return MFAEnableAdmission{custody: func() mfaEnablePrimaryCustody { return c }}, nil
}

// RestoreEnrollmentForConfirmation retains original enable evidence for the
// explicit authenticated enrollment variant. It performs no code computation,
// proof consumption, activation, session issuance or freshness renewal. Current
// protected admission remains required; a URI command cannot reuse this custody.
func (s *MFAEnablePrimarySource) RestoreEnrollmentForConfirmation(ctx context.Context, r mfa.TotpVerifyRequest, parent identity.CommandID, rowVersion uint64, wire []byte) (mfapg.TOTPConfirmationPrimary, error) {
	if r.Enrollment == nil || r.Validate() != nil {
		return nil, identity.InvalidInputError{Field: "mfa_totp_verify"}
	}
	// This is a scalar carrier for shared provenance restoration, not an URI
	// request or an authorization decision. Preserve the actual verify action;
	// the public variant has already been checked, and command custody below
	// selects only the distinct enrollment-confirmation schema/lifecycle.
	input := mfa.TotpUriRequest{TenantID: r.TenantID, EnrollmentID: mfa.EnrollmentID(r.FactorID), CommandID: r.CommandID, Session: r.Enrollment.Session, CSRFToken: r.Enrollment.CSRFToken, Caller: r.Caller, Origin: r.Origin, Network: r.Network}
	return s.restoreEnrollmentManagement(ctx, input, parent, rowVersion, wire, true)
}

func (s *MFAEnablePrimarySource) restoreEnrollmentManagement(ctx context.Context, r mfa.TotpUriRequest, parent identity.CommandID, rowVersion uint64, wire []byte, confirmation bool) (mfapg.TOTPURIPrimary, error) {
	if ctx == nil || s == nil || s.source == nil || s.validator == nil || len(s.csrfKeys) == 0 || len(wire) == 0 || len(wire) > maximumMFAEnableSnapshot || rowVersion == 0 || rowVersion == math.MaxUint64 {
		return nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := identity.ParseCommandID(string(parent)); err != nil || parent == r.CommandID {
		return nil, identity.ForbiddenError{}
	}
	// Only extract the record needed to invoke the existing strict canonical
	// Restore. No field from this preliminary decode grants authority; Restore
	// validates the complete snapshot/configuration/record and bearer commitment.
	var snapshot mfaEnableSnapshot
	if json.Unmarshal(wire, &snapshot) != nil {
		return nil, password.ErrPasswordWork
	}
	defer clear(snapshot.Record)
	var record auth.SignedReauthenticationRecord
	if json.Unmarshal(snapshot.Record, &record) != nil {
		return nil, password.ErrPasswordWork
	}
	defer clear(record.Signature)
	parentRequest := MFAEnablePrimaryRequest{TenantID: r.TenantID, CommandID: parent, FactorID: string(r.EnrollmentID), Session: r.Session, Proof: record.Proof, Caller: r.Caller}
	if snapshot.Cookie {
		parentRequest.CSRFToken = r.CSRFToken
	}
	a, err := s.Restore(ctx, parentRequest, wire)
	if err != nil {
		return nil, err
	}
	c := a.custody()
	b, err := c.original.Bindings()
	state, stateErr := c.original.CSRFState().Bindings()
	if err != nil || stateErr != nil {
		return nil, identity.ForbiddenError{}
	}
	var key session.CSRFKey
	for _, candidate := range s.csrfKeys {
		if candidate.Version() == state.KeyVersion {
			key = candidate
			break
		}
	}
	if key.Version() == 0 || c.original.CSRFState().Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, r.CSRFToken, key) != nil {
		return nil, identity.ForbiddenError{}
	}
	c.request.CommandID = r.CommandID
	c.request.Caller = r.Caller.Clone()
	c.uri = &mfaURIPrimaryCustody{parent: parent, rowVersion: rowVersion, token: r.CSRFToken, key: key, confirmation: confirmation}
	return MFAEnableAdmission{custody: func() mfaEnablePrimaryCustody { return c }}, nil
}

func (s mfaEnablePrimaryCustody) admitURI(ctx context.Context, w kernel.Work, b identity.CommandBinding) error {
	if s.uri == nil {
		return identity.ForbiddenError{}
	}
	if err := sessionpg.RequireCSRF(ctx, w, s.source.source.c.Session, s.original, s.uri.token, s.uri.key); err != nil {
		return err
	}
	parent, err := base64.RawURLEncoding.Strict().DecodeString(string(s.uri.parent))
	if err != nil {
		return password.ErrPasswordWork
	}
	expected, err := encodeReauthenticationRecord(s.record)
	if err != nil {
		return err
	}
	defer clear(expected)
	// The issuance and parent enrollment must both be committed. Fencing the
	// immutable record distinguishes the exact original enable from a different
	// verification, another consumer, or an unconsumed proof. URI never consumes
	// that proof again and cannot repurpose it for an unrelated protected action.
	rows, err := w.Query(ctx, `SELECT CASE WHEN octet_length(p.record)<=$5 THEN p.record ELSE ''::bytea END
FROM identity_password.reauthentication_records p
JOIN identity.commands issued USING(tenant_id,purpose,command_id)
JOIN identity.commands parent ON parent.tenant_id=p.tenant_id AND parent.purpose=p.consumed_purpose AND parent.command_id=p.consumed_command_id
WHERE p.proof_id=$1 AND p.tenant_id=$2 AND p.user_id=$3 AND p.consumed_purpose='identity.mfa.enable' AND p.consumed_command_id=$4
AND issued.state='committed' AND parent.state='committed' FOR SHARE OF p`, string(s.record.Proof.Proof.ID), string(b.TenantID), string(b.UserID), parent, maximumReauthenticationRecordBytes)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var payload []byte
	if rows.Scan(&payload) != nil {
		return password.ErrPasswordWork
	}
	defer clear(payload)
	if rows.Next() || rows.Err() != nil || !bytes.Equal(expected, payload) {
		return identity.ForbiddenError{}
	}
	return nil
}
