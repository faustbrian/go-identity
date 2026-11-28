package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

type approvalEpoch struct {
	userVersion          uint64
	authorizationVersion uint64
	namespace            string
}

func (e approvalEpoch) valid(tenant identity.TenantID, approver identity.UserID) bool {
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(tenant), SubjectID: authorization.SubjectID(approver), PolicyNamespace: e.namespace}
	return e.userVersion != 0 && e.authorizationVersion != 0 && scope.Validate() == nil
}

type activationApprovalPayload struct {
	Version              int    `json:"version"`
	Reason               string `json:"reason"`
	UserVersion          uint64 `json:"approver_user_version"`
	AuthorizationVersion uint64 `json:"approver_authorization_version"`
	Namespace            string `json:"authority_namespace"`
}

// The activation profile needs evidence that existed when the approval was
// admitted. Legacy approval-reason envelopes deliberately cannot be opened by
// this codec and never acquire a guessed historical authority epoch.
func sealActivationApproval(ctx context.Context, service *secretenvelope.Service, key string, grant grantRecord, decision approvalRecord, reason impersonation.Reason, epoch approvalEpoch) ([]byte, error) {
	if !epoch.valid(grant.tenant, decision.approver) {
		return nil, impersonation.ErrInvalidInput
	}
	if _, err := impersonation.NewReason(reason.StorageText()); err != nil {
		return nil, err
	}
	binding, err := activationApprovalBinding(grant, decision)
	if err != nil {
		return nil, err
	}
	wire, err := canonicalCustodyJSON(activationApprovalPayload{
		Version: 2, Reason: reason.StorageText(), UserVersion: epoch.userVersion,
		AuthorizationVersion: epoch.authorizationVersion, Namespace: epoch.namespace,
	})
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	return encryptCustody(ctx, service, key, binding, wire, maximumApprovalPlaintext)
}

// openActivationApproval touches the envelope provider outside kernel Work.
// The caller must bind the exact observed decision again inside the domain
// transaction; cryptographic custody alone is not current approval authority.
func openActivationApproval(ctx context.Context, service *secretenvelope.Service, grant grantRecord, decision approvalRecord) (impersonation.Reason, approvalEpoch, error) {
	binding, err := activationApprovalBinding(grant, decision)
	if err != nil {
		return impersonation.Reason{}, approvalEpoch{}, err
	}
	if ctx == nil || ctx.Err() != nil || service == nil || len(decision.payload) == 0 || len(decision.payload) > maximumCustodyEnvelope {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	envelope, err := secretenvelope.ParseEnvelope(decision.payload)
	if err != nil || len(envelope.Ciphertext()) > maximumApprovalPlaintext+16 {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	plain, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: binding})
	if err != nil {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	defer clear(plain)
	if len(plain) == 0 || len(plain) > maximumApprovalPlaintext {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	var payload activationApprovalPayload
	if err := json.Unmarshal(plain, &payload); err != nil || payload.Version != 2 {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	canonical, err := canonicalCustodyJSON(payload)
	if err != nil {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, plain) {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	reason, err := impersonation.NewReason(payload.Reason)
	epoch := approvalEpoch{userVersion: payload.UserVersion, authorizationVersion: payload.AuthorizationVersion, namespace: payload.Namespace}
	if err != nil || !epoch.valid(grant.tenant, decision.approver) {
		return impersonation.Reason{}, approvalEpoch{}, errCustody
	}
	return reason, epoch, nil
}

func activationApprovalBinding(g grantRecord, decision approvalRecord) (secretenvelope.Context, error) {
	id, err := identity.ParseCommandID(string(decision.commandID))
	if err != nil || string(id) == string(g.id) {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	approval, err := custodyBinding("approval-reason", g.tenant, g.id, g.requester, g.target, decision.approver, g.digest)
	if err != nil {
		return secretenvelope.Context{}, err
	}
	values := approval.Values()
	values["action"] = "activation-approval"
	values["approval_command"] = string(id)
	binding, err := secretenvelope.NewContext(values)
	if err != nil {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	return binding, nil
}
