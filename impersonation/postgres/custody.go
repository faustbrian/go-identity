package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const (
	maximumCustodyEnvelope = 64 << 10
	// The typed request permits 64 128-byte permissions and a 1024-byte
	// reason. Non-HTML-escaped JSON fits within 32KiB even at their maximum
	// JSON escaping expansion; the approval's reason alone fits within 8KiB.
	maximumRequestPlaintext  = 32 << 10
	maximumApprovalPlaintext = 8 << 10
)

var errCustody = errors.New("impersonation postgres: custody rejected")

type originalRequest struct {
	request                                         impersonation.Request
	requesterAuthorityVersion, requesterUserVersion uint64
}

func (originalRequest) String() string     { return "[redacted original impersonation request]" }
func (r originalRequest) GoString() string { return r.String() }

type custodyRequestPayload struct {
	Version                   int               `json:"version"`
	Tenant                    identity.TenantID `json:"tenant"`
	Requester                 identity.UserID   `json:"requester"`
	Target                    identity.UserID   `json:"target"`
	TargetVersion             uint64            `json:"target_version"`
	DurationNS                int64             `json:"duration_ns"`
	Scope                     []string          `json:"scope"`
	Reason                    string            `json:"reason"`
	PolicyID                  string            `json:"policy_id"`
	PolicyVersion             uint64            `json:"policy_version"`
	RequesterAuthorityVersion uint64            `json:"requester_authority_version"`
	RequesterUserVersion      uint64            `json:"requester_user_version"`
}

type custodyApprovalPayload struct {
	Version int    `json:"version"`
	Reason  string `json:"reason"`
}

// sealRequest and openRequest perform provider I/O. The service must call them
// outside its transaction Work and revalidate authority inside that Work.
func sealRequest(ctx context.Context, service *secretenvelope.Service, key string, id impersonation.GrantID, original originalRequest) ([]byte, error) {
	validated, err := impersonation.NewRequest(original.request.Input())
	if err != nil || validated.Digest() != original.request.Digest() || original.requesterAuthorityVersion == 0 || original.requesterUserVersion == 0 {
		return nil, impersonation.ErrInvalidInput
	}
	binding, err := custodyBinding("request", validated.Tenant(), id, validated.Actor().User(), validated.Target().User(), "", validated.Digest())
	if err != nil {
		return nil, err
	}
	plaintext, err := marshalCustodyRequest(original)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return encryptCustody(ctx, service, key, binding, plaintext, maximumRequestPlaintext)
}

func openRequest(ctx context.Context, service *secretenvelope.Service, tenant identity.TenantID, id impersonation.GrantID, requester, target identity.UserID, digest [32]byte, encoded []byte) (originalRequest, error) {
	binding, err := custodyBinding("request", tenant, id, requester, target, "", digest)
	if err != nil {
		return originalRequest{}, err
	}
	if ctx == nil || ctx.Err() != nil || service == nil || len(encoded) == 0 || len(encoded) > maximumCustodyEnvelope {
		return originalRequest{}, errCustody
	}
	envelope, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil || len(envelope.Ciphertext()) > maximumRequestPlaintext+16 {
		return originalRequest{}, errCustody
	}
	plaintext, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: binding})
	if err != nil {
		return originalRequest{}, errCustody
	}
	defer clear(plaintext)
	if len(plaintext) == 0 || len(plaintext) > maximumRequestPlaintext {
		return originalRequest{}, errCustody
	}

	var payload custodyRequestPayload
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return originalRequest{}, errCustody
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return originalRequest{}, errCustody
	}
	if payload.Version != 1 || payload.Tenant != tenant || payload.Requester != requester || payload.Target != target || payload.RequesterAuthorityVersion == 0 || payload.RequesterUserVersion == 0 {
		return originalRequest{}, errCustody
	}

	original, err := originalFromCustody(payload)
	if err != nil || original.request.Digest() != digest {
		return originalRequest{}, errCustody
	}
	// Re-encode the reconstructed typed request, not the decoded wire value:
	// this also rejects duplicate fields, normalized scopes and alternate JSON.
	canonical, err := marshalCustodyRequest(original)
	if err != nil {
		return originalRequest{}, errCustody
	}
	defer clear(canonical)
	if !bytes.Equal(plaintext, canonical) {
		return originalRequest{}, errCustody
	}
	return original, nil
}

func sealApprovalReason(ctx context.Context, service *secretenvelope.Service, key string, tenant identity.TenantID, id impersonation.GrantID, requester, target, approver identity.UserID, digest [32]byte, reason impersonation.Reason) ([]byte, error) {
	validated, err := impersonation.NewReason(reason.StorageText())
	if err != nil {
		return nil, impersonation.ErrInvalidInput
	}
	binding, err := custodyBinding("approval-reason", tenant, id, requester, target, approver, digest)
	if err != nil {
		return nil, err
	}
	plaintext, err := canonicalCustodyJSON(custodyApprovalPayload{Version: 1, Reason: validated.StorageText()})
	if err != nil {
		return nil, errCustody
	}
	defer clear(plaintext)
	return encryptCustody(ctx, service, key, binding, plaintext, maximumApprovalPlaintext)
}

func custodyBinding(action string, tenant identity.TenantID, id impersonation.GrantID, requester, target, approver identity.UserID, digest [32]byte) (secretenvelope.Context, error) {
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	if _, err := impersonation.NewActor(tenant, requester); err != nil {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	if _, err := impersonation.NewActor(tenant, target); err != nil {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	if requester == target || digest == ([32]byte{}) {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	values := map[string]string{
		"purpose":        "identity.impersonation.postgres.custody.v1",
		"action":         action,
		"tenant":         string(tenant),
		"grant":          string(id),
		"requester":      string(requester),
		"target":         string(target),
		"request_digest": hex.EncodeToString(digest[:]),
	}
	switch action {
	case "request":
		if approver != "" {
			return secretenvelope.Context{}, impersonation.ErrInvalidInput
		}
	case "approval-reason":
		if _, err := impersonation.NewActor(tenant, approver); err != nil || approver == requester || approver == target {
			return secretenvelope.Context{}, impersonation.ErrInvalidInput
		}
		values["approver"] = string(approver)
	default:
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	binding, err := secretenvelope.NewContext(values)
	if err != nil {
		return secretenvelope.Context{}, impersonation.ErrInvalidInput
	}
	return binding, nil
}

func marshalCustodyRequest(original originalRequest) ([]byte, error) {
	request := original.request
	return canonicalCustodyJSON(custodyRequestPayload{
		Version:                   1,
		Tenant:                    request.Tenant(),
		Requester:                 request.Actor().User(),
		Target:                    request.Target().User(),
		TargetVersion:             request.Target().Version(),
		DurationNS:                int64(request.Duration()),
		Scope:                     request.Scope().Permissions(),
		Reason:                    request.Reason().StorageText(),
		PolicyID:                  request.Policy().ID(),
		PolicyVersion:             request.Policy().Version(),
		RequesterAuthorityVersion: original.requesterAuthorityVersion,
		RequesterUserVersion:      original.requesterUserVersion,
	})
}

func originalFromCustody(payload custodyRequestPayload) (originalRequest, error) {
	actor, err := impersonation.NewActor(payload.Tenant, payload.Requester)
	if err != nil {
		return originalRequest{}, errCustody
	}
	target, err := impersonation.NewTarget(payload.Tenant, payload.Target, payload.TargetVersion)
	if err != nil {
		return originalRequest{}, errCustody
	}
	scope, err := impersonation.NewScope(payload.Scope)
	if err != nil {
		return originalRequest{}, errCustody
	}
	reason, err := impersonation.NewReason(payload.Reason)
	if err != nil {
		return originalRequest{}, errCustody
	}
	policy, err := impersonation.NewPolicy(payload.PolicyID, payload.PolicyVersion)
	if err != nil {
		return originalRequest{}, errCustody
	}
	request, err := impersonation.NewRequest(impersonation.RequestInput{
		Tenant: payload.Tenant, Actor: actor, Target: target, Scope: scope,
		Reason: reason, Duration: time.Duration(payload.DurationNS), Policy: policy,
	})
	if err != nil {
		return originalRequest{}, errCustody
	}
	return originalRequest{request: request, requesterAuthorityVersion: payload.RequesterAuthorityVersion, requesterUserVersion: payload.RequesterUserVersion}, nil
}

func canonicalCustodyJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		clear(buffer.Bytes())
		return nil, errCustody
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func encryptCustody(ctx context.Context, service *secretenvelope.Service, key string, binding secretenvelope.Context, plaintext []byte, limit int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || len(plaintext) == 0 || len(plaintext) > limit {
		return nil, errCustody
	}
	envelope, err := service.Encrypt(ctx, secretenvelope.EncryptRequest{Plaintext: plaintext, KeyReference: key, Context: binding})
	if err != nil {
		return nil, errCustody
	}
	encoded, err := envelope.MarshalBinary()
	if err != nil || len(encoded) > maximumCustodyEnvelope {
		return nil, errCustody
	}
	return encoded, nil
}
