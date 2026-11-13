package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func signinCallbackOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// The callback command belongs to the original RP transaction, not a browser
// idempotency key or the subsequently selected user. The existing journal
// fingerprints this secret-free command before any provider exchange. A retry
// with another code keeps the command ID but conflicts on immutable intent.
func (s *SigninService) signinCallbackCommand(ctx context.Context, r oauth.SigninCallbackRequest, flow signinCallbackFlow) (identity.Command, error) {
	if ctx == nil || s == nil || s.config.IntentKey == ([32]byte{}) || r.Validate() != nil || flow.statePlan.CapabilityID == "" || r.Callback.Denied() || !reflect.DeepEqual(r.Callback.Profile(), flow.binding.Provider) {
		return identity.Command{}, identity.InvalidInputError{Field: "oauth_signin_command"}
	}
	input, ok := r.Callback.Input()
	if !ok {
		return identity.Command{}, identity.InvalidInputError{Field: "oauth_signin_command"}
	}
	frame, err := json.Marshal(struct {
		Binding                 signinRPBinding
		Origin, Network, Device string
	}{flow.binding, r.Origin, r.Network, r.Device})
	if err != nil {
		return identity.Command{}, identity.InvalidInputError{Field: "oauth_signin_command"}
	}
	defer clear(frame)
	mac := hmac.New(sha256.New, s.config.IntentKey[:])
	_, _ = mac.Write([]byte("identity-oauth-signin-callback-input-v1\x00"))
	_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(frame))))
	_, _ = mac.Write(frame)
	err = input.Use(ctx, func(_ context.Context, code, state []byte) error {
		if !bytes.Equal(state, []byte(flow.binding.State)) {
			return identity.ForbiddenError{}
		}
		_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(code))))
		_, _ = mac.Write(code)
		_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(state))))
		_, _ = mac.Write(state)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return identity.Command{}, ctx.Err()
		}
		return identity.Command{}, identity.ForbiddenError{}
	}
	b := identity.CommandBinding(flow.binding.Input.Binding)
	op := signinCallbackOperation()
	b.CommandID = flow.binding.CallbackCommandID
	b.RecordID = ""
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.CorrelationID = string(b.CommandID)
	return identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "oauth.signin.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}}}, r.FlowCookie)
}
