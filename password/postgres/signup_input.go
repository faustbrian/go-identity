package passwordpostgres

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This projection is private to authenticated native custody. It deliberately
// flattens the opaque remember policy rather than permitting generic export of
// a flow. Restoration is historical structural state, never live authority.
type signupOriginalFlow struct {
	Schema                           uint8
	ID                               identity.PreAuthTransactionID
	Tenant                           identity.TenantID
	Action, Origin, Callback, Policy string
	Nonce                            [32]byte
	Remember                         session.RememberPolicySpec
	PolicyVersion                    uint64
	IssuedAt, ExpiresAt              time.Time
	Cookie                           session.TokenDigest
	Version                          uint64
}

func signupFlowProjection(flow session.PreAuthTransaction) (signupOriginalFlow, error) {
	s, err := flow.Bindings()
	if err != nil {
		return signupOriginalFlow{}, password.ErrPasswordWork
	}
	i := s.Binding.Intent
	remember, err := i.Remember.Bindings()
	if err != nil {
		return signupOriginalFlow{}, password.ErrPasswordWork
	}
	return signupOriginalFlow{1, s.Binding.ID, i.TenantID, i.Action, i.Origin, i.CallbackURL, i.PolicyID, i.Nonce, remember, i.PolicyVersion, s.Binding.IssuedAt, s.Binding.ExpiresAt, s.Cookie, s.Version}, nil
}

func signupFlowState(original signupOriginalFlow) (session.PreAuthTransaction, error) {
	if original.Schema != 1 {
		return session.PreAuthTransaction{}, password.ErrPasswordWork
	}
	remember, err := session.NewRememberPolicy(original.Remember)
	if err != nil {
		return session.PreAuthTransaction{}, password.ErrPasswordWork
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: original.ID, Intent: session.PreAuthIntent{TenantID: original.Tenant, Action: original.Action, Origin: original.Origin, CallbackURL: original.Callback, PolicyID: original.Policy, PolicyVersion: original.PolicyVersion, Nonce: original.Nonce, Remember: remember}, IssuedAt: original.IssuedAt, ExpiresAt: original.ExpiresAt}, Cookie: original.Cookie, Version: original.Version})
	if err != nil {
		return session.PreAuthTransaction{}, password.ErrPasswordWork
	}
	return flow, nil
}

// Original prepared input lives only in the existing immutable kernel request-
// key mapping. AAD binds all coordinator provenance plus the actual frozen
// deployment profile. Active encryption key selection is not a new profile:
// retained envelopes carry their original key reference. There is no password,
// cookie or retry key in this projection, and no new replay/storage authority.
func (*Repository) signupInputAAD(k kernel.RequestKeyPreparationBinding, profile [32]byte) (envelope.Context, error) {
	bad := func() (envelope.Context, error) { return envelope.Context{}, password.ErrPasswordWork }
	if profile == ([32]byte{}) || !reauthenticationText(k.Namespace, 128) || !reauthenticationText(string(k.Scope.TenantID), 128) || !reauthenticationText(string(k.Scope.ActorID), 128) || k.Scope.Method != "POST" || k.Scope.RouteID != passwordSignupOperation().OperationID || k.Feature.Operation != passwordSignupOperation() || k.Feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || k.PolicyVersion == 0 || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return bad()
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return bad()
	}
	switch k.Scope.ActorKind {
	case authorization.SubjectUser, authorization.SubjectAPIKey, authorization.SubjectServiceAccount:
	default:
		return bad()
	}
	// The complete binding intentionally has a closed serializer; explicit scalar
	// projection is permitted only at this authenticated native custody boundary.
	frame, err := json.Marshal(struct {
		Namespace     string
		Scope         kernel.RequestKeyScope
		Admission     kernel.RequestKeyAdmission
		Feature       kernel.FeatureRegistration
		PolicyVersion uint64
		IntentDigest  [32]byte
		Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, profile})
	if err != nil {
		return bad()
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-password-signup-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
