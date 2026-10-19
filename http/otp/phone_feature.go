package otphttp

import (
	"encoding/json"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// NewPhoneSigninFeature explicitly selects existing verified-phone SMS issuance,
// consuming signin and original code-free recovery under identity/phone. Each
// configuration must name the intended deployment and native owners. Selection
// validates and freezes them without IO; failure returns no partial feature.
// It selects neither pre-auth initiation nor session read/logout, enrollment,
// password signin, signup, reset, replacement or MFA continuation. Omission
// exposes no route, schema or capability. Combine other phone contributions
// under this same feature owner rather than registering duplicate owners.
func NewPhoneSigninFeature(send PhoneSigninSendConfig, signin SigninConfig, recovery SigninRecoveryConfig) (identityhttp.Feature, error) {
	return NewPhoneSigninFeatureWithMiddleware(send, signin, recovery, nil)
}

// NewPhoneSigninFeatureWithMiddleware preserves each real typed pipeline and
// guarded response. Middleware cannot replace native original-flow authority
// or deliver credentials through issuance, denials or historical recovery.
func NewPhoneSigninFeatureWithMiddleware(send PhoneSigninSendConfig, signin SigninConfig, recovery SigninRecoveryConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	start, err := NewPhoneSigninSendHandlerWithMiddleware(send, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	finish, err := NewPhoneSigninHandlerWithMiddleware(signin, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	history, err := NewPhoneSigninRecoveryHandlerWithMiddleware(recovery, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	ids := []string{"identity.phone.send-signin", "identity.phone.signin", "identity.phone.signin.recover"}
	ops := make([]identityhttp.OperationDescriptor, 0, len(ids))
	for mode, handler := range []http.Handler{start, finish, history} {
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: ids[mode], Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = phoneSigninWire(mode, ids[mode])
		// Issuance declares the shared original-flow and device schemes once.
		// The other closed operations only reference original-flow custody.
		if mode != 0 {
			op.Wire.SecuritySchemes = nil
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: ops})
}

// Reuse the unchanged closed OTP wire shapes, not a second response protocol.
// Every call receives detached definitions. Phone selection specializes
// ownership, scheme names and the issuance identifier, never generic email.
func phoneSigninWire(mode int, id string) *identityhttp.WireOperation {
	wire := signinWire()
	if mode == 0 {
		wire = emailSigninSendWire()
	} else if mode == 2 {
		wire = signinRecoveryWire()
	}
	var definition map[string]any
	json.Unmarshal(wire.Definition, &definition)
	definition["operationId"] = id
	// OpenAPI composition rejects duplicate component declarations even when
	// their cookies coincide. Keep phone's names/references separate so the
	// retained email feature can coexist; actual cookie custody is unchanged.
	names := map[string]string{"IdentityOTPOriginalFlow": "IdentityPhoneOTPOriginalFlow", "IdentityOTPBrowserDevice": "IdentityPhoneOTPBrowserDevice"}
	for _, raw := range definition["security"].([]any) {
		requirement := raw.(map[string]any)
		for old, renamed := range names {
			if value, ok := requirement[old]; ok {
				delete(requirement, old)
				requirement[renamed] = value
			}
		}
	}
	for i := range wire.SecuritySchemes {
		wire.SecuritySchemes[i].Name = names[wire.SecuritySchemes[i].Name]
	}
	if mode == 0 {
		definition["description"] = "Existing verified-phone SMS signin issuance only. Exact HTTPS tenant/Origin, original target-bound pre-auth flow/cookie, signed browser device and header Idempotency-Key are mandatory. The selected phone policy canonicalizes number; the native owner authenticates the original target/profile before issuance or indistinguishable suppression. Acceptance proves neither account existence nor delivery. No signup, MFA continuation, replacement remember policy, session or credential delivery."
		schema := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
		schema["required"] = []string{"flowID", "number"}
		fields := schema["properties"].(map[string]any)
		delete(fields, "email")
		fields["number"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": true, "description": "Strict ASCII international E.164 or explicitly enabled national digits. The selected native profile, region and byte limit remain authoritative; input cannot select them."}
	} else if mode == 1 {
		definition["description"] = "Existing verified-phone SMS-code signin, never password or email fallback. Original HTTPS tenant/Origin and target-bound flow/cookie are mandatory. Original Send selects the canonical profiled phone and remember policy. Shared IP then original-source admission precedes one atomic consuming native call. Native current account/phone/factor authority must permit this profile; only fresh committed success delivers session and synchronizer headers. Unknown outcomes never retry. No replacement number, user or remember policy."
	} else {
		definition["description"] = "Code-free original phone SMS signin history, not authentication. Exact original HTTPS tenant/Origin, flow cookie and retained recovery correlation are mandatory; no code, idempotency key, replacement number/user or remember policy. One bounded native historical read uses the distinct recovery action and current disclosure policy. No comparison, debit, execution retry, renewed custody or credential delivery. Unknown remains unknown."
	}
	wire.Definition, _ = json.Marshal(definition)
	return wire
}
