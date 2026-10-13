package mfahttp

import (
	"encoding/json"
	"fmt"
	"log/slog"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// FeatureConfig selects only explicitly configured native MFA operations.
// Omit the feature from composition to expose no routes or metadata. Empty
// selection denies; construction invokes no native service or global registry.
type FeatureConfig struct {
	// List exposes only authenticated safe metadata, independently of mutations.
	List *ListConfig
	// FactorUpdate independently selects authenticated native TOTP management.
	FactorUpdate *FactorUpdateConfig
	// Disable separately selects exact disable-purpose native mutation.
	Disable *DisableConfig
	// RecoveryUse exposes only the explicitly selected original-primary owner.
	RecoveryUse *RecoveryUseConfig
	// RecoveryRegenerate explicitly selects fresh-factor whole-set replacement.
	RecoveryRegenerate *RecoveryRegenerateConfig
	TOTPVerify         *TOTPVerifyConfig
	// PasswordTOTPVerify selects the password-origin native owner explicitly.
	// With both login owners, singleton X-MFA-Variant: password selects it;
	// otherwise it is the selected default. Selection is never fallback after denial.
	PasswordTOTPVerify     *TOTPVerifyConfig
	Enable                 *EnableConfig
	URI                    *URIConfig
	EnrollmentConfirmation *EnrollmentConfirmationConfig
	// ActiveStepUp selects only the explicit authenticated step-up verify arm.
	ActiveStepUp *ActiveStepUpConfig
}

// NewFeature contributes the selected owned handler and closed wire contract.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware binds hooks to actual owned phases without granting
// credential output ownership or returning a partial feature on failure.
func NewFeatureWithMiddleware(c FeatureConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if c.Disable == nil && c.FactorUpdate == nil && c.List == nil && c.TOTPVerify == nil && c.PasswordTOTPVerify == nil && c.Enable == nil && c.URI == nil && c.EnrollmentConfirmation == nil && c.ActiveStepUp == nil && c.RecoveryUse == nil && c.RecoveryRegenerate == nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var operations []identityhttp.OperationDescriptor
	if c.Disable != nil {
		h, err := NewDisableHandlerWithMiddleware(*c.Disable, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.disable", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 4096})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = disableWire(*c.Disable)
		operations = append(operations, op)
	}
	if c.FactorUpdate != nil {
		h, err := NewFactorUpdateHandlerWithMiddleware(*c.FactorUpdate, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.factor-update", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 4096})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = factorUpdateWire(*c.FactorUpdate)
		operations = append(operations, op)
	}
	if c.List != nil {
		h, err := NewListHandlerWithMiddleware(*c.List, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.list", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 262144})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = listWire(*c.List)
		operations = append(operations, op)
	}
	if c.RecoveryRegenerate != nil {
		h, err := NewRecoveryRegenerateHandlerWithMiddleware(*c.RecoveryRegenerate, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.recovery-regenerate", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = regenerationWire(*c.RecoveryRegenerate)
		operations = append(operations, op)
	}
	if c.RecoveryUse != nil {
		h, err := NewRecoveryUseHandlerWithMiddleware(*c.RecoveryUse, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.recovery-use", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = recoveryWire(*c.RecoveryUse)
		operations = append(operations, op)
	}
	if c.TOTPVerify != nil || c.PasswordTOTPVerify != nil || c.EnrollmentConfirmation != nil || c.ActiveStepUp != nil {
		h := &verifyDispatch{passwordDefault: c.TOTPVerify == nil && c.PasswordTOTPVerify != nil}
		var err error
		policy := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}
		if c.TOTPVerify != nil {
			h.login, err = NewTOTPVerifyHandlerWithMiddleware(*c.TOTPVerify, m)
			if err != nil {
				return identityhttp.Feature{}, err
			}
		}
		if c.PasswordTOTPVerify != nil {
			if c.TOTPVerify != nil {
				a, b := *c.TOTPVerify, *c.PasswordTOTPVerify
				if a.Origin != b.Origin || a.CallbackURL != b.CallbackURL || a.ActorID != b.ActorID || a.PolicyRevision != b.PolicyRevision || a.Audience != b.Audience {
					return identityhttp.Feature{}, identityhttp.ErrInvalidInput
				}
			}
			password := *c.PasswordTOTPVerify
			password.PasswordPrimary = true
			h.password, err = NewTOTPVerifyHandlerWithMiddleware(password, m)
			if err != nil {
				return identityhttp.Feature{}, err
			}
		}
		if c.EnrollmentConfirmation != nil {
			h.enrollment, err = NewEnrollmentConfirmationHandlerWithMiddleware(*c.EnrollmentConfirmation, m)
			if err != nil {
				return identityhttp.Feature{}, err
			}
			policy.Mode = identityhttp.CSRFSessionState
			policy.TokenHeader = "X-CSRF-Token"
			if c.TOTPVerify != nil || c.PasswordTOTPVerify != nil {
				policy.Mode = identityhttp.CSRFVariantOriginSessionState
			}
		}
		if c.ActiveStepUp != nil {
			h.stepup, err = NewActiveStepUpHandlerWithMiddleware(*c.ActiveStepUp, m)
			if err != nil {
				return identityhttp.Feature{}, err
			}
			policy.Mode = identityhttp.CSRFSessionState
			policy.TokenHeader = "X-CSRF-Token"
			if c.TOTPVerify != nil || c.PasswordTOTPVerify != nil {
				policy.Mode = identityhttp.CSRFVariantOriginSessionState
			}
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", Handler: h, CSRF: policy, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = selectedVerifyWire(c)
		operations = append(operations, op)
	}
	if c.Enable != nil {
		h, err := NewEnableHandlerWithMiddleware(*c.Enable, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.enable", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 32768})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = enableWire(*c.Enable)
		operations = append(operations, op)
	}
	if c.URI != nil {
		h, err := NewURIHandlerWithMiddleware(*c.URI, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.totp-uri", Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = uriWire(*c.URI)
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/mfa", Operations: operations})
}

func totpWire(c TOTPVerifyConfig) *identityhttp.WireOperation {
	text := func(max int) any { return map[string]any{"type": "string", "minLength": 1, "maxLength": max} }
	object := func(required []string, properties map[string]any) any {
		return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
	}
	id := map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$", "not": map[string]any{"const": "AAAAAAAAAAAAAAAAAAAAAA"}}
	codes := map[string]any{"type": "string", "enum": []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "denied", "unavailable", "conflict", "in_progress", "replay"}}
	success := object([]string{"signedIn", "commitOutcome", "commandID", "sessionID"}, map[string]any{"signedIn": map[string]any{"const": true}, "commitOutcome": map[string]any{"const": "committed"}, "commandID": id, "sessionID": text(128)})
	failure := object([]string{"signedIn", "commitOutcome", "error"}, map[string]any{"signedIn": map[string]any{"const": false}, "commitOutcome": map[string]any{"type": "string", "enum": []string{"none", "committed", "not_committed", "unknown", "conflict", "in_progress"}}, "commandID": id, "error": codes})
	response := func(schema any) any {
		return map[string]any{"description": "No-store original outcome; no credential or subject in JSON.", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	responses := map[string]any{"200": response(success)}
	responses["200"].(map[string]any)["headers"] = map[string]any{"Set-Cookie": map[string]any{"description": "Fresh original committed session only; never on retry or ambiguity.", "schema": text(4096)}, "X-CSRF-Token": map[string]any{"description": "Original session/version synchronizer, only with the fresh bearer.", "schema": text(256)}}
	for _, status := range []string{"400", "403", "404", "405", "409", "421", "429", "503"} {
		responses[status] = response(map[string]any{"oneOf": []any{object([]string{"error"}, map[string]any{"error": codes}), failure}})
	}
	plain := map[string]any{"schema": map[string]any{"type": "string", "const": "identity.http.origin_denied\n"}}
	responses["403"].(map[string]any)["content"].(map[string]any)["text/plain"] = plain
	responses["408"] = map[string]any{"description": "Canceled during shared origin admission, before native completion.", "content": map[string]any{"text/plain": plain}}
	for _, status := range []string{"409", "429"} {
		responses[status].(map[string]any)["headers"] = map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "string", "pattern": "^[0-9]+$"}}}
	}
	proof := map[string]any{"type": "string", "minLength": 32, "maxLength": 4096, "writeOnly": true}
	code := map[string]any{"type": "string", "minLength": 4, "maxLength": 128, "writeOnly": true, "description": "Opaque bounded input; native enrolled TOTP profile owns mismatch and shared attempts."}
	body := object([]string{"commandID", "preAuthID", "challengeID", "factorID", "token", "code", "callbackURL", "trustDevice"}, map[string]any{"commandID": id, "preAuthID": id, "challengeID": id, "factorID": id, "token": proof, "code": code, "callbackURL": map[string]any{"const": c.CallbackURL}, "trustDevice": map[string]any{"type": "boolean", "description": "Native unsupported trusted-device requests deny; never silently ignored."}})
	definition := map[string]any{"operationId": "identity.mfa.totp-verify", "description": "Explicit browser TOTP completion for the selected native magic-link continuation. Exact tenant/HTTPS/Origin/callback and original flow/device cookies required. No Idempotency-Key, Authorization, query, redirect or automatic retry. IP admission precedes owning original source and subject/challenge quotas; native protected factor/risk/one-use/session authority remains decisive. Only a fresh error-free committed result delivers credentials. Expired-proof history uses explicit native recovery.", "security": []any{map[string]any{"MFAOriginalFlow": []string{}, "MFABrowserDevice": []string{}}}, "parameters": []any{map[string]any{"name": "Origin", "in": "header", "required": true, "schema": map[string]any{"const": string(c.Origin)}}}, "requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": responses}
	data, _ := json.Marshal(definition)
	flow, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_flow", "description": "Original native browser-flow possession, not a session."})
	device, _ := json.Marshal(map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-identity_device", "description": "Signed browser correlation, not a trusted MFA device."})
	return &identityhttp.WireOperation{Definition: data, SecuritySchemes: []identityhttp.WireComponent{{Name: "MFAOriginalFlow", Definition: flow}, {Name: "MFABrowserDevice", Definition: device}}}
}

// Format redacts selected borrowed owners and configuration.
func (FeatureConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.FeatureConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration/credential export.
func (FeatureConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit export and map-key disclosure.
func (FeatureConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits only a fixed redacted marker.
func (FeatureConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.FeatureConfig(redacted)")
}

// LogValue emits only a fixed redacted marker.
func (TOTPVerifyConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.TOTPVerifyConfig(redacted)")
}
