package postgres

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

// Admit is the owned pre-encryption half of native enqueue. Inputs and binding
// come from an authenticated owning workflow, not client JSON. The complete
// Queue still owns recipient discovery, scoped keyed admission and its public
// result mapping. This method grants no authority from an input address/digest.
// Current policy must explicitly allow the exact redacted delivery scope before
// encryption and again before reservation, using the original bounded context.
func (e *enqueueExecutor) Admit(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, inputs []IntentInput, policies *retainedPolicies) (identity.CommandResult, error) {
	return e.admit(ctx, b, caller, inputs, policies, nil, "")
}

// AdmitKeyed resolves matching explicit native enqueue requests to the original
// kernel command only after current scope authorization. The mapping is not
// execution evidence; prepared custody still commits under that sole command.
func (e *enqueueExecutor) AdmitKeyed(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, inputs []IntentInput, policies *retainedPolicies, keyed *keyedAdmission, requestKey string) (identity.CommandResult, error) {
	if keyed == nil || e == nil || e.custody == nil || e.custody.store == nil || keyed.deployment != e.custody.store.deployment || len(requestKey) < 16 || !safeID(requestKey, false) {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	return e.admit(ctx, b, caller, inputs, policies, keyed, requestKey)
}

func (e *enqueueExecutor) admit(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, inputs []IntentInput, policies *retainedPolicies, keyed *keyedAdmission, requestKey string) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.custody == nil || e.custody.store == nil || policies == nil || policies.deployment != e.custody.store.deployment || b.RecordID != "" || len(inputs) < 1 || len(inputs) > 16 {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	w, stop := context.WithTimeout(ctx, e.timeout)
	defer stop()
	if err := w.Err(); err != nil {
		return identity.CommandResult{}, err
	}
	checked := b
	checked.RecordID = "enqueue-validation"
	if checked.ValidateFor(EnqueueOperation()) != nil {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	inputs = slices.Clone(inputs)
	bindings, err := e.custody.validateInputs(checked, inputs)
	if err != nil {
		return identity.CommandResult{}, err
	}
	var scopes, purposes, templates, providers []string
	for n, bound := range bindings {
		if _, retained := policies.profiles[bound.PolicyVersion]; !retained {
			return identity.CommandResult{}, delivery.ErrUnavailable
		}
		if inputs[n].SubjectID != string(b.UserID) {
			return identity.CommandResult{}, delivery.ErrForbidden
		}
		scopes = append(scopes, inputs[n].Recipient.ScopeDigest)
		purposes = append(purposes, inputs[n].Purpose)
		templates = append(templates, fmt.Sprintf("%d:%s:%d", len(inputs[n].TemplateID), inputs[n].TemplateID, inputs[n].TemplateVersion))
		providers = append(providers, fmt.Sprintf("%d:%d", inputs[n].ProviderConfigVersion, bound.PolicyVersion))
	}
	// Bound/validate the caller before cloning its maps. Reserved attributes
	// cannot be supplied at any level and shadow the adapter's derived scope.
	for _, attrs := range []authorization.Attributes{caller.Request.Subject.Attributes, caller.Request.Resource.Attributes, caller.Request.Environment.Attributes, caller.Request.Attributes} {
		if len(attrs) > 128 {
			return identity.CommandResult{}, delivery.ErrInvalidInput
		}
		for name := range attrs {
			if len(name) > 128 || strings.HasPrefix(string(name), "delivery.") {
				return identity.CommandResult{}, delivery.ErrInvalidInput
			}
		}
	}
	// allow validates attribute values before any Clone. It is called with
	// the derived attributes below, so first copy only the bounded outer maps;
	// immutable authorization.Value contents are shared, never copied here.
	attrs := make(authorization.Attributes, len(caller.Request.Resource.Attributes)+4)
	for key, value := range caller.Request.Resource.Attributes {
		attrs[key] = value
	}
	attrs["delivery.recipient_scopes"] = authorization.StringSetValue(scopes)
	attrs["delivery.purposes"] = authorization.StringSetValue(purposes)
	attrs["delivery.templates"] = authorization.StringSetValue(templates)
	attrs["delivery.provider_policies"] = authorization.StringSetValue(providers)
	caller.Request.Resource.Attributes = attrs
	if err := e.allow(w, checked, caller); err != nil {
		return identity.CommandResult{}, err
	}
	version := e.custody.current
	if keyed != nil {
		logical, err := keyed.logical(bindings, inputs)
		if err != nil {
			return identity.CommandResult{}, err
		}
		original, retainedVersion, err := keyed.resolveVersion(w, b, requestKey, logical, version)
		if err != nil {
			return identity.CommandResult{}, err
		}
		b.CommandID = original
		version = retainedVersion
	}
	prepared, err := e.custody.prepareEnqueueVersion(w, b, inputs, version)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return e.Execute(w, prepared, caller)
}
