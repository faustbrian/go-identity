package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// Admit is the owned pre-encryption half of native enqueue. Inputs and binding
// come from an authenticated owning workflow, not client JSON. The complete
// Queue still owns recipient discovery, scoped keyed admission and its public
// result mapping. This method grants no authority from an input address/digest.
// Current policy must explicitly allow the exact redacted delivery scope before
// encryption and again before reservation, using the original bounded context.
func (e *enqueueExecutor) Admit(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, inputs []IntentInput, policies *retainedPolicies) (identity.CommandResult, error) {
	return e.admit(ctx, b, caller, inputs, policies, nil, "", nil)
}

// AdmitKeyed resolves matching explicit native enqueue requests to the original
// kernel command only after current scope authorization. The mapping is not
// execution evidence; prepared custody still commits under that sole command.
func (e *enqueueExecutor) AdmitKeyed(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, inputs []IntentInput, policies *retainedPolicies, keyed *keyedAdmission, requestKey string) (identity.CommandResult, error) {
	if keyed == nil || e == nil || e.custody == nil || e.custody.store == nil || keyed.deployment != e.custody.store.deployment || len(requestKey) < 16 || !safeID(requestKey, false) {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	return e.admit(ctx, b, caller, inputs, policies, keyed, requestKey, nil)
}

func (e *enqueueExecutor) admit(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, inputs []IntentInput, policies *retainedPolicies, keyed *keyedAdmission, requestKey string, recipients []recipientFence) (identity.CommandResult, error) {
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
	bindings, err := e.custody.validateInputShape(checked, inputs)
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
	expired := false
	for _, input := range inputs {
		expired = expired || !input.ExpiresAt.After(time.Now())
	}
	if expired {
		if keyed == nil {
			return identity.CommandResult{}, delivery.ErrExpired
		}
		logical, err := keyed.logical(bindings, inputs)
		if err != nil {
			return identity.CommandResult{}, err
		}
		original, _, err := keyed.observeVersion(w, b, requestKey, logical, version)
		if err != nil {
			return identity.CommandResult{}, err
		}
		b.CommandID = original
		b.RecordID = deliveryEffectID(e.custody.store.deployment, b, inputs[0].EffectIndex)
		query := identity.RecoveryQuery{CommandID: original, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
		observed, err := e.coordinator.ObserveCommandAdmission(w, query, caller)
		var denied identity.ForbiddenError
		if errors.As(err, &denied) {
			return identity.CommandResult{}, err
		}
		// An allocation alone never proves noncommit or authorizes a new send.
		result := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}
		if observed.Absent || observed.Record == (identitypostgres.CommandRecord{}) {
			return result, delivery.ErrOutcomeUnknown
		}
		result.Binding, result.Outcome = observed.Record.Binding, observed.Record.Outcome
		if observed.Record.Feature != nil {
			// Safe historical outcome projection only; no native payload or new
			// execution receipt is reconstructed from participant evidence.
			result.Feature = &identity.FeatureReceipt{Operation: *observed.Record.Feature}
		}
		return result, err
	}
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
	prepared.state.recipients = slices.Clone(recipients)
	return e.Execute(w, prepared, caller)
}
