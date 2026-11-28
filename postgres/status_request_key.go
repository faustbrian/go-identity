package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const (
	adminStatusBan   = "identity.admin.user-ban"
	adminStatusUnban = "identity.admin.user-unban"
)

// AdminStatusKeyRequest contains the caller's exact status intent. Ban requires
// a registered reason and accepts an optional absolute expiry. Unban requires
// ExpectedVersion instead. Neither operation accepts a caller-supplied epoch.
type AdminStatusKeyRequest struct {
	UserID          identity.UserID
	ExpectedVersion uint64
	Reason          string
	ExpiresAt       time.Time
}

// AdminStatusKeyAdmission locates the original command and its preconditions.
// These versions are immutable retry input, not current authority or a receipt.
type AdminStatusKeyAdmission struct {
	CommandID                identity.CommandID
	ExpectedVersion          uint64
	ExpectedAuthorityVersion uint64
}

// ResolveAdminStatusKey authorizes the exact target, then resolves the request
// key under separate current request-admission policy. The trusted composition
// must derive caller from an authenticated administrator on every attempt. The
// first admitted key captures versions from the owned primary repository;
// retries authenticate and restore those versions without a new target read.
// It never reserves or executes the status command. Install both selected
// Status and RequestKeyPreparation histories before use. Missing key history,
// changed intent, unauthorized callers and unknown commits return no versions.
// An earlier caller deadline wins. The coordinator and pool are borrowed.
func (o *StatusUnitOfWork) ResolveAdminStatusKey(ctx context.Context, key identity.IdempotencyKey, input AdminStatusKeyRequest, caller authorization.DecisionContext) (result AdminStatusKeyAdmission, err error) {
	defer func() {
		if recover() != nil {
			result, err = AdminStatusKeyAdmission{}, identity.UnavailableError{}
		}
	}()
	if ctx == nil || o == nil || o.owner == nil || o.owner.status == nil || o.owner.repository == nil || o.owner.coordinator == nil ||
		o.owner.coordinator.requestKeys == nil || key == (identity.IdempotencyKey{}) || !boundedQueryCaller(caller) {
		return result, invalidRequestKey()
	}
	c := o.owner.coordinator
	policy := c.requestKeys.Policy
	r := caller.Request
	action, tenant := string(r.Action), identity.TenantID(r.Tenant)
	scope := RequestKeyScope{TenantID: tenant, ActorID: identity.ActorID(r.Subject.ID), ActorKind: r.Subject.Kind, Method: "POST", RouteID: action}
	if !validRequestKeyScope(scope) || r.Subject.Kind != authorization.SubjectUser || r.Resource.Type != "identity.user" ||
		r.Resource.ID != authorization.ResourceID(input.UserID) || caller.PolicyRevision != authorization.Revision(policy.PolicyVersion) {
		return result, identity.ForbiddenError{}
	}
	intent, err := adminStatusKeyIntent(action, tenant, input, o.owner.status)
	if err != nil {
		return result, err
	}
	work, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if err := authorizeAdminStatusKeyTarget(work, caller, policy); err != nil {
		return result, err
	}
	keyCaller := caller.Clone()
	keyCaller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(action)}
	// Distinguish this exact core owner's custody from registered feature
	// preparations. The descriptor is used only to bind the stored encoding.
	feature := FeatureRegistration{Contributor: o.owner.repository.Descriptor(), Operation: identity.FeatureOperation{
		Owner: "identity", OperationID: action, SchemaID: "identity-admin-status-key", SchemaVersion: 1,
	}}
	owner := &adminStatusKeyPreparation{status: o.owner, input: input}
	prep := &requestKeyPreparation{owner: owner, feature: feature, identity: requestPreparationIdentity(feature)}
	defer func() { clear(prep.ciphertext) }()
	admission, err := c.resolveRequestKey(work, scope, key, intent, keyCaller, prep)
	if err != nil {
		var unavailable identity.UnavailableError
		if owner.rejected != nil && work.Err() == nil && errors.As(err, &unavailable) {
			return result, owner.rejected
		}
		return result, err
	}
	version, epoch, err := openAdminStatusVersions(c.keys.retained[admission.FingerprintKeyVersion], prep.binding, prep.storedCiphertext)
	if err != nil {
		return result, err
	}
	if work.Err() != nil {
		return result, readFailure(work, work.Err())
	}
	return AdminStatusKeyAdmission{CommandID: admission.CommandID, ExpectedVersion: version, ExpectedAuthorityVersion: epoch}, nil
}

func authorizeAdminStatusKeyTarget(ctx context.Context, caller authorization.DecisionContext, policy CommandQueryPolicy) error {
	if ctx.Err() != nil {
		return readFailure(ctx, ctx.Err())
	}
	now := policy.Clock.Now()
	if now.IsZero() {
		return identity.UnavailableError{}
	}
	dc := caller.Clone()
	dc.Request.Environment.Time = now.UTC()
	attrs := authorization.Attributes{}
	for name, value := range dc.Request.Resource.Attributes {
		if !strings.HasPrefix(string(name), "identity.user.") && !strings.HasPrefix(string(name), "identity.command.") {
			attrs[name] = value
		}
	}
	dc.Request.Resource.Attributes = attrs
	attrs["identity.command.read-admission"] = authorization.BoolValue(true)
	attrs["identity.command.recovery"] = authorization.BoolValue(false)
	if !boundedQueryCaller(dc) {
		return invalidRequestKey()
	}
	decision, err := policy.Authorization.Decide(ctx, dc)
	if ctx.Err() != nil || err != nil {
		return readFailure(ctx, err)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(policy.PolicyVersion) {
		return identity.ForbiddenError{}
	}
	return nil
}

func adminStatusKeyIntent(action string, tenant identity.TenantID, input AdminStatusKeyRequest, status *statusOwnerPolicy) (identity.RequestIntent, error) {
	shape := identity.User{ID: input.UserID, TenantID: tenant, Version: 1, Status: identity.StatusActive}
	if shape.Validate(tenant) != nil {
		return identity.RequestIntent{}, invalidRequestKey()
	}
	definition := sha256.Sum256(status.definition)
	fields := []identity.FeatureField{
		{Name: "status.target", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(input.UserID)}},
		{Name: "status.policy-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: status.config.PolicyVersion}},
		{Name: "status.policy-definition", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: definition[:]}},
		{Name: "status.retention-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: status.config.RetentionPolicyVersion}},
	}
	switch action {
	case adminStatusBan:
		if input.ExpectedVersion != 0 || !slices.Contains(status.config.Reasons, input.Reason) {
			return identity.RequestIntent{}, invalidRequestKey()
		}
		fields = append(fields, identity.FeatureField{Name: "status.reason", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: input.Reason}})
		if !input.ExpiresAt.IsZero() {
			expiry := input.ExpiresAt.UTC()
			if expiry.Year() < 1 || expiry.Year() > 9999 || expiry.Nanosecond()%1000 != 0 {
				return identity.RequestIntent{}, invalidRequestKey()
			}
			fields = append(fields, identity.FeatureField{Name: "status.expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: expiry}})
		}
	case adminStatusUnban:
		if !usableStatusVersion(input.ExpectedVersion) || input.Reason != "" || !input.ExpiresAt.IsZero() {
			return identity.RequestIntent{}, invalidRequestKey()
		}
		fields = append(fields, identity.FeatureField{Name: "status.expected-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: input.ExpectedVersion}})
	default:
		return identity.RequestIntent{}, invalidRequestKey()
	}
	return identity.NewRequestIntent(fields)
}

type adminStatusKeyPreparation struct {
	status   *CreationUnitOfWork
	input    AdminStatusKeyRequest
	rejected error
}

func (p *adminStatusKeyPreparation) PrepareRequestKey(ctx context.Context, b RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	current, err := p.status.repository.GetStatus(ctx, identity.UserStatusQuery{TenantID: b.Scope.TenantID, UserID: p.input.UserID})
	switch {
	case errors.Is(err, identity.ErrUserAbsent):
		p.rejected = identity.ForbiddenError{}
	case err != nil:
		return nil, err
	case current.User.Status == identity.StatusAnonymized || current.User.Status == identity.StatusDeleted:
		p.rejected = identity.ForbiddenError{}
	case b.Scope.RouteID == adminStatusUnban && current.User.Version != p.input.ExpectedVersion:
		p.rejected = identity.ConflictError{}
	}
	if p.rejected != nil {
		return nil, p.rejected
	}
	key := p.status.coordinator.keys.retained[b.Admission.FingerprintKeyVersion]
	return sealAdminStatusVersions(key, b, current.User.Version, current.AuthorityVersion)
}
