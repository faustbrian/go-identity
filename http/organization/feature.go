// Package organizationhttp supplies explicitly selected bearer-only organization
// HTTP operations. Domain state, authorization, durability and recovery remain
// with the storage-neutral organization contracts and their actual native owner.
package organizationhttp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

// Service is this finite consumer's neutral native port. It must own current
// session/membership/action authorization, keyed original-command custody,
// protected risk and atomic durable effects. Create/Add retries recover only
// the original command; removal is repeat, not keyed. No HTTP or storage adapter
// is imposed. Calls must honor ctx and support concurrent independent requests.
type Service interface {
	Create(context.Context, organization.CreateOperationRequest, string) (organization.StoreResult, error)
	Get(context.Context, organization.ReadRequest) (organization.View, error)
	ListMembers(context.Context, organization.ReadRequest) (organization.View, error)
	AddMember(context.Context, organization.AddMemberOperationRequest, string) (organization.StoreResult, error)
	RemoveMember(context.Context, organization.RemoveMemberOperationRequest, string) (organization.StoreResult, error)
}

// MetadataUpdater replaces metadata at an exact organization version using
// original-key native custody. It owns current administrator authority,
// protected risk and atomic effects; matching retries recover only the original
// outcome. Calls honor ctx and support concurrent independent requests.
type MetadataUpdater interface {
	Update(context.Context, organization.UpdateOperationRequest, string) (organization.StoreResult, error)
}

// MemberUpdater replaces a member's static role at exact organization/member
// versions. Current authority, owner transitions, last-owner safety and original
// keyed recovery remain native-owned. Calls honor ctx and are concurrent-safe.
type MemberUpdater interface {
	UpdateMember(context.Context, organization.UpdateMemberOperationRequest, string) (organization.StoreResult, error)
}

// InvitationSender is the independently selected native original-key send port.
// It owns current authority, immutable intent, protected risk and atomic proof/
// invitation/delivery effects. Matching retries classify the original outcome,
// never issue another proof or redispatch delivery. The caller borrows opaque
// request custody; implementations must honor ctx and support concurrent calls.
type InvitationSender interface {
	Send(context.Context, organization.InvitationSendOperationRequest, string) (organization.StoreResult, error)
}

// InvitationResender owns original-key successor rotation and original delivery
// observation under current native manager/recipient authority. It preserves the
// fixed recipient, role and deadline, never reconstructs execution on retry, and
// retains a known receipt if later disclosure fails. Calls honor ctx and support
// concurrent independent requests. No separate current-invitation read is used.
type InvitationResender interface {
	Resend(context.Context, organization.InvitationResendOperationRequest, string) (organization.InvitationResendOperationResult, error)
}

// InvitationAccepter acquires the actual native preparation and authenticated
// original issuance facts. HTTP admission retains it until Handle executes the
// identical preparation. Final current authority and atomic one-use effects
// remain native-owned. Calls must honor ctx and support concurrent independent
// requests. Acceptance is once, not a keyed retry API.
type InvitationAccepter interface {
	PrepareAcceptance(context.Context, organization.InvitationAcceptRequest, string) (organization.PreparedInvitationAcceptance, error)
}

// Config borrows actual concurrency-safe owners for their lifetime. Sessions
// supplies current actor custody for transport rate admission; Service and
// Invitations retain their respective native final authority fences. Supply
// only the owners used by selected operations; invitation-read-only selection
// needs neither Service nor AdminRate. Send requires InvitationSender,
// Invitations and AdminRate, not Service or SafeRate. The selected profile is
// strict Authorization bearer only, never ambient cookies or browser CSRF.
// Network policy is copied. SafeRate is required only for selected reads and
// AdminRate only for selected administrator mutations. Acceptance requires
// InvitationAccepter and SecretRate, not Service, Invitations or AdminRate.
// Update requires MetadataUpdater; MemberUpdate requires MemberUpdater. Each
// update selection needs AdminRate but neither Service nor SafeRate.
// Resend requires InvitationResender and AdminRate, not Service, Invitations or
// SafeRate: its native result owns the original command's delivery observation.
// Share each rate owner across its selected routes/requests.
// Now is trusted, prompt and concurrency-safe. MaximumDuration is 1ms..30s;
// inbound earlier deadlines win. Construction performs no owner reads or IO.
type Config struct {
	Network            identityhttp.NetworkConfig
	Sessions           *session.SessionService
	Service            Service
	MetadataUpdater    MetadataUpdater
	MemberUpdater      MemberUpdater
	Invitations        InvitationReader
	InvitationSender   InvitationSender
	InvitationResender InvitationResender
	InvitationAccepter InvitationAccepter
	// InvitationProofLimits must match the selected issuer's bounded parsing
	// profile. Zero uses capability.DefaultLimits; parsing grants no authority.
	InvitationProofLimits capability.Limits
	SafeRate              *identityhttp.SafeRateLimiter
	AdminRate             *AdminRateLimiter
	SecretRate            *identityhttp.KeyedSecretRateLimiter
	Now                   func() time.Time
	MaximumDuration       time.Duration
}

// FeatureConfig opts into exactly the selected operations. Empty selection is
// invalid; omission from FeatureServices exposes neither routes nor metadata.
// Invitation reads, original-key send and once-only acceptance are independently
// selectable. No team/browser/active-organization workflow is selected.
type FeatureConfig struct {
	Config                                           Config
	Create, Get, MemberList, MemberAdd, MemberRemove bool
	Update, MemberUpdate                             bool
	InvitationGet, InvitationListMine                bool
	InvitationSend, InvitationAccept                 bool
	InvitationResend                                 bool
}

// NewFeature constructs actual selected handlers and concrete wire metadata.
func NewFeature(c FeatureConfig) (identityhttp.Feature, error) {
	return NewFeatureWithMiddleware(c, nil)
}

// NewFeatureWithMiddleware binds real decode/authenticate/admit/handle phases.
// Trusted synchronous hooks cannot replace frozen credentials, request keys,
// tenant or target input. An invalid selection returns no partial feature.
func NewFeatureWithMiddleware(c FeatureConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if !c.Create && !c.Get && !c.MemberList && !c.MemberAdd && !c.MemberRemove && !c.Update && !c.MemberUpdate && !c.InvitationGet && !c.InvitationListMine && !c.InvitationSend && !c.InvitationAccept && !c.InvitationResend {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var operations []identityhttp.OperationDescriptor
	for _, selected := range []struct {
		op organization.Operation
		on bool
	}{{organization.Create, c.Create}, {organization.Update, c.Update}, {organization.Get, c.Get}, {organization.ListMembers, c.MemberList}, {organization.AddMember, c.MemberAdd}, {organization.UpdateMember, c.MemberUpdate}, {organization.RemoveMember, c.MemberRemove}, {organization.InvitationGet, c.InvitationGet}, {organization.InvitationListMine, c.InvitationListMine}, {organization.InvitationSend, c.InvitationSend}, {organization.InvitationAccept, c.InvitationAccept}, {organization.InvitationResend, c.InvitationResend}} {
		if !selected.on {
			continue
		}
		constructor := newHandler
		if selected.op == organization.InvitationGet || selected.op == organization.InvitationListMine {
			constructor = newInvitationHandler
		}
		h, err := constructor(c.Config, selected.op, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "organization", OperationID: string(selected.op), Handler: h, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: maximumResponseBytes})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		if selected.op == organization.InvitationGet || selected.op == organization.InvitationListMine {
			op.Wire = invitationWire(selected.op)
		} else if selected.op == organization.InvitationSend {
			op.Wire = invitationSendWire()
		} else {
			op.Wire = operationWire(selected.op)
		}
		if len(operations) == 0 {
			op.Wire.SecuritySchemes = []identityhttp.WireComponent{{Name: "OrganizationBearer", Definition: []byte(`{"type":"http","scheme":"bearer","bearerFormat":"opaque native session","description":"Exactly one Authorization: Bearer SP token. Ambient cookies never supply authority."}`)}}
		}
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "organization", Operations: operations})
}
func selectedMutation(op organization.Operation) bool {
	return op == organization.Create || op == organization.Update || op == organization.AddMember || op == organization.UpdateMember || op == organization.RemoveMember || op == organization.InvitationSend || op == organization.InvitationAccept || op == organization.InvitationResend
}
func nilService(service any) bool {
	if service == nil {
		return true
	}
	v := reflect.ValueOf(service)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// State is opaque request-local custody exposed only through PipelineValue after
// authentication. It is not an authority proof and must not outlive a request.
type State struct{ input func() *requestInput }

// Principal returns detached current actor metadata, never bearer or authority.
func (s State) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.input == nil {
		return "", "", false
	}
	v := s.input()
	return v.auth.TenantID, v.actor, v.actor != ""
}

// Format prevents traversal of request-local credentials and submitted input.
func (State) Format(s fmt.State, _ rune) { s.Write([]byte("organizationhttp.State(redacted)")) }

// MarshalJSON denies implicit request custody export.
func (State) MarshalJSON() ([]byte, error) { return nil, organization.ErrSensitiveSerialization }

// MarshalText denies implicit request custody export.
func (State) MarshalText() ([]byte, error) { return nil, organization.ErrSensitiveSerialization }

// LogValue redacts credentials and personal data.
func (State) LogValue() slog.Value { return slog.StringValue("organizationhttp.State(redacted)") }

// Format redacts runtime owners.
func (Config) Format(s fmt.State, _ rune) { s.Write([]byte("organizationhttp.Config(redacted)")) }

// MarshalJSON denies implicit runtime export.
func (Config) MarshalJSON() ([]byte, error) { return nil, organization.ErrSensitiveSerialization }

// MarshalText denies implicit runtime export.
func (Config) MarshalText() ([]byte, error) { return nil, organization.ErrSensitiveSerialization }

// LogValue redacts runtime owners.
func (Config) LogValue() slog.Value { return slog.StringValue("organizationhttp.Config(redacted)") }

// Format redacts selected runtime owners.
func (FeatureConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("organizationhttp.FeatureConfig(redacted)"))
}

// MarshalJSON denies implicit runtime export.
func (FeatureConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText denies implicit runtime export.
func (FeatureConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// LogValue redacts selected runtime owners.
func (FeatureConfig) LogValue() slog.Value {
	return slog.StringValue("organizationhttp.FeatureConfig(redacted)")
}

// All handlers are obtained through the selected canonical feature. This small
// private wrapper preserves response credential custody even during hook unwind.
type protectedPipeline struct{ pipeline http.Handler }

func (p *protectedPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h}, nil
}
