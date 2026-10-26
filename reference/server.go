package reference

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// DeploymentProfile selects authoritative PostgreSQL with optional Valkey.
// Zero is invalid. PostgreSQL-only selects durable admission; the optional
// Valkey profile keeps its explicit native recovery and coverage requirements.
type DeploymentProfile uint8

const (
	PostgresOnly DeploymentProfile = iota + 1
	PostgresWithValkey
)

// MigrationPolicy supplies explicit deployment bounds. Ordinary serving never
// applies migrations on startup; use StoreSet's separate Check/Plan/Apply APIs.
type MigrationPolicy struct {
	LockTimeout, CommandRetention time.Duration
	ApplyOnStartup                bool
}

// WorkerPolicy bounds cross-worker capacity, lease and shutdown drain. Workers
// remain explicitly scheduled through the graph; construction starts none.
type WorkerPolicy struct {
	MaxConcurrency              uint32
	LeaseDuration, DrainTimeout time.Duration
}

// BootstrapPolicy selects the offline bootstrap operation. Enabling remains
// rejected until its native one-time authority workflow is composed.
type BootstrapPolicy struct{ Enabled bool }

// ProviderConfig describes an explicitly selected provider. Names are unique
// 1..128 UTF-8 bytes; issuer/reference bounds are 2048/4096 bytes. Unsupported
// enabled providers are rejected, never silently omitted or defaulted.
type ProviderConfig struct {
	Name, Issuer, SecretReference string
	Enabled                       bool
}

// TenantResolver resolves only trusted context/deployment custody, honors the
// bounded caller context, and supports concurrent calls. Server checks its
// result against actual configured network facts before any workflow dispatch.
type TenantResolver interface {
	ResolveTenant(context.Context) (identity.TenantID, error)
}

// TenantPolicy requires one trusted tenant resolver; nil and typed nil deny.
type TenantPolicy struct{ Resolver TenantResolver }

// ReferenceConfig is copied during construction. Callbacks/resources remain
// borrowed, bounded and concurrency-safe; callers must not mutate inputs during
// construction. All five PolicySet members are mandatory and remain unchanged.
// Authorize must be the same comparable service handle already bound into the
// sealed graph (use a pointer for services with noncomparable value fields).
// Secrets and callback internals are never exported by formatting/serialization.
type ReferenceConfig struct {
	Profile               DeploymentProfile
	Policies              identity.PolicySet
	HTTP                  identityhttp.TransportPolicy
	ProviderConfiguration []ProviderConfig
	Migration             MigrationPolicy
	Workers               WorkerPolicy
	Bootstrap             BootstrapPolicy
	Tenant                TenantPolicy
}

// ReadinessCode is a stable opaque blocking label, never an endpoint or error.
type ReadinessCode string

// DegradationCode is a stable opaque optional-dependency label.
type DegradationCode string

// Readiness is a detached instantaneous observation, not admission authority.
type Readiness struct {
	Ready    bool
	Failures []ReadinessCode
	Degraded []DegradationCode
}

// Server owns one immutable router/document over the selected sealed graph.
// It acquires no listener, pool, worker, migration or native startup ownership.
// Initialize/recovery, migration deployment and StoreSet.Close remain explicit.
// The current profile supports probes and selected original-flow initiation;
// remaining OTP/browser routes and full lifecycle readiness remain in progress.
type Server struct {
	state    *storeState
	handler  http.Handler
	document identityhttp.OpenAPIDocument
	policies identity.PolicySet
	tenant   TenantResolver
	budget   time.Duration
}

// NewServer validates the selected graph, callbacks, deployment profile and
// transport before exposing a handler. It performs no IO, callbacks, entropy,
// startup, migrations or goroutine creation; failure returns no partial server.
func NewServer(c ReferenceConfig, d ReferenceDependencies, f FeatureSet) (*Server, error) {
	invalid := identity.InvalidInputError{Field: "reference_server"}
	s := f.state
	if s == nil || d.PostgreSQL == nil || d.PostgreSQL != s.pool || !matchingProfile(c.Profile, s.durable) || c.Bootstrap.Enabled || c.Migration.ApplyOnStartup || c.Migration.LockTimeout < time.Millisecond || c.Migration.LockTimeout > 5*time.Minute || c.Migration.CommandRetention < time.Hour || c.Migration.CommandRetention > 87600*time.Hour || c.Workers.MaxConcurrency < 1 || c.Workers.MaxConcurrency > 1024 || c.Workers.LeaseDuration < time.Second || c.Workers.LeaseDuration > time.Hour || c.Workers.DrainTimeout < time.Second || c.Workers.DrainTimeout > time.Hour || nilServerDependency(c.Tenant.Resolver) || len(c.ProviderConfiguration) > 64 {
		return nil, invalid
	}
	for i, p := range c.ProviderConfiguration {
		if !utf8.ValidString(p.Name) || len(p.Name) < 1 || len(p.Name) > 128 || !utf8.ValidString(p.Issuer) || len(p.Issuer) > 2048 || !utf8.ValidString(p.SecretReference) || len(p.SecretReference) > 4096 || p.Enabled {
			return nil, invalid
		}
		for _, previous := range c.ProviderConfiguration[:i] {
			if p.Name == previous.Name {
				return nil, invalid
			}
		}
	}
	// The upstream evaluator performs the exact complete-member validation
	// without invoking or replacing any policy callback.
	if _, err := identity.NewPolicyEvaluator(c.Policies, identity.PolicyEvaluatorConfig{PolicyID: "reference-composition", PolicyVersion: 1, Reasons: []identity.PolicyReason{"composition"}, MaximumDuration: time.Second}); err != nil {
		return nil, invalid
	}
	s.mu.Lock()
	valid := !s.closed && s.features != nil && s.features.composed
	if valid {
		valid = sameServerAuthorization(c.Policies.Authorize, s.features.authorize)
	}
	for _, host := range c.HTTP.Network.TenantHosts {
		if s.tenants[string(host.TenantID)] == nil {
			valid = false
		}
	}
	s.mu.Unlock()
	if !valid {
		return nil, invalid
	}
	server := &Server{state: s, policies: c.Policies, tenant: c.Tenant.Resolver, budget: min(c.HTTP.HandlerTimeout, 2*time.Second)}
	probe, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: server.lifecycle, Timeout: server.budget, Readiness: identityhttp.ReadinessProvider{Check: func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
		r := server.Readiness(ctx)
		codes := make([]identityhttp.ReadinessCode, len(r.Failures))
		for i, c := range r.Failures {
			codes[i] = identityhttp.ReadinessCode(c)
		}
		return identityhttp.ReadinessSnapshot{Ready: r.Ready, Codes: codes}, nil
	}}})
	if err != nil {
		return nil, invalid
	}
	contributions := []identityhttp.Feature{probe}
	organizationFeature, err := server.organizationFeature(c.HTTP.Network)
	if err != nil {
		return nil, err
	}
	if organizationFeature != nil {
		contributions = append(contributions, *organizationFeature)
	}
	passkeyFeature, err := server.passkeyFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if passkeyFeature != nil {
		contributions = append(contributions, *passkeyFeature)
	}
	anonymousFeature, err := server.anonymousFeature(c.HTTP.Network)
	if err != nil {
		return nil, err
	}
	if anonymousFeature != nil {
		contributions = append(contributions, *anonymousFeature)
	}
	phoneFeature, err := server.phoneVerificationFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	phoneSignin, err := server.phoneSigninFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if phoneSignin != nil {
		if phoneFeature == nil {
			phoneFeature = phoneSignin
		} else {
			combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: append(phoneFeature.Operations(), phoneSignin.Operations()...)})
			if err != nil {
				return nil, err
			}
			phoneFeature = &combined
		}
	}
	phoneOTP, err := server.phoneOTPSigninFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if phoneOTP != nil {
		if phoneFeature == nil {
			phoneFeature = phoneOTP
		} else {
			combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: append(phoneFeature.Operations(), phoneOTP.Operations()...)})
			if err != nil {
				return nil, err
			}
			phoneFeature = &combined
		}
	}
	phoneRemoval, err := server.phoneRemovalFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if phoneRemoval != nil {
		if phoneFeature == nil {
			phoneFeature = phoneRemoval
		} else {
			combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: append(phoneFeature.Operations(), phoneRemoval.Operations()...)})
			if err != nil {
				return nil, err
			}
			phoneFeature = &combined
		}
	}
	phoneChange, err := server.phoneChangeFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if phoneChange != nil {
		if phoneFeature == nil {
			phoneFeature = phoneChange
		} else {
			combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: append(phoneFeature.Operations(), phoneChange.Operations()...)})
			if err != nil {
				return nil, err
			}
			phoneFeature = &combined
		}
	}
	phoneReset, err := server.phonePasswordResetFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if phoneReset != nil {
		if phoneFeature == nil {
			phoneFeature = phoneReset
		} else {
			combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: append(phoneFeature.Operations(), phoneReset.Operations()...)})
			if err != nil {
				return nil, err
			}
			phoneFeature = &combined
		}
	}
	if phoneFeature != nil {
		contributions = append(contributions, *phoneFeature)
	}
	selected, err := server.sessionFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, err
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	selected, err = server.emailSigninFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	// Email OTP verification is a separately selected profile, never a fallback
	// branch of public OTP signin or a prerequisite of password endpoints.
	selected, err = server.emailOTPVerificationFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	selected, err = server.emailOTPChangeFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		// Owned OTP factories declare no transport-feature dependencies; their
		// native dependencies are explicit constructor inputs. Join disjoint
		// operations under their one canonical owner, never duplicate its ID.
		joined := false
		for n, existing := range contributions {
			if existing.ID() == "identity/otp" {
				combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: append(existing.Operations(), selected.Operations()...)})
				if err != nil {
					return nil, invalid
				}
				contributions[n] = combined
				joined = true
				break
			}
		}
		if !joined {
			contributions = append(contributions, *selected)
		}
	}
	selected, err = server.passwordFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	selected, err = server.usernameFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	selected, err = server.magicLinkFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	selected, err = server.mfaFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	selected, err = server.emailFeature(c.HTTP.Network, f)
	if err != nil {
		return nil, invalid
	}
	if selected != nil {
		contributions = append(contributions, *selected)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: contributions})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_server_operations"}
	}
	network, err := identityhttp.NewNetworkResolver(c.HTTP.Network)
	if err != nil {
		return nil, invalid
	}
	for i := range operations {
		if operations[i].Route.Path != "/healthz" && operations[i].Route.Path != "/readyz" {
			operations[i].Handler = server.guardTenant(network, operations[i].Handler)
		}
	}
	handler, document, err := identityhttp.NewRouter(c.HTTP, operations, nil)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_server_router"}
	}
	server.handler, server.document = handler, document
	return server, nil
}

func matchingProfile(profile DeploymentProfile, durable bool) bool {
	return durable && profile == PostgresOnly || !durable && profile == PostgresWithValkey
}

func sameServerAuthorization(a, b any) bool {
	left, right := reflect.ValueOf(a), reflect.ValueOf(b)
	return !nilServerDependency(a) && !nilServerDependency(b) && left.Comparable() && right.Comparable() && left.Interface() == right.Interface()
}

// guardTenant runs inside the native router's network, timeout and body guards.
// Re-resolving the same request with the same frozen policy avoids accepting
// caller-supplied context facts. The callback cannot override host ownership.
func (s *Server) guardTenant(network *identityhttp.NetworkResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deny := func() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "{\"error\":\"unavailable\"}\n")
		}
		if r == nil || network == nil || s.lifecycle() == identityhttp.ServerStopped {
			deny()
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.budget)
		defer cancel()
		owned := r.Clone(ctx)
		facts, err := network.Resolve(owned)
		if err != nil || !facts.Valid() || facts.Scheme() != "https" || facts.Realm() != identityhttp.RealmTenant || ctx.Err() != nil {
			deny()
			return
		}
		tenant, err := resolveServerTenant(ctx, s.tenant)
		if err != nil || ctx.Err() != nil || tenant == "" || tenant != facts.TenantID() || s.lifecycle() == identityhttp.ServerStopped {
			deny()
			return
		}
		// The callback budget bounds admission only. The native router already
		// owns the whole request deadline; forwarding this shorter context would
		// prematurely cancel multi-step password work after successful admission.
		cancel()
		next.ServeHTTP(w, r)
	})
}

func resolveServerTenant(ctx context.Context, resolver TenantResolver) (tenant identity.TenantID, err error) {
	defer func() {
		if recover() != nil {
			tenant = ""
			err = identity.InvalidInputError{Field: "tenant_resolution"}
		}
	}()
	return resolver.ResolveTenant(ctx)
}

func nilServerDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func (s *Server) lifecycle() identityhttp.ServerState {
	if s == nil || s.state == nil {
		return identityhttp.ServerStopped
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.closed {
		return identityhttp.ServerStopped
	}
	if s.state.features.ready {
		return identityhttp.ServerRunning
	}
	return identityhttp.ServerStarting
}

// Handler returns the validated immutable router; zero Server returns nil.
func (s *Server) Handler() http.Handler {
	if s == nil {
		return nil
	}
	return s.handler
}

// OpenAPI returns the native document's detached public snapshots; zero is empty.
func (s *Server) OpenAPI() identityhttp.OpenAPIDocument {
	if s == nil {
		return identityhttp.OpenAPIDocument{}
	}
	return s.document
}

// Health reports process-only liveness without dependency IO or callbacks.
func (s *Server) Health(ctx context.Context) Readiness {
	if s == nil || s.state == nil || ctx == nil || ctx.Err() != nil {
		return Readiness{Failures: []ReadinessCode{"process_unavailable"}}
	}
	return Readiness{Ready: true}
}

// Readiness never substitutes a listener or initialized flag for native health.
// Before startup it performs no IO. Initialized selected graphs require fresh
// complete migration compatibility and every selected tenant's original native
// custody. One server budget bounds the observation; closure joins/cancels it.
// Success is momentary, not cached admission or permission to skip workflow
// checks. No counter, marker, TTL, evidence or health authority is renewed.
func (s *Server) Readiness(ctx context.Context) Readiness {
	return s.readiness(ctx)
}

// Format redacts deployment policies and resource/callback internals.
func (ReferenceConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.ReferenceConfig(redacted)")
}

// MarshalJSON rejects implicit deployment export.
func (ReferenceConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText rejects implicit deployment export.
func (ReferenceConfig) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// Format redacts borrowed resources, deployment policies and callback custody.
func (Server) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.Server(redacted)")
}

// MarshalJSON rejects implicit export of the owned server graph.
func (Server) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}

// MarshalText rejects implicit export of the owned server graph.
func (Server) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_serialization"}
}
