package reference

import (
	"context"
	"net/http"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passkeyhttp "github.com/faustbrian/go-identity/http/passkey"
	"github.com/faustbrian/go-identity/session"
)

func (s *Server) passkeyFeature(network identityhttp.NetworkConfig, f FeatureSet) (*identityhttp.Feature, error) {
	state := s.state.features
	h := state.httpPasskey
	if h == nil {
		return nil, nil
	}
	owner, err := f.Passkeys()
	if err != nil {
		return nil, err
	}
	if state.session == nil || s.state.httpRate == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_passkey"}
	}
	n := h.native
	config := passkeyhttp.FeatureConfig{}
	revision := authorization.Revision(n.Flow.PolicyVersion)
	if h.config.Registration {
		if state.passwordVerification == nil {
			return nil, identity.InvalidInputError{Field: "reference_http_passkey"}
		}
		// composePasskey copies CSRF keys into its own native primaries. Retain
		// the same graph session keys here rather than the empty caller inputs.
		config.Registration = &passkeyhttp.RegistrationConfig{Network: network, Sessions: state.session.reader, Proofs: state.passwordVerification.proofs, Service: owner, OptionsRate: s.state.httpRate.limiter, VerificationRate: h.verification, Origin: identityhttp.Origin(n.Flow.Origin), SessionCookie: n.Issuer.Cookie, CSRFKeys: h.csrf, Device: h.device, PolicyRevision: revision, Audience: state.session.readerAudience, Now: h.now, MaximumDuration: n.Protocol.MaximumDuration}
	}
	if h.config.Signin {
		config.Signin = &passkeyhttp.SigninConfig{Network: network, Service: owner, OptionsRate: s.state.httpRate.limiter, VerificationRate: h.verification, Origin: identityhttp.Origin(n.Flow.Origin), FlowCookie: n.Flow.Cookie, SessionCookie: n.Issuer.Cookie, Device: h.device, Address: h.address, Discoverable: h.config.Discoverable, ActorID: n.Flow.ActorID, PolicyRevision: revision, Audience: state.session.readerAudience, Now: h.now, MaximumDuration: n.Protocol.MaximumDuration}
	}
	if h.config.Inventory {
		config.Inventory = &passkeyhttp.InventoryConfig{Network: network, Sessions: state.session.reader, Service: owner, Rate: h.safe, SessionCookie: n.Issuer.Cookie, PolicyRevision: revision, Now: h.now, MaximumDuration: n.Protocol.MaximumDuration}
	}
	if h.config.Update {
		if state.passwordVerification == nil {
			return nil, identity.InvalidInputError{Field: "reference_http_passkey"}
		}
		config.Update = &passkeyhttp.UpdateConfig{Network: network, Sessions: state.session.reader, Proofs: state.passwordVerification.proofs, Service: owner, Rate: h.secret, Origin: identityhttp.Origin(n.Flow.Origin), SessionCookie: n.Issuer.Cookie, CSRFKeys: h.csrf, PolicyRevision: revision, Audience: state.session.readerAudience, Now: h.now, MaximumDuration: n.Protocol.MaximumDuration}
	}
	feature, err := passkeyhttp.NewFeature(config)
	if err != nil {
		return nil, err
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range ops {
		ops[i].Handler = &passkeyLifetimeHandler{state: s.state, next: ops[i].Handler}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "passkey", Operations: ops})
	return &feature, err
}

// Concrete session/proof owners are borrowed by HTTP. Join their entire
// preliminary read, trusted hooks and native call to the existing graph drain;
// forwarding middleware binding preserves the leaf's actual pipeline phases.
type passkeyLifetimeHandler struct {
	state *storeState
	next  http.Handler
}

func (h *passkeyLifetimeHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.state == nil || h.next == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	next, err := identityhttp.WithOperationMiddleware(h.next, m)
	if err != nil {
		return nil, err
	}
	return &passkeyLifetimeHandler{state: h.state, next: next}, nil
}

func (h *passkeyLifetimeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, done, err := h.state.enterFeature(r.Context(), true)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("{\"error\":\"unavailable\"}\n"))
		return
	}
	defer done()
	h.next.ServeHTTP(w, r.Clone(ctx))
}

// This adapter changes only the shared initiation method names. Native passkey
// owns the original intent, entropy, remember custody, transaction and recovery.
type passkeyPreAuthHTTP struct{ owner *PasskeyService }

func (p passkeyPreAuthHTTP) Prepare(ctx context.Context, r session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	return p.owner.PrepareFlow(ctx, r)
}
func (p passkeyPreAuthHTTP) Issue(ctx context.Context, r session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	return p.owner.IssueFlow(ctx, r)
}
