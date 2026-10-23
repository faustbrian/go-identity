package passkeyhttp

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// DeleteState retains original session, synchronizer, proof and request custody.
// Hooks may inspect detached principal metadata, not substitute native inputs.
type DeleteState struct{ *deleteState }
type deleteState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	bearer     auth.BearerCredential
	csrf       session.CSRFToken
	credential session.Credential
	read       session.GetResult
	request    passkey.DeleteRequest
}

// Principal returns safe self-user scope, never a current authorization lease.
func (s DeleteState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.deleteState == nil || !s.read.Authenticated {
		return "", "", false
	}
	r, err := s.read.Session.Bindings()
	return r.TenantID, r.UserID, err == nil
}

func (DeleteState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.DeleteState(redacted)"))
}

// MarshalJSON prohibits implicit session/proof export.
func (DeleteState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit session/proof export.
func (DeleteState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// DeleteResponse projects original durability only. Neither fresh success nor
// retained retry returns credentials, session material or recovery authority.
type DeleteResponse struct {
	CommandID     identity.CommandID `json:"commandID"`
	CommitOutcome string             `json:"commitOutcome"`
	Replayed      bool               `json:"replayed"`
}

// NewDeleteHandler selects POST /v1/passkey/delete with one header-only retry
// key, exact trusted Origin, real session CSRF and an original signed delete
// proof locator. Native owns the sole command, recovery and atomic removal.
// This handler neither clears the retained password session nor issues cookies.
func NewDeleteHandler(c DeleteConfig) (http.Handler, error) {
	return NewDeleteHandlerWithMiddleware(c, nil)
}

// NewDeleteHandlerWithMiddleware retains real decode/session/rate/mutation
// phases and current session validity through synchronous hooks and delivery.
func NewDeleteHandlerWithMiddleware(c DeleteConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || absent(c.Proofs) || absent(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || !visible(c.Audience, 256) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 {
		return nil, identityhttp.ErrInvalidInput
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	for index, key := range c.CSRFKeys {
		if key.Version() == 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		for _, prior := range c.CSRFKeys[:index] {
			if key.Version() == prior.Version() {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	i, err := newIngress(c.Network, c.Origin)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: i.origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	fresh := func(s DeleteState) bool { return s.deleteState != nil && s.read.ValidateAt(c.Now()) == nil }
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[DeleteState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (DeleteState, error) {
			s := DeleteState{&deleteState{}}
			facts, body, key, err := i.decode(r, "delete", true)
			if err != nil {
				return s, err
			}
			s.facts, s.body, s.key = facts, body, key
			s.bearer, _, err = i.decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(decoder, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(s.bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			return s, err
		},
		Authenticate: func(r *http.Request, s DeleteState) (DeleteState, error) {
			var err error
			s.read, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !s.read.Authenticated {
				return s, failure{status: 401, code: "unauthenticated"}
			}
			if !fresh(s) {
				return s, identityhttp.ErrUnavailable
			}
			record, err := s.read.Session.Bindings()
			if err != nil || record.TenantID != s.facts.TenantID() || record.Audience != c.Audience {
				return s, identityhttp.ErrUnavailable
			}
			binding := session.CSRFBinding{TenantID: record.TenantID, SessionID: record.SessionID, SessionVersion: record.Version}
			matched := false
			for _, key := range c.CSRFKeys {
				if s.read.Session.CSRFState().Check(binding, s.csrf, key) == nil {
					matched = true
					break
				}
			}
			if !matched {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			proof, err := c.Proofs.Reauthentication(r.Context(), auth.ProofID(s.body.proofID))
			if err != nil {
				if errors.Is(err, auth.ErrInvalidProof) {
					return s, failure{status: 403, code: "denied"}
				}
				return s, identityhttp.ErrUnavailable
			}
			p := proof.Proof
			if p.Proof.ID != auth.ProofID(s.body.proofID) || p.Proof.Tenant != string(record.TenantID) || p.Proof.Subject != string(record.UserID) || p.SessionID != record.SessionID || p.SessionVersion != record.Version || p.Action != "identity.passkey.delete" || p.Proof.Purpose != "identity.password.verify" {
				return s, failure{status: 403, code: "denied"}
			}
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(correlation), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(record.UserID)}, Tenant: authorization.TenantID(record.TenantID), Action: "identity.passkey.delete", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
			s.request = passkey.DeleteRequest{Primary: password.ActionPrimaryRequest{TenantID: record.TenantID, Session: s.bearer, Proof: p, Caller: caller, CSRFToken: s.csrf}, ReferenceID: identity.CredentialID(s.body.referenceID), ExpectedVersion: s.body.expectedVersion, IdempotencyKey: s.key, Network: s.facts.ClientIP().String()}
			// Native distinguishes one-use mutation from current-authorized
			// historical retry. A transport proof-age check would break recovery.
			requestDelivery(r).valid = func() bool { return fresh(s) }
			return s, nil
		},
		Admit: func(r *http.Request, s DeleteState) error {
			if !fresh(s) {
				return identityhttp.ErrUnavailable
			}
			_, user, _ := s.Principal()
			return rateFailure(c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.passkey.delete", UserID: user, IdempotencyKey: s.key}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s DeleteState) {
			if !fresh(s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out, err := c.Service.Delete(r.Context(), s.request)
			valid := validDeleteReceipt(out, s.request)
			if valid {
				switch out.Outcome {
				case identity.CommitOutcomeCommitted:
					requestDelivery(r).observeCommitted(out.CommandID)
				case identity.CommitOutcomeUnknown:
					requestDelivery(r).observed = &failure{status: 503, code: "unknown", commandID: out.CommandID, outcome: "unknown"}
				case identity.CommitOutcomeNotCommitted:
					requestDelivery(r).observed = &failure{status: 503, code: "not_committed", commandID: out.CommandID, outcome: "not_committed"}
				case identity.CommitOutcomeConflict:
					requestDelivery(r).observed = &failure{status: 409, code: "conflict", commandID: out.CommandID, outcome: "conflict"}
				case identity.CommitOutcomeInProgress:
					requestDelivery(r).observed = &failure{status: 409, code: "in_progress", commandID: out.CommandID, outcome: "in_progress", retry: out.Receipt.RetryAfter}
				}
			}
			if err != nil {
				if valid {
					reject(w, r, domainFailure(err))
				} else {
					rejectNative(w, r, err)
				}
				return
			}
			if !valid || out.Outcome != identity.CommitOutcomeCommitted {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			requestDelivery(r).render(w, r, DeleteResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}, func() bool { return fresh(s) })
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: c.MaximumDuration}, nil
}

func validDeleteReceipt(out passkey.DeleteResult, r passkey.DeleteRequest) bool {
	b := out.Receipt.Binding
	// Removal's canonical lifecycle advances the kernel credential reference,
	// not the independently versioned display metadata selected by the request.
	// The native keyed owner binds that expected metadata into original intent.
	return out.CommandID != "" && out.Receipt.Validate() == nil && out.Outcome == out.Receipt.Outcome && out.CommandID == b.CommandID && b.TenantID == r.Primary.TenantID && b.UserID == identity.UserID(r.Primary.Caller.Request.Subject.ID) && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID) && b.OperationID == "identity.passkey.delete" && b.RecordID == string(r.ReferenceID) && b.SchemaID == "identity.passkey.delete.native-v1" && b.SchemaVersion == 1 && b.PolicyVersion == uint64(r.Primary.Caller.PolicyRevision) && (out.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature != nil && out.Receipt.Feature.BeforeVersion > 0 && out.Receipt.Feature.AfterVersion == out.Receipt.Feature.BeforeVersion+1)
}
