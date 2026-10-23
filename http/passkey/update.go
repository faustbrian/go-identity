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

// UpdateState retains private original session and signed-proof custody.
// Hooks may observe detached principal metadata, not replace the native input.
type UpdateState struct{ *updateState }
type updateState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	bearer     auth.BearerCredential
	csrf       session.CSRFToken
	credential session.Credential
	read       session.GetResult
	request    passkey.UpdateRequest
}

// Principal returns credential-free self-user metadata, not reusable authority.
func (s UpdateState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.updateState == nil || !s.read.Authenticated {
		return "", "", false
	}
	record, err := s.read.Session.Bindings()
	return record.TenantID, record.UserID, err == nil
}
func (UpdateState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.UpdateState(redacted)"))
}

// MarshalJSON prohibits implicit session/proof export.
func (UpdateState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit session/proof export.
func (UpdateState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// UpdateResponse contains safe native metadata only for the fresh committed
// mutation. Replays omit Credential and retain the original command outcome.
type UpdateResponse struct {
	CommandID     identity.CommandID  `json:"commandID"`
	CommitOutcome string              `json:"commitOutcome"`
	Replayed      bool                `json:"replayed"`
	Credential    *CredentialMetadata `json:"credential,omitempty"`
}

// NewUpdateHandler selects POST /v1/passkey/update with one header-only key,
// exact trusted Origin, actual session synchronizer and an original signed
// update-specific proof locator. The native owner allocates the sole command.
// No session cookie, proof, credential material or new challenge is returned.
func NewUpdateHandler(c UpdateConfig) (http.Handler, error) {
	return NewUpdateHandlerWithMiddleware(c, nil)
}

// NewUpdateHandlerWithMiddleware retains real decode/session/rate/mutation
// phases and original validity through synchronous hooks and final delivery.
func NewUpdateHandlerWithMiddleware(c UpdateConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
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
	fresh := func(s UpdateState) bool { return s.updateState != nil && s.read.ValidateAt(c.Now()) == nil }
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[UpdateState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (UpdateState, error) {
			s := UpdateState{&updateState{}}
			facts, body, key, err := i.decode(r, "update", true)
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
		Authenticate: func(r *http.Request, s UpdateState) (UpdateState, error) {
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
			if p.Proof.ID != auth.ProofID(s.body.proofID) || p.Proof.Tenant != string(record.TenantID) || p.Proof.Subject != string(record.UserID) || p.SessionID != record.SessionID || p.SessionVersion != record.Version || p.Action != "identity.passkey.update" || p.Proof.Purpose != "identity.password.verify" {
				return s, failure{status: 403, code: "denied"}
			}
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(correlation), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(record.UserID)}, Tenant: authorization.TenantID(record.TenantID), Action: "identity.passkey.update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
			s.request = passkey.UpdateRequest{Primary: password.ActionPrimaryRequest{TenantID: record.TenantID, Session: s.bearer, Proof: p, Caller: caller, CSRFToken: s.csrf}, ReferenceID: identity.CredentialID(s.body.referenceID), ExpectedVersion: s.body.expectedVersion, Name: s.body.name, IdempotencyKey: s.key, Network: s.facts.ClientIP().String()}
			// Native owns signature, original freshness and one-time use. Do not
			// reject a retained consumed/expired proof merely to hide an otherwise
			// authorized metadata-only original-command retry.
			requestDelivery(r).valid = func() bool { return fresh(s) }
			return s, nil
		},
		Admit: func(r *http.Request, s UpdateState) error {
			if !fresh(s) {
				return identityhttp.ErrUnavailable
			}
			_, user, _ := s.Principal()
			return rateFailure(c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.passkey.update", UserID: user, IdempotencyKey: s.key}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s UpdateState) {
			if !fresh(s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out, err := c.Service.Update(r.Context(), s.request)
			validReceipt := validUpdateReceipt(out, s.request)
			if validReceipt {
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
				if validReceipt {
					reject(w, r, domainFailure(err))
				} else {
					rejectNative(w, r, err)
				}
				return
			}
			if !validReceipt || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed && out.Credential != nil || !out.Replayed && out.Credential == nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response := UpdateResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}
			if !out.Replayed {
				item := out.Credential
				if item.ReferenceID != string(s.request.ReferenceID) || item.Version != s.request.ExpectedVersion+1 || item.State != "active" || item.Label != s.request.Name || item.CreatedAt.IsZero() {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				response.Credential = &CredentialMetadata{item.ReferenceID, item.Version, item.State, item.Label, item.AAGUID, item.BackupEligible, item.BackupState, item.CreatedAt, item.LastUsedAt}
			}
			requestDelivery(r).render(w, r, response, func() bool { return fresh(s) })
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: c.MaximumDuration}, nil
}

func validUpdateReceipt(out passkey.UpdateResult, r passkey.UpdateRequest) bool {
	b := out.Receipt.Binding
	return out.CommandID != "" && out.Receipt.Validate() == nil && out.Outcome == out.Receipt.Outcome && out.CommandID == b.CommandID && b.TenantID == r.Primary.TenantID && b.UserID == identity.UserID(r.Primary.Caller.Request.Subject.ID) && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID) && b.OperationID == "identity.passkey.update" && b.RecordID == string(r.ReferenceID) && b.SchemaID == "identity.passkey.update.native-v1" && b.SchemaVersion == 1 && b.PolicyVersion == uint64(r.Primary.Caller.PolicyRevision) && (out.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature != nil && out.Receipt.Feature.BeforeVersion == r.ExpectedVersion && out.Receipt.Feature.AfterVersion == r.ExpectedVersion+1)
}
