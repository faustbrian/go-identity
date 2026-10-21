package anonymoushttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// UpgradeConfig explicitly selects the existing single-factor password target,
// distinct guest/permanent cookie policies and their original synchronizers.
// Subjects and Proofs are the actual native primary repositories, not public
// admission or caller verification callbacks. Sessions and Service must share
// those owners. All owners/Rate/Now are borrowed, bounded and concurrency-safe;
// they outlive handler calls. Construction performs no IO. Audience and positive
// PolicyRevision are trusted deployment configuration, never request choices.
// MaximumDuration is 1ms..30s and cannot extend an inbound deadline.
type UpgradeConfig struct {
	Network                   identityhttp.NetworkConfig
	Service                   anonymous.Upgrader
	Sessions                  *session.SessionService
	Proofs                    auth.ReauthenticationSource
	Subjects                  anonymous.Store
	Rate                      *identityhttp.KeyedSecretRateLimiter
	GuestCookie, TargetCookie session.CookiePolicy
	Origin                    identityhttp.Origin
	Device                    session.BrowserDeviceConfig
	PolicyRevision            authorization.Revision
	Audience                  string
	Now                       func() time.Time
	MaximumDuration           time.Duration
}

func (UpgradeConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "anonymoushttp.UpgradeConfig(redacted)")
}
func (UpgradeConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (UpgradeConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// UpgradeResponse preserves both distinct original command correlations.
// Upgraded means fresh HTTP credential delivery only, never current authority.
// Replay and recovery disclose safe metadata, no session or synchronizer.
type UpgradeResponse struct {
	Upgraded      bool             `json:"upgraded"`
	CommitOutcome string           `json:"commitOutcome"`
	Preparation   *CommandRecovery `json:"preparation,omitempty"`
	Recovery      *CommandRecovery `json:"recovery,omitempty"`
	Replayed      bool             `json:"replayed,omitempty"`
	Error         string           `json:"error,omitempty"`
}
type upgradeState struct {
	facts     identityhttp.NetworkFacts
	request   anonymous.UpgradeRequest
	target    session.GetResult
	device    session.BrowserDevice
	guestID   identity.UserID
	version   uint64
	proofID   auth.ProofID
	conflicts []anonymous.Conflict
}

// NewUpgradeHandler selects POST /v1/anonymous/upgrade only. Exactly one
// header-only Idempotency-Key is required; it does not weaken native one-use
// proof/capability consumption. X-CSRF-Token belongs to the guest and the sole
// X-Target-CSRF-Token belongs to the permanent cookie. Neither is accepted in
// JSON/query/Authorization. Closed JSON contains guestID, expectedVersion,
// proofID and conflicts (empty or profile.display_name/keep_target only).
// Locators select no authority: native original signed proof, both possessions,
// current owners and exact protected intent decide the transition atomically.
// Fresh commit alone issues the permanent cookie/CSRF and clears the guest
// cookie; historical/unknown outcomes retain both correlations without reveal.
// The server retains body/connection cleanup and bounded raw IO ownership.
func NewUpgradeHandler(c UpgradeConfig) (http.Handler, error) {
	if nilOwner(c.Service) || !c.Sessions.Configured() || nilOwner(c.Proofs) || nilOwner(c.Subjects) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || !visible(c.Audience, 256) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	guest, err := c.GuestCookie.DeletionAttributes()
	if err != nil || guest.Name == "__Host-identity_flow" || guest.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	target, err := c.TargetCookie.DeletionAttributes()
	if err != nil || target.Name == guest.Name || target.Name == "__Host-identity_flow" || target.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	reject := func(w http.ResponseWriter, r *http.Request, e error) {
		a := attemptFor(r)
		out := &a.upgrade
		f := failure{status: 503, code: "unavailable"}
		var specific failure
		if errors.Is(e, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		if errors.As(e, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		a.cookies, a.csrf, a.fresh = nil, "", nil
		out.Upgraded, out.Error = false, f.code
		writeResponse(w, f.status, out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[upgradeState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(r *http.Request) (upgradeState, error) {
			var s upgradeState
			attemptFor(r).ctx = r.Context()
			if r.URL.Path != "/v1/anonymous/upgrade" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			guestBearer, present, err := decoder.CookieBearer(r, guest.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			targetBearer, present, err := decoder.CookieBearer(r, target.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			guestToken, err := session.ParseToken(guestBearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			guestCredential, err := session.NewCredential(session.CredentialCookie, guestToken)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(targetBearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			guestCSRF, _, err := identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			var targetWire string
			count := 0
			for name, values := range r.Header {
				if strings.EqualFold(name, "X-Target-CSRF-Token") {
					count += len(values)
					if len(values) == 1 {
						targetWire = values[0]
					}
				}
			}
			targetCSRF, err := session.ParseCSRFToken(targetWire)
			if count != 1 || err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			device, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), facts.TenantID(), string(c.Origin), device.Token())
			if err != nil {
				return s, failure{status: 403, code: "denied"}
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 4 {
				return s, identityhttp.ErrInvalidInput
			}
			var id, proof string
			var version uint64
			var conflicts []struct {
				Field       string `json:"field"`
				Disposition string `json:"disposition"`
			}
			for _, name := range []string{"guestID", "expectedVersion", "proofID", "conflicts"} {
				if raw, ok := body[name]; !ok || string(raw) == "null" {
					return s, identityhttp.ErrInvalidInput
				}
			}
			conflictDecoder := json.NewDecoder(bytes.NewReader(body["conflicts"]))
			conflictDecoder.DisallowUnknownFields()
			if json.Unmarshal(body["guestID"], &id) != nil || json.Unmarshal(body["expectedVersion"], &version) != nil || json.Unmarshal(body["proofID"], &proof) != nil || conflictDecoder.Decode(&conflicts) != nil || version == 0 || version == ^uint64(0) || !visible(proof, 128) || len(proof) < 22 || len(conflicts) > 1 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseSubjectID(id); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if len(conflicts) == 1 {
				if conflicts[0].Field != "profile.display_name" || conflicts[0].Disposition != "keep_target" {
					return s, identityhttp.ErrInvalidInput
				}
				s.conflicts = []anonymous.Conflict{{Field: conflicts[0].Field, Disposition: anonymous.KeepTarget}}
			}
			s.facts, s.guestID, s.version, s.proofID = facts, identity.UserID(id), version, auth.ProofID(proof)
			s.request = anonymous.UpgradeRequest{TenantID: facts.TenantID(), TargetSession: targetBearer, TargetCSRF: targetCSRF, Guest: guestCredential, GuestCSRF: guestCSRF, Origin: string(c.Origin), Network: facts.ClientIP().String(), Device: s.device.DeviceID(), IdempotencyKey: key}
			return s, nil
		},
		Authenticate: func(r *http.Request, s upgradeState) (upgradeState, error) {
			token, err := session.ParseToken(s.request.TargetSession.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			credential, err := session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.target, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.request.TenantID, Credential: credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !s.target.Authenticated || s.target.ValidateAt(c.Now()) != nil {
				return s, failure{status: 403, code: "denied"}
			}
			target, err := s.target.Session.Bindings()
			if err != nil || target.Audience != c.Audience || target.Authentication.Kind != session.AuthenticationVerified {
				return s, failure{status: 403, code: "denied"}
			}
			s.request.Remember = target.Remember
			// As in the keyed password-change transport, leave ingress time absent.
			// It is part of exact native intent, not authoritative current time:
			// retries must preserve it while native primary/proof clocks own expiry.
			s.request.Caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(s.request.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(target.UserID)}, Action: "identity.anonymous.upgrade", Resource: authorization.Resource{Type: "anonymous", ID: authorization.ResourceID(s.guestID)}}}
			return s, nil
		},
		Admit: func(r *http.Request, s upgradeState) error {
			if s.target.ValidateAt(c.Now()) != nil || !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return rateError(c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.anonymous.upgrade", UserID: identity.UserID(s.request.Caller.Request.Subject.ID), IdempotencyKey: s.request.IdempotencyKey}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s upgradeState) {
			a := attemptFor(r)
			out := &a.upgrade
			if s.target.ValidateAt(c.Now()) != nil || !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			subject, err := c.Subjects.Read(r.Context(), anonymous.SubjectQuery{TenantID: s.request.TenantID, UserID: s.guestID})
			if err != nil {
				var denied identity.ForbiddenError
				if errors.Is(err, anonymous.ErrSubjectAbsent) || errors.As(err, &denied) {
					reject(w, r, failure{status: 403, code: "denied"})
				} else {
					reject(w, r, identityhttp.ErrUnavailable)
				}
				return
			}
			spec, err := subject.Record()
			if err != nil || spec.TenantID != s.request.TenantID || spec.UserID != s.guestID || spec.Version < s.version {
				reject(w, r, failure{status: 403, code: "denied"})
				return
			}
			// Terminal rows retain immutable original lifecycle metadata. Rebuild
			// only the proposed old intent, never authority: native possession and
			// prepared-command admission independently decide fresh work or replay.
			spec.State, spec.Version = anonymous.StateActive, s.version
			source, err := anonymous.NewAnonymousSubject(spec)
			if err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if err != nil {
				if errors.Is(err, auth.ErrInvalidProof) {
					reject(w, r, failure{status: 403, code: "denied"})
				} else {
					reject(w, r, identityhttp.ErrUnavailable)
				}
				return
			}
			s.request.TargetProof = record.Proof
			s.request.Plan = anonymous.MergePlan{Source: source, Target: identity.SubjectID(s.request.Caller.Request.Subject.ID), Conflicts: s.conflicts}
			target, _ := s.target.Session.Bindings()
			if s.request.Validate() != nil || record.Proof.Proof.ID != s.proofID || record.Proof.Proof.Audience != c.Audience || record.Proof.SessionID != target.SessionID || record.Proof.SessionVersion != target.Version {
				reject(w, r, failure{status: 403, code: "denied"})
				return
			}
			result, err := c.Service.Upgrade(r.Context(), s.request)
			out.CommitOutcome, out.Replayed = outcome(result.Outcome), result.Replayed
			for i, q := range []identity.RecoveryQuery{result.Preparation, result.Recovery} {
				if q.CommandID == "" {
					continue
				}
				if _, e := identity.ParseCommandID(string(q.CommandID)); e != nil || q.TenantID != s.request.TenantID || q.UserID != identity.UserID(s.request.Plan.Target) || q.ActorID != identity.ActorID(s.request.Plan.Target) || q.ActorKind != authorization.SubjectUser || q.OperationID != "identity.anonymous.upgrade" || q.AnonymousFlowID != "" || q.LinkMode != 0 || (i == 0 && q.RecordID != "") || (i == 1 && q.RecordID != string(s.guestID)) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				projection := &CommandRecovery{q.CommandID, q.TenantID, q.UserID, q.ActorID, q.ActorKind, q.OperationID, q.RecordID}
				if i == 0 {
					out.Preparation = projection
				} else {
					out.Recovery = projection
				}
			}
			if out.Preparation != nil && out.Recovery != nil && out.Preparation.CommandID == out.Recovery.CommandID {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil || r.Context().Err() != nil || result.Outcome != identity.CommitOutcomeCommitted || out.Preparation == nil || out.Recovery == nil {
				f := nativeFailure(result.Outcome, result.RetryAfter, err)
				if r.Context().Err() != nil {
					f = failure{status: 503, code: "unavailable"}
				}
				reject(w, r, f)
				return
			}
			if result.Replayed {
				writeResponse(w, 200, out)
				return
			}
			original, _ := s.target.Session.Bindings()
			issued, e := result.Session.Session.Bindings()
			if e != nil || issued.UserID != original.UserID || issued.TenantID != original.TenantID || issued.Audience != c.Audience || issued.Remember != original.Remember || issued.Authentication != original.Authentication || issued.SessionID == original.SessionID || issued.FamilyID == original.FamilyID || result.Session.CommandID != out.Recovery.CommandID || result.Session.Replayed || result.Session.CommitOutcome != identity.CommitOutcomeCommitted {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			cookie, synchronizer, e := sessionDelivery(c.TargetCookie, result.Session, result.CSRFToken, c.Now())
			if e != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out.Upgraded = true
			a.cookies = []string{cookie, guest.String()}
			a.csrf = synchronizer
			a.fresh = func() bool {
				now := c.Now()
				_, e := result.Session.Session.Lifetime(now)
				return s.target.ValidateAt(now) == nil && now.Before(result.Session.DeliveryValidUntil) && now.Before(s.device.ExpiresAt()) && now.Before(spec.ExpiresAt) && now.Before(record.Proof.Proof.ExpiresAt) && e == nil
			}
			a.revoke = func() { out.Upgraded = false; out.Error = "unavailable" }
			writeResponse(w, 200, out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &browserPipeline{pipeline: pipeline}, nil
}

func nativeFailure(out identity.CommitOutcome, retry time.Duration, err error) failure {
	f := failure{status: 503, code: "unavailable"}
	if out == identity.CommitOutcomeUnknown {
		return f
	}
	var denied identity.ForbiddenError
	var conflict identity.ConflictError
	var busy identity.InProgressError
	switch {
	case errors.As(err, &denied) || out == identity.CommitOutcomeNotCommitted:
		f = failure{status: 403, code: "denied"}
	case errors.As(err, &conflict) || out == identity.CommitOutcomeConflict:
		f = failure{status: 409, code: "conflict"}
	case errors.As(err, &busy):
		f = failure{status: 409, code: "in_progress", retry: busy.RetryAfter}
	case out == identity.CommitOutcomeInProgress:
		f = failure{status: 409, code: "in_progress", retry: retry}
	}
	return f
}
