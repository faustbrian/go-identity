package reference

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"github.com/faustbrian/go-identity/session"
)

// HTTPEmailRequestsConfiguration explicitly selects cookie-only keyed add/resend,
// change-request and/or new-address change-confirmation. Native owners are
// required, not their HTTP password-verification/signup routes. Origin and
// PolicyRevision are trusted deployment policy; ActorID is required only for
// change confirmation. Request routes preserve the original proof/cookie/CSRF
// custody. Change selects new-address proof plus required old-address notice,
// never old-address confirmation or automatic signin. AddressRemove separately
// selects native protected self-removal; no link delivery is implied.
type HTTPEmailRequestsConfiguration struct {
	VerificationSend, ChangeRequest, ChangeConfirm bool
	AddressRemove                                  bool
	Origin                                         string
	ActorID                                        identity.ActorID
	PolicyRevision                                 authorization.Revision
}

type emailRequestsHTTPState struct {
	now                        func() time.Time
	config                     HTTPEmailRequestsConfiguration
	secret                     *identityhttp.KeyedSecretRateLimiter
	confirmation               *identityhttp.ChallengeVerificationRateLimiter
	ownSecret, ownConfirmation bool
}

func (s *emailRequestsHTTPState) close() {
	if s.ownSecret {
		s.secret.Close()
	}
	if s.ownConfirmation {
		s.confirmation.Close()
	}
}

func composeEmailRequestsHTTP(c StoreConfiguration, owner *emailState, proof *passwordVerificationState, rate *httpRateState, change *passwordChangeHTTPState, confirmation *registrationVerificationHTTPState) (*emailRequestsHTTPState, error) {
	if c.HTTPEmailRequests == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_http_email_requests"}
	p := *c.HTTPEmailRequests
	if !p.VerificationSend && !p.ChangeRequest && !p.ChangeConfirm && !p.AddressRemove || owner == nil || c.Email == nil || c.Session == nil || c.Session.Native.Execution.Clock == nil || c.OTP == nil || rate == nil || c.HTTPRate == nil || p.PolicyRevision == 0 || uint64(p.PolicyRevision) != c.OTP.RequestKeys.Policy.PolicyVersion {
		return nil, invalid
	}
	u, err := url.Parse(p.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != p.Origin {
		return nil, invalid
	}
	if p.VerificationSend || p.ChangeRequest || p.AddressRemove {
		if proof == nil || proof.proofs == nil || proof.cookie == nil {
			return nil, invalid
		}
		for _, selected := range []struct {
			enabled bool
			native  *EmailManagementConfiguration
		}{{p.VerificationSend, c.Email.Verification}, {p.ChangeRequest, c.Email.Change}} {
			if selected.enabled && (selected.native == nil || selected.native.Keyed == nil || selected.native.Primary.Transport != session.CredentialCookie) {
				return nil, invalid
			}
		}
	}
	if p.AddressRemove && (c.Email.Removal == nil || owner.removal == nil || c.Email.Removal.Primary.Transport != session.CredentialCookie) {
		return nil, invalid
	}
	if p.VerificationSend && owner.verificationRequests == nil || p.ChangeRequest && owner.changeRequests == nil || p.ChangeConfirm && (owner.change == nil || p.ActorID == "") {
		return nil, invalid
	}
	out := &emailRequestsHTTPState{config: p, now: c.Session.Native.Execution.Clock.Now}
	retained := false
	defer func() {
		if !retained {
			out.close()
		}
	}()
	now := c.Session.Native.Execution.Clock.Now
	if p.ChangeRequest || p.AddressRemove {
		if change != nil {
			out.secret = change.rate
		} else {
			out.secret, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: rate.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
			if err != nil {
				return nil, invalid
			}
			out.ownSecret = true
		}
	}
	if p.ChangeConfirm {
		if confirmation != nil {
			// One existing native rate owner is shared; its request authority is
			// still independently fixed by the selected change handler.
			if confirmation.config.Origin != p.Origin || confirmation.config.ActorID != p.ActorID || confirmation.config.PolicyRevision != p.PolicyRevision {
				return nil, invalid
			}
			out.confirmation = confirmation.rate
		} else {
			out.confirmation, err = identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: rate.backend, Namespace: c.HTTPRate.Namespace, Key: c.HTTPRate.IdentifierKey, Now: now, MaximumDuration: c.HTTPRate.MaximumDuration})
			if err != nil {
				return nil, invalid
			}
			out.ownConfirmation = true
		}
	}
	retained = true
	return out, nil
}

func (s *Server) selectEmailRequests(network identityhttp.NetworkConfig, f FeatureSet, selection *emailhttp.FeatureConfig) error {
	state := s.state.features
	h := state.httpEmailRequests
	if h == nil {
		return nil
	}
	c := h.config
	request := emailhttp.RequestConfig{Network: network, Cookie: state.session.config.Cookie, Origin: identityhttp.Origin(c.Origin), PolicyRevision: c.PolicyRevision, MaximumDuration: state.timeout}
	if c.VerificationSend || c.ChangeRequest || c.AddressRemove {
		request.Proofs = state.passwordVerification.proofs
	}
	if c.AddressRemove {
		owner, err := f.EmailRemoval()
		if err != nil {
			return err
		}
		selection.AddressRemove = &emailhttp.RemovalConfig{Network: network, Proofs: state.passwordVerification.proofs, Service: owner, Rate: h.secret, Cookie: state.session.config.Cookie, Origin: identityhttp.Origin(c.Origin), PolicyRevision: c.PolicyRevision, MaximumDuration: state.timeout}
	}
	if c.VerificationSend {
		owner, err := f.EmailVerificationRequests()
		if err != nil {
			return err
		}
		config := request
		config.Verification, config.DeliveryRate = owner, s.state.httpRate.limiter
		selection.VerificationRequest = &config
	}
	if c.ChangeRequest {
		owner, err := f.EmailChangeRequests()
		if err != nil {
			return err
		}
		config := request
		config.Change, config.SecretRate, config.CurrentAddressProofPolicy = owner, h.secret, email.NotifyCurrentAddress
		selection.ChangeRequest = &config
	}
	if c.ChangeConfirm {
		owner, err := f.EmailChange()
		if err != nil {
			return err
		}
		selection.ChangeConfirmation = &emailhttp.ChangeConfirmationConfig{Network: network, Service: owner, Rate: h.confirmation, Origin: identityhttp.Origin(c.Origin), ActorID: c.ActorID, PolicyRevision: c.PolicyRevision, Now: h.now, MaximumDuration: state.timeout}
	}
	return nil
}

// The original proof repository is read before the guarded native request port.
// Join the whole transport to graph cancellation so shutdown cannot leave that
// earlier read outside request draining.
func (s *Server) guardEmailRequestLifetime(operation string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, done, err := s.state.enterFeature(r.Context(), true)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusServiceUnavailable)
			if operation == "identity.email.address-remove" {
				_ = json.NewEncoder(w).Encode(emailhttp.RemovalResponse{CommitOutcome: "none", Error: "unavailable"})
			} else {
				_ = json.NewEncoder(w).Encode(emailhttp.RequestResponse{CommitOutcome: "none", Error: "unavailable"})
			}
			return
		}
		defer done()
		next.ServeHTTP(w, r.Clone(ctx))
	})
}

// Format redacts trusted deployment configuration.
func (HTTPEmailRequestsConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPEmailRequestsConfiguration(redacted)")
}

// MarshalJSON refuses implicit configuration export.
func (HTTPEmailRequestsConfiguration) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText refuses implicit text export.
func (HTTPEmailRequestsConfiguration) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
