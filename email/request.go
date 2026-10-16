package email

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/session"
)

// RequestPrimary borrows original password or selected TOTP/session proof and, for the selected
// cookie profile, its synchronizer. It is not current authority. Native owners
// authenticate the signed record, original possession and fresh current policy
// and atomically consume the proof with the protected mutation. Do not log its
// explicit fields or destroy/replace borrowed custody during a call.
type RequestPrimary struct {
	Session   auth.BearerCredential
	Proof     auth.ReauthenticationProof
	CSRFToken session.CSRFToken
}

// VerificationSendRequest selects keyed authenticated add or exact pending
// resend. Empty AddressID means add; otherwise the native owner resolves that
// existing target and an omitted Address. SubjectID, when present, must equal
// the authenticated self. Tenant/Caller/Network are trusted composition. Only
// the exact initiating key is retried: command and new-address IDs are selected
// by the winning native mapping, never by a browser or a replacement command.
// Caller collections and borrowed primary custody must remain immutable.
type VerificationSendRequest struct {
	TenantID       identity.TenantID
	SubjectID      identity.SubjectID
	Address        AddressInput
	AddressID      identity.IdentifierID
	Callback       url.URL
	IdempotencyKey identity.IdempotencyKey
	Primary        RequestPrimary
	Caller         authorization.DecisionContext
	Network        string
}

// CurrentAddressProofPolicy names the selected original-address requirement.
// Zero and unimplemented branches deny; it is startup policy, not browser input.
type CurrentAddressProofPolicy uint8

const (
	// NotifyCurrentAddress requires an independently retained old-address notice
	// after new-address confirmation; it does not claim old-address confirmation.
	NotifyCurrentAddress CurrentAddressProofPolicy = iota + 1
)

// ChangeRequestRequest creates a new-address possession challenge, not a primary
// swap. The selected native ChangeProfile owns previous-address selection and
// required session effects. CurrentAddressProofPolicy must match startup policy.
// No caller can choose a replacement command, actor, epoch or weaker proof.
type ChangeRequestRequest struct {
	TenantID                  identity.TenantID
	NewAddress                AddressInput
	CurrentAddressProofPolicy CurrentAddressProofPolicy
	Callback                  url.URL
	IdempotencyKey            identity.IdempotencyKey
	Primary                   RequestPrimary
	Caller                    authorization.DecisionContext
	Network                   string
}

// VerificationSendService owns the complete keyed native add/resend workflow.
// Rate-source output is sensitive original subject/destination metadata only;
// callers must not log/disclose it or treat it as current mutation authority.
// It must read retained input before mutable source, allocate no durable state,
// and return zero metadata on error. Execution owns atomic proof, domain, risk,
// issuance/delivery and audit effects. Calls honor bounded cancellation and
// support concurrent independent requests without caller-owned domain stores.
type VerificationSendService interface {
	VerificationSendRateSource(context.Context, VerificationSendRequest) (identity.UserID, string, error)
	VerificationSend(context.Context, VerificationSendRequest) (VerificationSendResult, error)
}

// ChangeRequestService retains original old-address policy and new-address
// intent through keyed request, delivery and recovery. Rate discovery has the
// same no-mutation/sensitive-metadata rules as VerificationSendService. A queued
// result is neither new-address ownership nor successful primary replacement.
type ChangeRequestService interface {
	ChangeRequestRateSource(context.Context, ChangeRequestRequest) (identity.UserID, string, error)
	ChangeRequest(context.Context, ChangeRequestRequest) (ChangeRequestResult, error)
}

// Validate checks bounded self scope and intrinsic original-proof structure.
// It does not validate a signature, current freshness, normalization, callbacks'
// allowlisting, CSRF or authority. Native execution independently owns those
// requirements. Historical retries do not substitute the current time here.
func (r VerificationSendRequest) Validate() error {
	if r.SubjectID != "" && string(r.SubjectID) != string(r.Caller.Request.Subject.ID) {
		return ErrInvalidVerification
	}
	if r.AddressID != "" {
		if _, err := identity.ParseIdentifierID(string(r.AddressID)); err != nil {
			return ErrInvalidVerification
		}
	}
	if !boundedRequestAddress(r.Address, r.AddressID != "") {
		return ErrInvalidVerification
	}
	return validateRequestPrimary(r.TenantID, r.Primary, r.Caller, r.Network, &r.Callback, r.IdempotencyKey, "identity.email.verification-send")
}

// Validate checks only the selected notify-old/new-address-proof structure.
// Current confirmation and other factor profiles are unavailable, not inferred.
func (r ChangeRequestRequest) Validate() error {
	if r.CurrentAddressProofPolicy != NotifyCurrentAddress || !boundedRequestAddress(r.NewAddress, false) {
		return ErrInvalidVerification
	}
	return validateRequestPrimary(r.TenantID, r.Primary, r.Caller, r.Network, &r.Callback, r.IdempotencyKey, "identity.email.change-request")
}

func boundedRequestAddress(address AddressInput, optional bool) bool {
	if address == "" {
		return optional
	}
	if len(address) > 4096 || !utf8.ValidString(string(address)) {
		return false
	}
	for _, r := range address {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateRequestPrimary(tenant identity.TenantID, p RequestPrimary, caller authorization.DecisionContext, network string, callback *url.URL, key identity.IdempotencyKey, action authorization.Action) error {
	return validateTargetRequestPrimary(tenant, p, caller, identity.UserID(caller.Request.Subject.ID), network, callback, key, action)
}

func validateTargetRequestPrimary(tenant identity.TenantID, p RequestPrimary, caller authorization.DecisionContext, target identity.UserID, network string, callback *url.URL, key identity.IdempotencyKey, action authorization.Action) error {
	if key == (identity.IdempotencyKey{}) || caller.Request.Subject.Kind != authorization.SubjectUser || caller.PolicyRevision == 0 || caller.Request.Resource.ID != authorization.ResourceID(target) || validateEmailCaller(tenant, caller, action) != nil {
		return ErrInvalidVerification
	}
	if callback != nil {
		if _, ok := verificationURL(callback, 2048); !ok {
			return ErrInvalidVerification
		}
	}
	if len(network) > 128 {
		return ErrInvalidVerification
	}
	ip, err := netip.ParseAddr(network)
	if err != nil || ip.Zone() != "" || ip.String() != network {
		return ErrInvalidVerification
	}
	if _, err := session.ParseToken(p.Session.Token()); err != nil {
		return ErrInvalidVerification
	}
	proof := p.Proof
	purpose := auth.Purpose("identity.password.verify")
	passwordProfile := proof.Proof.Method == "password" && proof.Proof.Assurance == auth.AssuranceSingleFactor
	// Only change-request has an active-TOTP profile. This structural check
	// grants no authority: the selected native owner authenticates and consumes
	// original evidence; password-only owners still reject enrolled factors.
	totpProfile := action == "identity.email.change-request" && proof.Proof.Method == "totp" && proof.Proof.Assurance == auth.AssuranceMultiFactor
	if totpProfile {
		purpose = "identity.email.change-request"
	}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(tenant), Subject: string(caller.Request.Subject.ID), Purpose: purpose, Audience: proof.Proof.Audience, Now: proof.Proof.IssuedAt}, SessionID: proof.SessionID, SessionVersion: proof.SessionVersion, Action: string(action), MaximumAge: 5 * time.Minute}
	if proof.Validate(use) != nil || !passwordProfile && !totpProfile {
		return ErrInvalidVerification
	}
	return nil
}

// VerificationSendResult is original credential-free request metadata. Queued
// means local committed delivery intent, never sent/verified or current account
// eligibility. Known commit survives a later error, which may omit all success
// fields. Unknown/pending/conflict disclose no address or successful versions.
type VerificationSendResult struct {
	CommandID                              identity.CommandID
	Outcome                                identity.CommitOutcome
	DeliveryState                          delivery.DeliveryState
	AddressID                              identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	RetryAfter                             time.Duration
}

// ChangeRequestResult has the same original pending-request semantics. It never
// claims the later primary switch or old-address notification has completed.
type ChangeRequestResult VerificationSendResult

// Validate checks internal observation shape, not durable truth or permission.
func (r VerificationSendResult) Validate() error {
	switch r.Outcome {
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress:
	default:
		return ErrInvalidVerification
	}
	if r.CommandID != "" {
		if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
			return ErrInvalidVerification
		}
	}
	if r.Outcome == identity.CommitOutcomeCommitted && r.CommandID == "" {
		return ErrInvalidVerification
	}
	if r.RetryAfter < 0 || r.RetryAfter > time.Minute || r.Outcome != identity.CommitOutcomeInProgress && r.RetryAfter != 0 {
		return ErrInvalidVerification
	}
	empty := r.DeliveryState == 0 && r.AddressID == "" && r.IdentifierVersion == 0 && r.VerificationVersion == 0
	if empty {
		return nil
	}
	if r.Outcome != identity.CommitOutcomeCommitted || r.DeliveryState != delivery.StateQueued || r.IdentifierVersion == 0 || r.VerificationVersion == 0 {
		return ErrInvalidVerification
	}
	if _, err := identity.ParseIdentifierID(string(r.AddressID)); err != nil {
		return ErrInvalidVerification
	}
	return nil
}

// Validate checks original request metadata only.
func (r ChangeRequestResult) Validate() error { return VerificationSendResult(r).Validate() }

// Format redacts borrowed credential and source proof.
func (RequestPrimary) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.RequestPrimary(redacted)"))
}

// MarshalJSON refuses implicit credential export.
func (RequestPrimary) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText refuses implicit credential export.
func (RequestPrimary) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (RequestPrimary) LogValue() slog.Value {
	return slog.StringValue("email.RequestPrimary(redacted)")
}

// Format redacts original request intent and correlation.
func (VerificationSendRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.VerificationSendRequest(redacted)"))
}

// MarshalJSON refuses implicit sensitive request export.
func (VerificationSendRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText refuses implicit sensitive request export.
func (VerificationSendRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (VerificationSendRequest) LogValue() slog.Value {
	return slog.StringValue("email.VerificationSendRequest(redacted)")
}

// Format redacts candidate and original request correlation.
func (ChangeRequestRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.ChangeRequestRequest(redacted)"))
}

// MarshalJSON refuses implicit sensitive request export.
func (ChangeRequestRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText refuses implicit sensitive request export.
func (ChangeRequestRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (ChangeRequestRequest) LogValue() slog.Value {
	return slog.StringValue("email.ChangeRequestRequest(redacted)")
}

// Format redacts original request metadata.
func (VerificationSendResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.VerificationSendResult(redacted)"))
}

// MarshalJSON refuses implicit metadata export; HTTP owns its closed projection.
func (VerificationSendResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText refuses implicit metadata export.
func (VerificationSendResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (VerificationSendResult) LogValue() slog.Value {
	return slog.StringValue("email.VerificationSendResult(redacted)")
}

// Format redacts original request metadata.
func (ChangeRequestResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.ChangeRequestResult(redacted)"))
}

// MarshalJSON refuses implicit metadata export.
func (ChangeRequestResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText refuses implicit metadata export.
func (ChangeRequestResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (ChangeRequestResult) LogValue() slog.Value {
	return slog.StringValue("email.ChangeRequestResult(redacted)")
}
