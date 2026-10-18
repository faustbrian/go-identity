package phone

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// WorkflowError is a stable redacted verification-contract diagnostic.
type WorkflowError string

// Error returns only the fixed diagnostic, never submitted custody.
func (e WorkflowError) Error() string { return string(e) }

const (
	// ErrInvalidVerification denies malformed or cross-scope workflow input.
	ErrInvalidVerification WorkflowError = "identity.phone.invalid_verification"
	// ErrVerificationDisclosure denies implicit workflow serialization.
	ErrVerificationDisclosure WorkflowError = "identity.phone.verification_explicit_projection_required"
)

// VerificationService is the separately selected existing-account phone
// enrollment workflow, not its implementation. Native adapters authenticate
// original session/action proof, current account/factors/policy and risk, and
// atomically coordinate identifier, OTP, delivery and audit effects. Contexts
// must be bounded; implementations honor cancellation and concurrent calls.
// Sending does not verify ownership. Verify consumes one original purpose-bound
// OTP; ambiguous outcomes retain original code-free recovery, never a new
// submission. These operations issue no session and expose no suppression choice.
// Signup, signin, replacement/removal and password recovery are not this profile.
type VerificationService interface {
	SendVerification(context.Context, EnrollmentRequest) (EnrollmentResult, error)
	Verify(context.Context, VerificationRequest) (VerificationResult, error)
	RecoverVerification(context.Context, VerificationRecoveryRequest) (VerificationResult, error)
}

// EnrollmentRequest is immutable opaque original enrollment custody. Zero is
// invalid. Copies are concurrent-safe and own no IO, callbacks or goroutines.
// Closure-backed state prevents fmt from traversing sensitive input even when
// an enclosing private field bypasses Format. Use Bindings only at an explicit
// native admission boundary; release every copy after terminal use.
type EnrollmentRequest struct{ read func() EnrollmentRequestSpec }

// EnrollmentRequestSpec is an explicitly sensitive construction/projection value,
// not an opaque secret-safe logging handle. Its exported fields reveal custody;
// do not serialize/log it or enclose it in diagnostics. Ordinary Format redacts
// only when invoked; private enclosing fields can bypass that method.
// Number is already canonicalized by an explicit NumberPolicy; it is not
// ownership evidence. Caller, Network and Device require trusted composition,
// not user-supplied forwarding or authorization facts. Session and Proof remain
// actual original custody; structural validity is not authentication. Do not
// mutate Caller maps during construction. Native configuration selects bearer
// versus cookie admission and enforces CSRF for the latter; zero CSRF is valid
// structural input for the bearer profile. The service allocates command IDs.
type EnrollmentRequestSpec struct {
	TenantID        identity.TenantID
	UserID          identity.UserID
	Number          Number
	Session         auth.BearerCredential
	Proof           auth.ReauthenticationProof
	Caller          authorization.DecisionContext
	CSRFToken       session.CSRFToken
	IdempotencyKey  identity.IdempotencyKey
	Network, Device string
}

// NewEnrollmentRequest validates bounded structure before copying original
// custody. Caller collections are cloned; no input mutation after return can
// change retained scope. Construction authenticates nothing and performs no IO.
func NewEnrollmentRequest(spec EnrollmentRequestSpec) (EnrollmentRequest, error) {
	if err := spec.Validate(); err != nil {
		return EnrollmentRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return EnrollmentRequest{read: func() EnrollmentRequestSpec { return spec }}, nil
}

// Bindings explicitly reveals sensitive original input with independent Caller
// collections. It establishes structural validity only, never authentication,
// freshness or permission. Do not log or serialize the returned projection.
func (r EnrollmentRequest) Bindings() (EnrollmentRequestSpec, error) {
	if r.read == nil {
		return EnrollmentRequestSpec{}, ErrInvalidVerification
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return EnrollmentRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate rejects zero custody and rechecks its unchanged structural binding.
// Native admission still authenticates the original proof and current policy.
func (r EnrollmentRequest) Validate() error {
	_, err := r.Bindings()
	return err
}

// Validate checks bounded structure and exact self/action binding only. It
// checks neither signatures, one-use proof custody, current session/version,
// assurance policy nor present freshness; those remain native-owner admission.
func (r EnrollmentRequestSpec) Validate() error {
	const action = "identity.phone.send-verification"
	if validateVerificationCaller(r.TenantID, r.UserID, r.Caller, action) != nil ||
		r.IdempotencyKey == (identity.IdempotencyKey{}) || !verificationText(r.Device, 128) || len(r.Network) > 128 {
		return ErrInvalidVerification
	}
	if _, err := r.Number.Record(); err != nil {
		return ErrInvalidVerification
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return ErrInvalidVerification
	}
	ip, err := netip.ParseAddr(r.Network)
	if err != nil || ip.Zone() != "" || ip.String() != r.Network {
		return ErrInvalidVerification
	}
	p := r.Proof
	if _, err := auth.NewProof(auth.ProofSpec(p.Proof)); err != nil || p.Proof.Tenant != string(r.TenantID) ||
		p.Proof.Subject != string(r.UserID) || p.Action != action || p.SessionVersion == 0 || !verificationASCII(p.SessionID, 128) {
		return ErrInvalidVerification
	}
	return nil
}

// VerificationRequest is immutable opaque code-submission custody. Zero is
// invalid; copies are concurrent-safe and own no IO or goroutines. Closure-backed
// state prevents nested formatting from traversing the original flow or bearer.
type VerificationRequest struct {
	read func() VerificationRequestSpec
}

// VerificationRequestSpec is an explicitly sensitive construction/projection
// value, not an opaque logging handle. Exported fields reveal original flow and
// correlation; do not log/serialize it or enclose it in private diagnostics.
// It is a new logical code submission against the original
// authenticated-session Send. The native owner selects attempt/command IDs and
// authenticates original subject, number, purpose, session and absolute limits.
// A repeat Verify is a new submission, not recovery of an ambiguous attempt.
type VerificationRequestSpec struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Caller        authorization.DecisionContext
	Flow          otp.SendFlow
	SendCommandID identity.CommandID
	Code          auth.OneTimeCode
}

// NewVerificationRequest validates bounded scope before copying it and cloning
// Caller collections. It grants neither flow possession nor code correctness.
func NewVerificationRequest(spec VerificationRequestSpec) (VerificationRequest, error) {
	if err := spec.Validate(); err != nil {
		return VerificationRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return VerificationRequest{read: func() VerificationRequestSpec { return spec }}, nil
}

// Bindings explicitly reveals sensitive original submission with independent
// Caller collections. Native OTP admission owns authentication and comparison;
// never log/serialize the returned projection or retain it after terminal use.
func (r VerificationRequest) Bindings() (VerificationRequestSpec, error) {
	if r.read == nil {
		return VerificationRequestSpec{}, ErrInvalidVerification
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return VerificationRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate rejects zero custody and rechecks its unchanged structural scope.
func (r VerificationRequest) Validate() error {
	_, err := r.Bindings()
	return err
}

// Validate checks bounded scope, not possession or OTP correctness. The opaque
// code has no inspection accessor; the native OTP attempt owner validates its
// custody before metering or comparison, matching the existing OTP contract.
func (r VerificationRequestSpec) Validate() error {
	if _, err := identity.ParseCommandID(string(r.SendCommandID)); err != nil {
		return ErrInvalidVerification
	}
	return validateVerificationFlow(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.phone.verify")
}

// VerificationRecovery retains immutable code-free original attempt correlation.
// Zero denies. It is not a selector for another workflow, permission to disclose
// history, or authority to resubmit. Copies are concurrent-safe and own no IO.
type VerificationRecovery struct {
	read func() (otp.CheckRecoveryBindings, error)
}

// NewVerificationRecovery checks original bounded correlation using the OTP
// owner's validator, without IO, authentication, renewal or code comparison.
// The send and consuming attempt must have distinct command identities.
func NewVerificationRecovery(b otp.CheckRecoveryBindings) (VerificationRecovery, error) {
	if b.SendCommandID == b.Attempt.CommandID {
		return VerificationRecovery{}, ErrInvalidVerification
	}
	original, err := otp.NewCheckRecovery(b)
	if err != nil {
		return VerificationRecovery{}, ErrInvalidVerification
	}
	// Closure custody prevents recursive fmt through an unexported enclosing
	// field from traversing the original scalar correlation (as for Number).
	return VerificationRecovery{read: original.Bindings}, nil
}

// Bindings explicitly returns sensitive scalar original correlation, never
// current validity, a bearer, a code or permission to execute/disclose history.
func (r VerificationRecovery) Bindings() (otp.CheckRecoveryBindings, error) {
	if r.read == nil {
		return otp.CheckRecoveryBindings{}, ErrInvalidVerification
	}
	b, err := r.read()
	if err != nil {
		return otp.CheckRecoveryBindings{}, ErrInvalidVerification
	}
	return b, nil
}

// VerificationRecoveryRequest is immutable opaque recovery-request custody.
// Zero denies. Copies are concurrent-safe and own no IO or goroutines; closure
// custody prevents nested diagnostic traversal of original possession.
type VerificationRecoveryRequest struct {
	read func() VerificationRecoveryRequestSpec
}

// VerificationRecoveryRequestSpec is an explicitly sensitive construction/
// projection value, not a safe logging handle. Its exported fields reveal flow
// and correlation. Do not log/serialize it or enclose it in private diagnostics.
// It observes an original ambiguous attempt under
// current recovery/disclosure policy and original session possession. It never
// carries a code, compares again, charges another attempt or renews authority.
type VerificationRecoveryRequestSpec struct {
	TenantID identity.TenantID
	UserID   identity.UserID
	Caller   authorization.DecisionContext
	Flow     otp.SendFlow
	Recovery VerificationRecovery
}

// NewVerificationRecoveryRequest validates bounded original scope before copying
// custody and cloning Caller collections. It performs no lookup or comparison.
func NewVerificationRecoveryRequest(spec VerificationRecoveryRequestSpec) (VerificationRecoveryRequest, error) {
	if err := spec.Validate(); err != nil {
		return VerificationRecoveryRequest{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return VerificationRecoveryRequest{read: func() VerificationRecoveryRequestSpec { return spec }}, nil
}

// Bindings explicitly reveals original sensitive correlation/possession with
// independent Caller collections, not disclosure or execution permission.
func (r VerificationRecoveryRequest) Bindings() (VerificationRecoveryRequestSpec, error) {
	if r.read == nil {
		return VerificationRecoveryRequestSpec{}, ErrInvalidVerification
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return VerificationRecoveryRequestSpec{}, err
	}
	spec.Caller = spec.Caller.Clone()
	return spec, nil
}

// Validate rejects zero custody and rechecks its unchanged structural scope.
func (r VerificationRecoveryRequest) Validate() error {
	_, err := r.Bindings()
	return err
}

// Validate checks structural self-session scope and the original attempt tenant.
// Native recovery independently authenticates original Send and query authority.
func (r VerificationRecoveryRequestSpec) Validate() error {
	b, err := r.Recovery.Bindings()
	if err != nil || b.Attempt.TenantID != r.TenantID {
		return ErrInvalidVerification
	}
	return validateVerificationFlow(r.TenantID, r.UserID, r.Caller, r.Flow, "identity.phone.verify.recover")
}

// EnrollmentResult is immutable opaque original command/result custody. Its zero
// may be returned alongside an error but has no valid Bindings. Copies support
// concurrent reads and own no resources; closure custody prevents nested fmt
// from traversing original binding or identifier correlation.
type EnrollmentResult struct{ read func() EnrollmentResultSpec }

// EnrollmentResultSpec is an explicitly sensitive construction/projection value,
// not an opaque safe logging handle. Do not log/serialize its exported fields or
// enclose it in private diagnostics. It preserves observed durability independently of later errors.
// IdentifierID is original pending identifier correlation, not verified status
// or evidence of SMS delivery. Replay retains original binding; Unknown must
// not be inferred to mean rollback. RetryAfter applies only to InProgress.
type EnrollmentResultSpec struct {
	Binding      identity.CommandBinding
	Outcome      identity.CommitOutcome
	IdentifierID identity.IdentifierID
	Replayed     bool
	RetryAfter   time.Duration
}

// NewEnrollmentResult validates original native operation/binding and bounded
// durability metadata. It does not establish commit truth or disclosure policy.
func NewEnrollmentResult(spec EnrollmentResultSpec) (EnrollmentResult, error) {
	if err := spec.Validate(); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{read: func() EnrollmentResultSpec { return spec }}, nil
}

// Bindings explicitly reveals sensitive original result correlation, not proof
// of durability or permission to disclose an identifier. Zero denies.
func (r EnrollmentResult) Bindings() (EnrollmentResultSpec, error) {
	if r.read == nil {
		return EnrollmentResultSpec{}, ErrInvalidVerification
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return EnrollmentResultSpec{}, err
	}
	return spec, nil
}

// Validate checks original native sending scope and internal metadata shape only.
func (r EnrollmentResultSpec) Validate() error {
	if validateVerificationResult(r.Binding, "identity.phone.send-verification", r.Outcome, r.RetryAfter) != nil {
		return ErrInvalidVerification
	}
	if r.IdentifierID != "" && string(r.IdentifierID) != r.Binding.RecordID || r.Outcome == identity.CommitOutcomeCommitted && r.IdentifierID == "" {
		return ErrInvalidVerification
	}
	return nil
}

// VerificationResult is immutable opaque original attempt/result custody. Zero
// may accompany an error but has no Bindings. Copies are concurrent-safe and own
// no resources; closure custody prevents nested diagnostic traversal.
type VerificationResult struct{ read func() VerificationResultSpec }

// VerificationResultSpec is an explicitly sensitive construction/projection
// value, not a safe logging handle. Its exported fields must not be logged,
// serialized implicitly or enclosed in private diagnostics. It preserves original attempt identity and observed durability
// independently of disclosure errors. Identifier is a native policy-authorized
// projection, not a credential or new session. Unknown retains original Recovery;
// replay/recovery must not recompare a code or repeat terminal effects.
type VerificationResultSpec struct {
	Binding    identity.CommandBinding
	Outcome    identity.CommitOutcome
	Identifier identity.IdentifierProjection
	Recovery   VerificationRecovery
	Replayed   bool
	RetryAfter time.Duration
}

// NewVerificationResult checks original native scope, disclosure shape and any
// retained OTP recovery correlation without claiming durable truth or authority.
func NewVerificationResult(spec VerificationResultSpec) (VerificationResult, error) {
	if err := spec.Validate(); err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{read: func() VerificationResultSpec { return spec }}, nil
}

// Bindings explicitly reveals sensitive result metadata. The returned immutable
// projections are not credentials, current authority or disclosure permission.
func (r VerificationResult) Bindings() (VerificationResultSpec, error) {
	if r.read == nil {
		return VerificationResultSpec{}, ErrInvalidVerification
	}
	spec := r.read()
	if err := spec.Validate(); err != nil {
		return VerificationResultSpec{}, err
	}
	return spec, nil
}

// Validate checks internal original correlation. A phone projection is permitted
// only for a fresh committed result and must match the exact tenant/user/record.
func (r VerificationResultSpec) Validate() error {
	if validateVerificationResult(r.Binding, "identity.phone.verify", r.Outcome, r.RetryAfter) != nil {
		return ErrInvalidVerification
	}
	if r.Identifier != (identity.IdentifierProjection{}) {
		b, err := r.Identifier.Bindings()
		if err != nil || r.Outcome != identity.CommitOutcomeCommitted || r.Replayed || b.TenantID != r.Binding.TenantID || b.UserID != r.Binding.UserID || string(b.IdentifierID) != r.Binding.RecordID || b.Kind != identity.IdentifierPhone || !b.Verified || b.VerificationState != identity.VerificationVerified {
			return ErrInvalidVerification
		}
	}
	if r.Recovery.read != nil {
		b, err := r.Recovery.Bindings()
		if err != nil || b.Attempt.TenantID != r.Binding.TenantID || b.Attempt.CommandID != r.Binding.CommandID {
			return ErrInvalidVerification
		}
	}
	return nil
}

func validateVerificationResult(b identity.CommandBinding, operation string, outcome identity.CommitOutcome, retryAfter time.Duration) error {
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: operation, SchemaID: operation + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || retryAfter < 0 || outcome != identity.CommitOutcomeInProgress && retryAfter != 0 {
		return ErrInvalidVerification
	}
	switch outcome {
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress:
		return nil
	default:
		return ErrInvalidVerification
	}
}

func validateVerificationCaller(tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, action authorization.Action) error {
	if !boundedVerificationCaller(caller) {
		return ErrInvalidVerification
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return ErrInvalidVerification
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return ErrInvalidVerification
	}
	if caller.Validate() != nil || string(caller.Request.Tenant) != string(tenant) || caller.Request.Subject.Kind != authorization.SubjectUser ||
		string(caller.Request.Subject.ID) != string(user) || caller.Request.Action != action {
		return ErrInvalidVerification
	}
	return nil
}

// These are this native request profile's admission limits, not authorization
// library defaults. Check the borrowed input before Caller.Clone: the pinned
// authorization Value constructors/validation do not bound strings or sets, and
// StringSet returns a copy. Its CollectionLength must be checked before that copy.
func boundedVerificationCaller(c authorization.DecisionContext) bool {
	const maximumBytes = 64 << 10
	used := 0
	add := func(n int) bool {
		if n < 0 || n > maximumBytes-used {
			return false
		}
		used += n
		return true
	}
	text := func(s string, maximum int, empty bool) bool {
		return (empty && s == "" || verificationText(s, maximum)) && add(len(s))
	}
	r := c.Request
	if len(r.Subject.Groups) > 64 || !text(string(r.Tenant), 128, false) || !text(string(r.Subject.Kind), 128, false) ||
		!text(string(r.Subject.ID), 128, false) || !text(string(r.Action), 256, false) || !text(string(r.Resource.Type), 256, false) ||
		!text(string(r.Resource.ID), 128, true) || !text(c.CorrelationID, 128, true) || !add(24) {
		return false
	}
	for _, group := range r.Subject.Groups {
		if !text(string(group), 128, false) {
			return false
		}
	}
	for _, attributes := range []authorization.Attributes{r.Attributes, r.Subject.Attributes, r.Resource.Attributes, r.Environment.Attributes} {
		if len(attributes) > 64 {
			return false
		}
		for key, value := range attributes {
			if !text(string(key), 128, false) || !add(1) {
				return false
			}
			switch value.Kind() {
			case authorization.ValueNull:
			case authorization.ValueString:
				v, _ := value.String()
				if !text(v, 4096, true) {
					return false
				}
			case authorization.ValueStringSet:
				n, ok := value.CollectionLength()
				if !ok || n > 64 {
					return false
				}
				values, _ := value.StringSet()
				for _, v := range values {
					if !text(v, 4096, true) {
						return false
					}
				}
			case authorization.ValueBool:
				if !add(1) {
					return false
				}
			case authorization.ValueInt, authorization.ValueFloat:
				if !add(8) {
					return false
				}
			case authorization.ValueTime:
				if !add(16) {
					return false
				}
			case authorization.ValueIP:
				ip, _ := value.IP()
				if !ip.IsValid() || ip.Zone() != "" || !add(16) {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func validateVerificationFlow(tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow otp.SendFlow, action authorization.Action) error {
	if validateVerificationCaller(tenant, user, caller, action) != nil {
		return ErrInvalidVerification
	}
	kind, _, _, err := flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationAuthenticatedSession {
		return ErrInvalidVerification
	}
	return nil
}

func verificationText(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func verificationASCII(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum {
		return false
	}
	for i := range s {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

// Format redacts all enrollment custody for every diagnostic verb.
func (EnrollmentRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.EnrollmentRequest(redacted)")
}

// MarshalJSON denies implicit enrollment disclosure.
func (EnrollmentRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit enrollment disclosure.
func (EnrollmentRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue emits only a constant marker.
func (EnrollmentRequest) LogValue() slog.Value {
	return slog.StringValue("phone.EnrollmentRequest(redacted)")
}

// Format redacts code, original session and command correlation.
func (VerificationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationRequest(redacted)")
}

// MarshalJSON denies implicit submission disclosure.
func (VerificationRequest) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit submission disclosure.
func (VerificationRequest) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue emits only a constant marker.
func (VerificationRequest) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationRequest(redacted)")
}

// Format redacts original attempt correlation.
func (VerificationRecovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationRecovery(redacted)")
}

// MarshalJSON denies implicit original-correlation disclosure.
func (VerificationRecovery) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit original-correlation disclosure.
func (VerificationRecovery) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue emits only a constant marker.
func (VerificationRecovery) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationRecovery(redacted)")
}

// Format redacts original session and recovery custody.
func (VerificationRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationRecoveryRequest(redacted)")
}

// MarshalJSON denies implicit recovery-request disclosure.
func (VerificationRecoveryRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// MarshalText denies implicit recovery-request disclosure.
func (VerificationRecoveryRequest) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// LogValue emits only a constant marker.
func (VerificationRecoveryRequest) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationRecoveryRequest(redacted)")
}

// Format redacts original pending identifier correlation.
func (EnrollmentResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.EnrollmentResult(redacted)")
}

// MarshalJSON denies implicit result disclosure.
func (EnrollmentResult) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit result disclosure.
func (EnrollmentResult) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue emits only a constant marker.
func (EnrollmentResult) LogValue() slog.Value {
	return slog.StringValue("phone.EnrollmentResult(redacted)")
}

// Format redacts private identifier projections and original attempt correlation.
func (VerificationResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationResult(redacted)")
}

// MarshalJSON denies implicit result disclosure.
func (VerificationResult) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit result disclosure.
func (VerificationResult) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue emits only a constant marker.
func (VerificationResult) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationResult(redacted)")
}

// Format redacts ordinary Spec formatting, not separately accessed or nested private fields.
func (EnrollmentRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.EnrollmentRequestSpec(redacted)")
}

// MarshalJSON denies implicit sensitive projection export.
func (EnrollmentRequestSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit sensitive projection export.
func (EnrollmentRequestSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts ordinary structured logging, not separately accessed fields.
func (EnrollmentRequestSpec) LogValue() slog.Value {
	return slog.StringValue("phone.EnrollmentRequestSpec(redacted)")
}

// Format redacts ordinary Spec formatting, not separately accessed or nested private fields.
func (VerificationRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationRequestSpec(redacted)")
}

// MarshalJSON denies implicit sensitive projection export.
func (VerificationRequestSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit sensitive projection export.
func (VerificationRequestSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts ordinary structured logging, not separately accessed fields.
func (VerificationRequestSpec) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationRequestSpec(redacted)")
}

// Format redacts ordinary Spec formatting, not separately accessed or nested private fields.
func (VerificationRecoveryRequestSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationRecoveryRequestSpec(redacted)")
}

// MarshalJSON denies implicit sensitive projection export.
func (VerificationRecoveryRequestSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// MarshalText denies implicit sensitive projection export.
func (VerificationRecoveryRequestSpec) MarshalText() ([]byte, error) {
	return nil, ErrVerificationDisclosure
}

// LogValue redacts ordinary structured logging, not separately accessed fields.
func (VerificationRecoveryRequestSpec) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationRecoveryRequestSpec(redacted)")
}

// Format redacts ordinary Spec formatting, not separately accessed or nested private fields.
func (EnrollmentResultSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.EnrollmentResultSpec(redacted)")
}

// MarshalJSON denies implicit sensitive projection export.
func (EnrollmentResultSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit sensitive projection export.
func (EnrollmentResultSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts ordinary structured logging, not separately accessed fields.
func (EnrollmentResultSpec) LogValue() slog.Value {
	return slog.StringValue("phone.EnrollmentResultSpec(redacted)")
}

// Format redacts ordinary Spec formatting, not separately accessed or nested private fields.
func (VerificationResultSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "phone.VerificationResultSpec(redacted)")
}

// MarshalJSON denies implicit sensitive projection export.
func (VerificationResultSpec) MarshalJSON() ([]byte, error) { return nil, ErrVerificationDisclosure }

// MarshalText denies implicit sensitive projection export.
func (VerificationResultSpec) MarshalText() ([]byte, error) { return nil, ErrVerificationDisclosure }

// LogValue redacts ordinary structured logging, not separately accessed fields.
func (VerificationResultSpec) LogValue() slog.Value {
	return slog.StringValue("phone.VerificationResultSpec(redacted)")
}
