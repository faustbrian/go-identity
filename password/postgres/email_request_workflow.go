package passwordpostgres

import (
	"context"
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
)

// EmailRequestWorkflow supplies the storage-neutral email request ports over
// the existing keyed native owner. It owns no transaction, journal, stores,
// retries or goroutines. The immutable borrowed native service must outlive
// calls. Independent requests are concurrency-safe; zero denies. Unselected
// actions and proof policies never fall back to another workflow.
type EmailRequestWorkflow struct {
	native func() *KeyedEmailManagementService
}

var _ email.VerificationSendService = (*EmailRequestWorkflow)(nil)
var _ email.ChangeRequestService = (*EmailRequestWorkflow)(nil)

// NewEmailRequestWorkflow binds an already constructed native keyed owner
// without IO, cryptographic work or dependency ownership transfer.
func NewEmailRequestWorkflow(native *KeyedEmailManagementService) (*EmailRequestWorkflow, error) {
	if native == nil || native.native == nil || native.native.primary == nil || native.config == nil {
		return nil, email.ErrInvalidVerification
	}
	return &EmailRequestWorkflow{native: func() *KeyedEmailManagementService { return native }}, nil
}

func portableEmailRequest(r email.VerificationSendRequest) EmailManagementRequest {
	return EmailManagementRequest{Primary: EmailPrimaryRequest{TenantID: r.TenantID, AddressID: r.AddressID, Session: r.Primary.Session, Proof: r.Primary.Proof, CSRFToken: r.Primary.CSRFToken, Caller: r.Caller.Clone()}, Address: r.Address, CallbackURL: r.Callback.String(), Network: r.Network}
}
func portableEmailChange(r email.ChangeRequestRequest) EmailManagementRequest {
	return EmailManagementRequest{Primary: EmailPrimaryRequest{TenantID: r.TenantID, Session: r.Primary.Session, Proof: r.Primary.Proof, CSRFToken: r.Primary.CSRFToken, Caller: r.Caller.Clone()}, Address: r.NewAddress, CallbackURL: r.Callback.String(), Network: r.Network}
}

// VerificationSendRateSource preserves native original-custody-first rate
// discovery. It returns sensitive subject/destination metadata, never current
// authority; errors disclose neither. It does not allocate a request mapping.
func (s *EmailRequestWorkflow) VerificationSendRateSource(ctx context.Context, r email.VerificationSendRequest) (identity.UserID, string, error) {
	if s == nil || s.native == nil || ctx == nil {
		return "", "", email.ErrInvalidVerification
	}
	if err := r.Validate(); err != nil {
		return "", "", err
	}
	return s.native().RequestRateSource(ctx, portableEmailRequest(r), r.IdempotencyKey, r.AddressID != "")
}

// VerificationSend dispatches explicit add/resend on the same keyed native
// owner. Native current authority, normalization, counters, one-use consumption,
// delivery and original outcome/recovery remain authoritative. No secret is
// destroyed, regenerated, retained or retried by this forwarding boundary.
func (s *EmailRequestWorkflow) VerificationSend(ctx context.Context, r email.VerificationSendRequest) (email.VerificationSendResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return email.VerificationSendResult{}, email.ErrInvalidVerification
	}
	if err := r.Validate(); err != nil {
		return email.VerificationSendResult{}, err
	}
	request := portableEmailRequest(r)
	var result EmailManagementResult
	var err error
	if r.AddressID != "" {
		result, err = s.native().VerificationResend(ctx, request, r.IdempotencyKey)
	} else {
		result, err = s.native().VerificationSend(ctx, request, r.IdempotencyKey)
	}
	return projectEmailRequest(result, err)
}

// ChangeRequestRateSource authenticates original sensitive rate metadata for
// the selected notify-old/new-address-proof profile without executing it.
func (s *EmailRequestWorkflow) ChangeRequestRateSource(ctx context.Context, r email.ChangeRequestRequest) (identity.UserID, string, error) {
	if s == nil || s.native == nil || ctx == nil {
		return "", "", email.ErrInvalidVerification
	}
	if err := r.Validate(); err != nil {
		return "", "", err
	}
	return s.native().RequestRateSource(ctx, portableEmailChange(r), r.IdempotencyKey, false)
}

// ChangeRequest creates one retained pending native candidate. It neither
// promotes the address nor substitutes another current-address proof policy.
func (s *EmailRequestWorkflow) ChangeRequest(ctx context.Context, r email.ChangeRequestRequest) (email.ChangeRequestResult, error) {
	if s == nil || s.native == nil || ctx == nil {
		return email.ChangeRequestResult{}, email.ErrInvalidVerification
	}
	if err := r.Validate(); err != nil {
		return email.ChangeRequestResult{}, err
	}
	result, err := s.native().ChangeRequest(ctx, portableEmailChange(r), r.IdempotencyKey)
	out, err := projectEmailRequest(result, err)
	return email.ChangeRequestResult(out), err
}

func projectEmailRequest(r EmailManagementResult, err error) (email.VerificationSendResult, error) {
	out := email.VerificationSendResult{CommandID: r.CommandID, Outcome: r.Outcome, RetryAfter: r.RetryAfter}
	if err == nil && r.Outcome == identity.CommitOutcomeCommitted {
		out.DeliveryState, out.AddressID = delivery.StateQueued, r.AddressID
		out.IdentifierVersion, out.VerificationVersion = r.IdentifierVersion, r.VerificationVersion
	}
	if r.Outcome == identity.CommitOutcomeInvalid && err != nil {
		return out, err
	}
	if out.Validate() != nil {
		return email.VerificationSendResult{CommandID: r.CommandID, Outcome: r.Outcome}, identity.UnavailableError{}
	}
	return out, err
}

// Format prevents traversal of borrowed native custody.
func (EmailRequestWorkflow) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailRequestWorkflow(redacted)"))
}

// MarshalJSON refuses implicit service export.
func (EmailRequestWorkflow) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText refuses implicit service export.
func (EmailRequestWorkflow) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// LogValue returns a fixed redacted marker.
func (EmailRequestWorkflow) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.EmailRequestWorkflow(redacted)")
}
