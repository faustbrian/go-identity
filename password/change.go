package password

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

// ChangeRequest is the adapter-neutral keyed authenticated password-change
// input. TenantID, Caller and Network require trusted transport provenance;
// neither an untrusted body nor a client-selected user creates that provenance.
// Session and Proof retain the authentication owner's original values, not a
// reconstructed identity/password proof. IdempotencyKey is required for direct
// calls and maps only from one HTTP Idempotency-Key header for HTTP calls.
// Password is borrowed, not normalized or destroyed; destroy it after return.
// Treat the request as immutable during a call. The native service independently
// checks signed proof, current authority, configured risk and raw-byte policy.
// No clock, assurance, session-revocation policy or recovery bypass is selected
// by this request. Explicit fields are sensitive: never log their projections
// or put this input into private diagnostic wrappers that bypass its methods.
type ChangeRequest struct {
	TenantID       identity.TenantID
	Session        auth.BearerCredential
	Proof          auth.ReauthenticationProof
	Password       primitive.Secret
	Caller         authorization.DecisionContext
	Network        string
	IdempotencyKey identity.IdempotencyKey
}

// Validate checks only intrinsic input bounds, key presence and trusted caller
// scope consistency. It performs no IO, crypto, proof validation or secret
// borrowing, and provides no freshness or mutation authority. A structurally
// accepted request may still contain a zero/expired/foreign proof; only the
// upstream signed-proof engine and protected native transaction can admit it.
// Deployment password limits are separately enforced by the selected service.
// A live-secret length observation is not a custody lease; native work must
// borrow again and deny concurrent destruction. Zero denies without defaults.
func (r ChangeRequest) Validate() error {
	if !boundedChangeText(string(r.TenantID)) || !boundedChangeText(string(r.Caller.Request.Subject.ID)) || !boundedChangeText(r.Network) || r.Caller.Request.Subject.Kind != authorization.SubjectUser || r.Caller.Request.Tenant != authorization.TenantID(r.TenantID) || r.Caller.Validate() != nil || r.IdempotencyKey == (identity.IdempotencyKey{}) || len(r.Session.Token()) == 0 || len(r.Session.Token()) > 128 || r.Password.Len() == 0 || r.Password.Len() > 1<<20 {
		return ErrPasswordWork
	}
	return nil
}

func boundedChangeText(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Format redacts direct password-change request diagnostics for every verb.
func (ChangeRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.ChangeRequest(redacted)")
}

// MarshalJSON rejects implicit export of sensitive input and borrowed owners.
func (ChangeRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects text and map-key export of sensitive input.
func (ChangeRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue returns only a fixed redacted diagnostic marker.
func (ChangeRequest) LogValue() slog.Value {
	return slog.StringValue("password.ChangeRequest(redacted)")
}

// ChangeResult describes the original durable command, never password/hash,
// proof or bearer material. Outcome zero means no authoritative observation,
// not proof of rollback. CredentialVersion and AuthorityInvalidated are usable
// only on error-free known commitment. AuthorityInvalidated describes the
// predecessor credential authority, not necessarily revocation of every session:
// eligible sessions may continue under the configured successor policy.
// Busy/unknown outcomes must not cause a new key, regeneration or automatic
// replay. Use original scoped code-free recovery to reconcile ambiguity.
type ChangeResult struct {
	CommandID            identity.CommandID
	Outcome              identity.CommitOutcome
	CredentialVersion    uint64
	AuthorityInvalidated bool
}

// ChangeService is the narrow platform-owned workflow port used by optional
// transports. Select the real durable platform adapter, not a consumer-written
// store or callback workflow. Implementations are concurrency-safe with
// independently owned request secrets, honor bounded caller contexts and retain
// earlier proof/risk expiry. They own signed-original validation, mandatory
// screening before hashing, protected counter admission and same-transaction
// proof/password/credential/session/audit/outbox effects. Matching retries retain
// the original outcome; changed complete input conflicts without repeated work.
// Errors are redacted and preserve standard cancellation plus commit ambiguity.
// Recovery never requires resubmitting secrets or creates new credential output;
// it independently enforces current scoped result-access policy. Borrowed
// resources must outlive calls; no resource ownership transfers through this port.
type ChangeService interface {
	Change(context.Context, ChangeRequest) (ChangeResult, error)
	Recover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (ChangeResult, error)
}
