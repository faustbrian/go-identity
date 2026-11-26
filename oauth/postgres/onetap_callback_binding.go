package postgres

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The command ID is a recovery locator, not a credential. Derive it from
// immutable original identifiers so the same authenticated start cannot open
// a second callback command after restart or an envelope-key rotation.
func oneTapCallbackBinding(original identity.CommandBinding) (identity.CommandBinding, error) {
	if original.ValidateFor(kernel.OneTapStartOperation()) != nil ||
		original.ActorKind != authorization.SubjectServiceAccount ||
		original.RecordID != original.AnonymousFlowID ||
		original.CorrelationID != string(original.CommandID) {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParsePreAuthTransactionID(original.AnonymousFlowID); err != nil {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}

	frame := []byte("identity.oauth.onetap-callback:command-id:v1\x00")
	for _, field := range [...]string{string(original.TenantID), string(original.CommandID), original.AnonymousFlowID} {
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(field)))
		frame = append(frame, field...)
	}
	digest := sha256.Sum256(frame)
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(digest[:16]))
	if err != nil || id == original.CommandID {
		return identity.CommandBinding{}, identity.UnavailableError{}
	}
	op := kernel.OneTapCallbackOperation()
	callback := original
	callback.CommandID = id
	callback.OperationID, callback.SchemaID, callback.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	if callback.ValidateFor(op) != nil {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	return callback, nil
}
