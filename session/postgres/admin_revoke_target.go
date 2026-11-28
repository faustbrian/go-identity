package postgres

import (
	"context"
	"crypto/sha256"
	"errors"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type adminRevokeTarget struct {
	record  session.Session
	version uint64
	digest  [sha256.Size]byte
}

// Read through the existing exact primary key lookup. A row from another
// subject or audience is indistinguishable from absence to the caller.
func (r *Repository) readAdminRevokeTarget(ctx context.Context, b identity.CommandBinding, audience string) (adminRevokeTarget, bool, error) {
	stored, err := r.Get(ctx, b.TenantID, b.RecordID)
	if errors.Is(err, ErrRecordAbsent) {
		return adminRevokeTarget{}, false, nil
	}
	if err != nil {
		return adminRevokeTarget{}, false, err
	}
	return freezeAdminRevokeTarget(b, audience, stored)
}

func freezeAdminRevokeTarget(b identity.CommandBinding, audience string, stored StoredSession) (adminRevokeTarget, bool, error) {
	spec, err := stored.Session.Bindings()
	if err != nil || spec.TenantID != b.TenantID || spec.SessionID != b.RecordID {
		return adminRevokeTarget{}, false, identity.UnavailableError{}
	}
	if spec.UserID != b.UserID || spec.Audience != audience || stored.Revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != spec.FamilyVersion {
		return adminRevokeTarget{}, false, nil
	}
	if spec.Version == 0 || spec.Version == ^uint64(0) {
		return adminRevokeTarget{}, false, identity.UnavailableError{}
	}
	payload, _, err := encodeRecord(stored.Session)
	if err != nil {
		return adminRevokeTarget{}, false, identity.UnavailableError{}
	}
	return adminRevokeTarget{record: stored.Session, version: spec.Version, digest: sha256.Sum256(payload)}, true, nil
}
