package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// This is original sealed issuance custody, not current browser, provider,
// account or one-use authority. The callback owner must validate those inputs
// and consume through the existing session and capability owners atomically.
// The caller owns Proof's lifetime and must transfer or destroy it on all paths.
type oneTapVerifiedCallbackGrant struct {
	Original         identity.CommandBinding
	Proof            capability.Proof
	Grant            kernel.CapabilityPlan
	IssuedAt         time.Time
	CiphertextDigest [32]byte
}

// original must come from session/postgres.ReadProviderPreAuth, not browser
// fields. This read neither locks nor reserves, renews, erases or consumes it.
func (s *OneTapStartService) loadOneTapCallbackGrant(ctx context.Context, original session.ProviderPreAuthTransactionSpec) (out oneTapVerifiedCallbackGrant, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.pool.Raw() == nil || s.envelopes == nil {
		return out, identity.InvalidInputError{Field: "oauth_onetap_callback_grant"}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil {
			_ = out.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			out = oneTapVerifiedCallbackGrant{}
		}
	}()
	c := s.config()
	flow := original.Transaction.Binding
	intent := flow.Intent
	if original.Provider != s.selected || intent.TenantID != c.TenantID || intent.Action != oneTapStartOperationID ||
		intent.Origin != c.Issuance.Origin || intent.PolicyID != c.Issuance.PolicyID || intent.PolicyVersion != c.Issuance.PolicyVersion {
		return out, identity.ForbiddenError{}
	}
	if _, err := session.NewProviderPreAuthTransaction(original); err != nil ||
		!rpUTCTime(flow.IssuedAt) || flow.IssuedAt.Nanosecond() != 0 || !flow.ExpiresAt.Equal(flow.IssuedAt.Add(5*time.Minute)) {
		return out, identity.ForbiddenError{}
	}
	flowID, err := base64.RawURLEncoding.Strict().DecodeString(string(flow.ID))
	if err != nil || len(flowID) != 16 {
		return out, identity.ForbiddenError{}
	}
	bounded, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	var commandID, ciphertext []byte
	var operation string
	var issued, expires time.Time
	var erased bool
	err = s.pool.Raw().QueryRow(bounded, `SELECT origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext,erased_at IS NOT NULL
	 FROM `+rpQuotedSchema(c.Schema)+`.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, string(c.TenantID), flowID).
		Scan(&commandID, &operation, &issued, &expires, &ciphertext, &erased)
	defer clear(ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, identity.ForbiddenError{}
	}
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, identity.UnavailableError{}
	}
	if erased || len(ciphertext) == 0 || len(ciphertext) > 65536 || len(commandID) != 16 || operation != oneTapStartOperationID ||
		!issued.Equal(flow.IssuedAt) || !expires.Equal(flow.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	// PrepareRequestKey closes every other binding field; only the original
	// command ID is stored independently beside this exact tenant/flow row.
	op := kernel.OneTapStartOperation()
	b := identity.CommandBinding{CommandID: identity.CommandID(base64.RawURLEncoding.EncodeToString(commandID)), TenantID: c.TenantID,
		AnonymousFlowID: string(flow.ID), RecordID: string(flow.ID), CorrelationID: base64.RawURLEncoding.EncodeToString(commandID),
		ActorID: c.Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID,
		PolicyID: c.Issuance.PolicyID, PolicyVersion: c.Issuance.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion}
	if b.ValidateFor(op) != nil {
		return out, identity.ForbiddenError{}
	}
	aad, err := s.callbackAAD(b, flow.ExpiresAt)
	if err != nil {
		return out, err
	}
	var stored oneTapStoredCallbackGrant
	defer func() { clear(stored.Proof) }()
	if err := s.openOneTap(bounded, aad, ciphertext, 65536, &stored); err != nil {
		if bounded.Err() != nil {
			return out, bounded.Err()
		}
		return out, err
	}
	meta := kernel.CapabilityPlan(stored.Grant)
	if identity.CommandBinding(stored.Original) != b || meta.Purpose != oneTapCallbackPurpose || meta.MaxUses != 1 ||
		meta.ReplayKeyVersion == 0 || meta.ProofFingerprint == ([32]byte{}) || !meta.ExpiresAt.Equal(flow.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	if _, err := capability.NewReference(meta.CapabilityID, meta.Purpose, meta.ReplayDigest, meta.ExpiresAt); err != nil {
		return out, identity.ForbiddenError{}
	}
	out.Proof, err = capability.ParseProof(string(stored.Proof), c.Capability.Crypto.Limits)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	crypto, err := capability.NewService(c.Capability.Crypto)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	grant, err := crypto.Verify(bounded, out.Proof, oneTapCallbackPurpose, c.Capability.Audience)
	if err != nil {
		if bounded.Err() != nil {
			return out, bounded.Err()
		}
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			return out, identity.UnavailableError{}
		}
		return out, identity.ForbiddenError{}
	}
	payload := grant.Payload()
	if payload.Version != 1 || payload.Bearer || payload.MaxUses != 1 || len(payload.Audiences) != 1 || len(payload.Caveats) != 0 ||
		payload.ID != meta.CapabilityID || payload.CorrelationID != b.CorrelationID || grant.EnvelopeDigest() != meta.ProofFingerprint ||
		!payload.IssuedAt.Equal(flow.IssuedAt) || !payload.NotBefore.Equal(flow.IssuedAt) || !payload.ExpiresAt.Equal(flow.ExpiresAt) ||
		grant.Authorize(capability.Use{Issuer: c.Capability.Crypto.Issuer, Audience: c.Capability.Audience,
			Subject: b.AnonymousFlowID, Tenant: string(b.TenantID), Resource: b.RecordID, Operation: oneTapCallbackPurpose}) != nil {
		return out, identity.ForbiddenError{}
	}
	// Capability clock skew must not extend the original session flow lifetime.
	// Sample after verification so a slow verifier cannot cross that boundary.
	now := c.Issuance.Clock.Now().UTC()
	if !rpUTCTime(now) || now.Before(flow.IssuedAt) || !now.Before(flow.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	out.Original, out.Grant = b, meta
	out.IssuedAt, out.CiphertextDigest = flow.IssuedAt, sha256.Sum256(ciphertext)
	return out, nil
}
