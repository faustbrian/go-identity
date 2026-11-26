package postgres

import (
	"context"
	"encoding/base64"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Erasure belongs to the successful callback's original Work, after the
// capability owner provisionally consumed the exact authenticated grant.
// The caller must propagate any error so all callback effects roll back.
func (s *OneTapStartService) eraseOneTapCallbackGrant(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, grant oneTapVerifiedCallbackGrant) error {
	if ctx == nil || s == nil || s.config == nil {
		return identity.InvalidInputError{Field: "oauth_onetap_callback_grant"}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	callback, err := oneTapCallbackBinding(grant.Original)
	if err != nil {
		return err
	}
	consumption, err := w.OneTapCallbackConsumption(owner)
	if err != nil {
		return err
	}
	if consumption.Command != callback || consumption.Plan != grant.Grant ||
		grant.CiphertextDigest == ([32]byte{}) || !rpUTCTime(grant.IssuedAt) || grant.IssuedAt.Nanosecond() != 0 ||
		!grant.Grant.ExpiresAt.Equal(grant.IssuedAt.Add(5*time.Minute)) {
		return identity.ForbiddenError{}
	}
	c := s.config()
	if grant.Original.TenantID != c.TenantID || grant.Original.ActorID != c.Issuance.ActorID ||
		grant.Original.PolicyID != c.Issuance.PolicyID || grant.Original.PolicyVersion != c.Issuance.PolicyVersion {
		return identity.ForbiddenError{}
	}
	now := c.Issuance.Clock.Now().UTC()
	if !rpUTCTime(now) || now.Before(grant.IssuedAt) || !now.Before(grant.Grant.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	flow, err := base64.RawURLEncoding.Strict().DecodeString(grant.Original.AnonymousFlowID)
	if err != nil || len(flow) != 16 {
		return identity.ForbiddenError{}
	}
	originalCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(grant.Original.CommandID))
	if err != nil || len(originalCommand) != 16 {
		return identity.ForbiddenError{}
	}
	bounded, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	count, err := w.Exec(bounded, oneTapCallbackGrantEraseSQL(c.Schema), string(c.TenantID), flow, originalCommand,
		grant.Original.OperationID, grant.IssuedAt, grant.Grant.ExpiresAt, grant.CiphertextDigest[:])
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func oneTapCallbackGrantEraseSQL(schema string) string {
	// Keep origin-command equality as a row check so the alternate command
	// uniqueness index cannot replace the original tenant/flow lookup key.
	return `UPDATE ` + rpQuotedSchema(schema) + `.onetap_callback_grants
 SET proof_ciphertext=NULL,erased_at=pg_catalog.clock_timestamp()
 WHERE tenant_id=$1 AND flow_id=$2 AND origin_command_id IS NOT DISTINCT FROM $3 AND origin_operation=$4
 AND issued_at=$5 AND expires_at=$6 AND issued_at<=pg_catalog.clock_timestamp()
 AND expires_at>pg_catalog.clock_timestamp() AND erased_at IS NULL
 AND pg_catalog.sha256(proof_ciphertext)=$7`
}
