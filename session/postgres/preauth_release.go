package postgres

import (
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// ReleasePreAuth terminalizes an exact original reserved flow only within the
// registered owner's live sealed OTP noncommit callback. The coordinator proves
// rollback or unanimous primary noncommit; no data-only proof is accepted.
// Zero, foreign, expired callback and returned handles deny. Original flow
// expiry does not block terminal release and never authorizes it. The exact
// predecessor is released at its unchanged rollback generation or coordinator
// successor. Original cookie, policy, intent and timeline remain unchanged.
//
// This borrows the callback's bounded transaction, closes all cursors, invokes
// no callbacks and retains no handles. The owner must abort on every error.
// Install PreAuthReleaseMigrationSource first. Malformed input is InvalidInput;
// absent/terminal/changed custody is Forbidden; storage is Unavailable and
// cancellation/deadline classifications are preserved. No initiation or native
// OTP contributor registration is performed by this storage operation.
func ReleasePreAuth(ctx context.Context, w kernel.OTPReleaseWork, owner kernel.OTPReservationContributor, c Config, record session.PreAuthTransaction) error {
	if ctx == nil {
		return identity.InvalidInputError{Field: "session_preauth"}
	}
	if ctx.Err() != nil {
		return readError(ctx, ctx.Err())
	}
	b, err := w.Binding(owner)
	if err != nil {
		return identity.ForbiddenError{}
	}
	previous := PreAuthUse{Command: b.Command, Fingerprint: b.Fingerprint, Generation: b.PreviousGeneration}
	return releasePreAuth(ctx, w, c, record, previous, b.Generation)
}

// Private SQL portion. Only ReleasePreAuth supplies noncommit authority; scalar
// custody and successor fields are never an independently callable proof API.
func releasePreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, previous PreAuthUse, next uint64) error {
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, record)
	if err != nil {
		return err
	}
	defer stop()
	if !previous.valid(s) || next == 0 || (next != previous.Generation && (previous.Generation == ^uint64(0) || next != previous.Generation+1)) {
		return identity.InvalidInputError{Field: "session_preauth_use"}
	}
	if err = lockPreAuthRecord(bounded, q, c, s, canonical, &previous, true); err != nil {
		return err
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(previous.Command.CommandID))
	count, err := q.Exec(bounded, `UPDATE `+pgx.Identifier{c.Schema}.Sanitize()+`.preauth_transactions SET state='released',version=$3::numeric,generation=$4::numeric WHERE tenant_id=$1 AND flow_id=$2 AND state='reserved' AND version=$5::numeric AND command_id=$6 AND fingerprint=$7 AND generation=$8::numeric`, string(s.Binding.Intent.TenantID), string(s.Binding.ID), strconv.FormatUint(s.Version+2, 10), strconv.FormatUint(next, 10), strconv.FormatUint(s.Version+1, 10), command, previous.Fingerprint[:], strconv.FormatUint(previous.Generation, 10))
	return preAuthWriteResult(bounded, count, err)
}
