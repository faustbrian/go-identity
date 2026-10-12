package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// RequireMFAConsumedPreAuth fences the unchanged original browser flow already
// consumed by the committed magic-link primary. It is read-only: it neither
// reactivates nor consumes that flow again. Only the exact registered native
// TOTP completion owner, during its bounded preparation or Apply callback, may
// invoke it. Primary must come from verified original child issuance custody,
// never a request field. The native owner must separately compare the submitted
// opaque cookie digest, original origin/callback/Remember and signed child scope.
// This check alone is not browser possession, factor proof or session authority.
// Locks last until the sole coordinator closes Work; propagate every error.
func RequireMFAConsumedPreAuth(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, c Config, original session.PreAuthTransaction, primary identity.CommandID) error {
	if ctx == nil || owner == nil {
		return identity.InvalidInputError{Field: "session_mfa_preauth"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, feature, transition, err := w.FeatureScope(owner)
	spec, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	if err != nil || !ok || !cookie || !code || spec.Binding != b || spec.Operation != feature.Operation || feature.Operation != mfaTOTPCompletionSessionOperation() || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return identity.ForbiddenError{}
	}
	return requireMFAConsumedPreAuth(ctx, w, w.DatabaseTime, b, c, original, primary)
}

// RequireMFAConsumedPreAuthAttempt applies the same original-browser fence in
// the sealed counted-TOTP callback, before any shared-budget charge. Invalid
// browser possession must not become a factor attempt. The owner separately
// authenticates cookie/scope as documented by RequireMFAConsumedPreAuth; this
// reader cannot consume a child, compare a code, charge a budget or issue a
// session. Zero/foreign/returned callback handles fail closed. The original
// journal and flow remain unchanged on both correct and rejected submissions.
func RequireMFAConsumedPreAuthAttempt(ctx context.Context, w kernel.MFATOTPAttemptWork, owner kernel.MFATOTPAttemptContributor, c Config, original session.PreAuthTransaction, primary identity.CommandID) error {
	if ctx == nil || owner == nil {
		return identity.InvalidInputError{Field: "session_mfa_preauth"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	command, err := w.NativeCommand(owner)
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	if !ok || !cookie || !code || spec.Binding != b.Command || spec.Operation != mfaTOTPCompletionSessionOperation() || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return identity.ForbiddenError{}
	}
	return requireMFAConsumedPreAuth(ctx, w, w.DatabaseTime, b.Command, c, original, primary)
}

// Both callers supply sealed native readers and their own database-time method,
// never a consumer callback or independently opened transaction.
func requireMFAConsumedPreAuth[R SessionRows](ctx context.Context, q SessionQueryer[R], databaseTime func(context.Context) (time.Time, error), b identity.CommandBinding, c Config, original session.PreAuthTransaction, primary identity.CommandID) error {
	if _, err := identity.ParseCommandID(string(primary)); err != nil || primary == b.CommandID {
		return identity.ForbiddenError{}
	}
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, original)
	if err != nil {
		return err
	}
	defer stop()
	if s.Binding.Intent.TenantID != b.TenantID || string(s.Binding.ID) != b.AnonymousFlowID || s.Binding.Intent.Action != "identity.magic-link.consume" {
		return identity.ForbiddenError{}
	}
	primaryBytes, _ := base64.RawURLEncoding.DecodeString(string(primary))
	rows, err := q.Query(bounded, `SELECT f.record FROM `+pgx.Identifier{c.Schema}.Sanitize()+`.preauth_transactions f
JOIN identity.commands j ON j.command_id=f.command_id AND j.tenant_id=f.tenant_id AND j.purpose='identity.magic-link.consume'
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
WHERE f.tenant_id=$1 AND f.flow_id=$2 AND f.state='consumed'
AND f.version=$3::numeric AND f.issued_version=$4::numeric AND f.issued_at=$5 AND f.expires_at=$6
AND f.digest_version=$7 AND f.digest=$8 AND f.command_id=$9
AND j.state='committed' AND j.generation=f.generation AND k.fingerprint=f.fingerprint AND NOT k.retired
FOR SHARE OF f,j,k`, string(b.TenantID), string(s.Binding.ID), strconv.FormatUint(s.Version+2, 10), strconv.FormatUint(s.Version, 10), s.Binding.IssuedAt.Format(storedTimeLayout), s.Binding.ExpiresAt.Format(storedTimeLayout), int64(s.Cookie.KeyVersion), s.Cookie.Sum[:], primaryBytes)
	if err != nil {
		return readError(bounded, err)
	}
	var stored []byte
	err = readSessionAdmission(rows, &stored)
	rows.Close()
	if err != nil {
		return admissionError(bounded, err)
	}
	if !bytes.Equal(stored, canonical) {
		return identity.ForbiddenError{}
	}
	now, err := databaseTime(bounded)
	if err != nil {
		return err
	}
	if original.Check(now, s.Binding, s.Cookie) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
