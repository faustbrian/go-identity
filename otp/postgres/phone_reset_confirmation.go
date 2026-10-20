package postgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func (p PreparedPhonePasswordResetSend) confirmationState() (*preparedPhonePasswordResetSend, otp.ChallengeSpec, error) {
	s := p.state()
	if s == nil || s.phase == nil || s.phase.store == nil || s.phase.store.codec == nil || s.phase.store.preauth == nil || s.custody.recipient == nil {
		return nil, otp.ChallengeSpec{}, ErrInvalidCommand
	}
	source, ok := s.root.Feature()
	issued, err := s.custody.challenge.Bindings()
	if !ok || source.Operation != phoneResetSendOperation() || source.Binding != s.input.binding || err != nil || s.custody.authority != s.input.record.authority {
		return nil, otp.ChallengeSpec{}, ErrInvalidCommand
	}
	input := PhonePasswordResetSendInput{read: func() phonePasswordResetSendInput { return s.input }}
	if _, err := input.Fields(); err != nil {
		return nil, otp.ChallengeSpec{}, ErrInvalidCommand
	}
	return s, issued, nil
}

// Fields returns an owned copy of the exact original encrypted factor's
// selection triplet for completion fingerprinting. It is not current factor
// authority, a verification result or permission to reset a password. Zero
// denies; no IO, cryptography or freshness renewal occurs.
func (p PreparedPhonePasswordResetSend) Fields() ([]identity.FeatureField, error) {
	s, _, err := p.confirmationState()
	if err != nil {
		return nil, err
	}
	return (PhonePasswordResetSendInput{read: func() phonePasswordResetSendInput { return s.input }}).Fields()
}

// OriginalFactor borrows the exact original encrypted MFA snapshot authenticated
// by Restore. It does not read current factor state or decrypt the secret. The
// native MFA owner must fence and verify it in the protected completion Work;
// callers must not interpret its metadata as a successful factor verdict.
func (p PreparedPhonePasswordResetSend) OriginalFactor() (mfapg.TOTPFactorSnapshot, error) {
	s, _, err := p.confirmationState()
	if err != nil {
		return mfapg.TOTPFactorSnapshot{}, err
	}
	return s.input.factor, nil
}

// Timeline returns the authenticated original SMS's absolute issued/expiry
// instants, never a new observation or renewed validity. Zero denies without
// times; no resources, clock, IO or live admission are owned.
func (p PreparedPhonePasswordResetSend) Timeline() (issuedAt, expiresAt time.Time, err error) {
	_, issued, err := p.confirmationState()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return issued.IssuedAt, issued.ExpiresAt, nil
}

// NewPhoneRecoveryContributor selects a fresh invocation-local consuming owner
// from this original send's actual immutable store configuration. Register its
// stable pointer before generation, then call its PreparePhoneRecovery with the
// final retained generated joint command, original factor and native verifier.
// It grants no reset permission and owns no transaction or background resource.
// Never share it between requests. Issuance and other invocations stay unchanged.
func (p PreparedPhonePasswordResetSend) NewPhoneRecoveryContributor() (*Contributor, error) {
	s, _, err := p.confirmationState()
	if err != nil {
		return nil, err
	}
	store := *s.phase.store
	store.send = nil
	store.phoneRecovery = &phoneRecoveryProfile{}
	return &store, nil
}

// NewPhoneRecoveryContributor creates the same invocation-local native consuming
// owner without requiring live factor or code custody. This permits authorized
// code-free receipt recovery after the original browser/factor has expired or
// been consumed. It grants no execution authority: consuming calls must still
// PreparePhoneRecovery from the authenticated original send and exact command.
// No IO, decryption, callbacks, transaction or background resources are created.
func (s *PhonePasswordResetIssuer) NewPhoneRecoveryContributor() (*Contributor, error) {
	native := s.state()
	if native == nil || native.store == nil {
		return nil, ErrInvalidCommand
	}
	store := *native.store
	store.send = nil
	store.phoneRecovery = &phoneRecoveryProfile{}
	return &store, nil
}

func (p PreparedPhonePasswordResetSend) confirmationInput(ctx context.Context, input identity.Command) (*preparedPhonePasswordResetSend, otp.ChallengeSpec, identity.FeatureCommandSpec, error) {
	bad := func(err error) (*preparedPhonePasswordResetSend, otp.ChallengeSpec, identity.FeatureCommandSpec, error) {
		return nil, otp.ChallengeSpec{}, identity.FeatureCommandSpec{}, err
	}
	if ctx == nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	s, issued, err := p.confirmationState()
	if err != nil {
		return bad(err)
	}
	spec, ok := input.PhonePasswordResetInputFeature()
	_, _, _, _, custody := input.PhonePasswordResetInputCustody()
	cookie, present := input.PhonePasswordResetPreAuthCookie()
	b, source := spec.Binding, s.input.binding
	if !ok || !custody || !present || b.ValidateFor(spec.Operation) != nil || b.CommandID == source.CommandID ||
		b.TenantID != source.TenantID || b.UserID != source.UserID || b.ActorID != source.ActorID || b.ActorKind != source.ActorKind ||
		b.PolicyID != source.PolicyID || b.PolicyVersion != source.PolicyVersion || b.LinkMode != source.LinkMode ||
		b.RecordID != string(s.custody.authority.Credential.ID) {
		return bad(ErrInvalidCommand)
	}
	want, err := p.Fields()
	if err != nil {
		return bad(err)
	}
	var seen int
	for _, field := range spec.Fields {
		if otpField(field.Name) {
			return bad(ErrInvalidCommand)
		}
		if !strings.HasPrefix(field.Name, "phone.reset.factor-") {
			continue
		}
		matched := false
		for _, expected := range want {
			if reflect.DeepEqual(field, expected) {
				matched = true
				seen++
				break
			}
		}
		if !matched {
			return bad(ErrInvalidCommand)
		}
	}
	if seen != len(want) {
		return bad(ErrInvalidCommand)
	}
	continuation, err := issued.Continuation.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	original, bound := continuation.Authorization.PreAuthTransaction()
	actual, err := original.Bindings()
	retained, retainedErr := s.flow.preauth.Bindings()
	if !bound || err != nil || retainedErr != nil || actual != retained {
		return bad(ErrInvalidCommand)
	}
	if _, err := authenticateOriginalPreAuth(ctx, s.phase.store.preauth, original, cookie); err != nil {
		return bad(err)
	}
	return s, issued, spec, nil
}

// PrepareConfirmation creates one new logical consuming SMS attempt from the
// exact original challenge/continuation/authority authenticated by Restore, not
// from grant scalars or newer directory/factor rows. The native owner must first
// authenticate the committed request's provenance and current phone/password/
// factor/recovery policy. The joint input must carry the original factor triplet,
// tenant/user/actor/policy, password credential target and original browser cookie.
//
// The borrowed pool supplies only the original challenge's actual current
// version; no transaction, code comparison, issuance, consumption or permission
// is created. All password/capability/SMS/TOTP/cookie custody stays borrowed in
// the returned joint input. Native completion must use distinct actual risk,
// HIBP and all protected effects in its sole Work. Preserve the mapped command
// and plan unchanged for retries; ambiguous completion uses original recovery,
// never this new-attempt API. Earlier caller deadlines win; failures return zero
// outputs and redacted errors. This method owns no background resource.
func (p PreparedPhonePasswordResetSend) PrepareConfirmation(ctx context.Context, pool *database.Pool, input identity.Command, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func(err error) (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	s, issued, spec, err := p.confirmationInput(ctx, input)
	if err != nil {
		return bad(err)
	}
	if pool == nil || pool.Raw() == nil {
		return bad(ErrInvalidCommand)
	}
	store := s.phase.store
	issuer, retained := store.codec.issuers[keyVersion]
	if !retained {
		return bad(ErrInvalidCommand)
	}
	ctx, stop := context.WithTimeout(ctx, store.codec.maximumDuration)
	defer stop()
	scope, err := issued.Continuation.DigestScope()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	digest, err := store.codec.verifier.ScopeDigest(scope, issued.Digest.KeyVersion)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	id, ok := ownershipID(string(s.input.binding.CommandID))
	if !ok {
		return bad(ErrInvalidCommand)
	}
	var encoded string
	err = pool.Raw().QueryRow(ctx, `SELECT e.version::text FROM `+pgx.Identifier{store.schema}.Sanitize()+`.challenges e
WHERE e.tenant_id=$1 AND e.challenge_id=$2 AND e.digest_key_version=$3 AND e.scope_digest=$4
AND e.issue_command_id=$5 AND e.issue_command_purpose=$6 AND e.state='issued'
AND e.issued_at=$7 AND e.expires_at=$8 AND e.expires_at>clock_timestamp()
AND EXISTS(SELECT 1 FROM identity.commands j WHERE j.command_id=e.issue_command_id AND j.tenant_id=e.tenant_id
AND j.purpose=e.issue_command_purpose AND j.state='committed' AND j.terminal_class='committed')`,
		string(s.input.binding.TenantID), string(s.input.binding.CommandID), int64(issued.Digest.KeyVersion), digest.Value[:], id,
		s.input.binding.OperationID, issued.IssuedAt, issued.ExpiresAt).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return bad(ErrInvalidCommand)
	}
	if err != nil {
		return bad(custodyFailure(ctx))
	}
	version, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != encoded {
		return bad(ErrUnavailable)
	}
	_, _, sms, _, _ := input.PhonePasswordResetInputCustody()
	attempt, err := issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, issued.Continuation, otp.AttemptModeConsume, version, sms)
	if err != nil {
		return bad(err)
	}
	return store.codec.MapPhonePasswordResetWithAuthority(ctx, attempt, issued.Digest.KeyVersion, input, s.custody.authority)
}
