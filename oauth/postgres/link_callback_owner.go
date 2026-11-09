package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Each callback owns one immutable phase. The root coordinator, not this value,
// owns reservation, generation acknowledgment, retained output and recovery.
type rpLinkPhase struct {
	service     *LinkService
	flow        rpCallbackFlow
	original    identity.Command
	input       [32]byte
	declaration kernel.CommandPlan
}

var _ kernel.AccountLinkPreparationContributor = (*rpLinkPhase)(nil)
var _ kernel.AccountLinkCleanupContributor = (*rpLinkPhase)(nil)

func bearerOf(command identity.Command) auth.BearerCredential {
	_, _, bearer, _ := command.AccountLinkPreparationInput()
	return bearer
}

func (*rpLinkPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}
}

func (p *rpLinkPhase) validateOriginal(ctx context.Context, command identity.Command) error {
	if p == nil || p.service == nil || p.input == ([32]byte{}) {
		return identity.InvalidInputError{Field: "oauth_link_owner"}
	}
	digest, err := p.inputDigest(ctx, command)
	if err != nil || digest != p.input {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpLinkPhase) ValidateAccountLinkPreparation(command identity.Command, plan kernel.CommandPlan) error {
	if err := p.validateOriginal(context.Background(), command); err != nil {
		return err
	}
	if !sameRPLinkDeclaration(plan, p.declaration) || plan.Capability != nil || plan.AccountLinkState == nil {
		return identity.InvalidInputError{Field: "oauth_link_declaration"}
	}
	return nil
}

// Digest belongs to the root's canonical admitted snapshot, not native intent.
// Compare every actual declaration field while allowing the coordinator to
// attach its computed digest; never copy that digest into retained authority.
func sameRPLinkDeclaration(a, b kernel.CommandPlan) bool {
	a.Digest, b.Digest = [32]byte{}, [32]byte{}
	return reflect.DeepEqual(a, b)
}

func (p *rpLinkPhase) AdmitAccountLinkPreparation(ctx context.Context, w kernel.AccountLinkPreparationWork, command identity.Command) error {
	if err := p.validateOriginal(ctx, command); err != nil {
		return err
	}
	spec, err := w.Command(p)
	want, _, _, ok := command.AccountLinkPreparationInput()
	if err != nil || !ok || !reflect.DeepEqual(spec, want) || p.flow.erased || !p.service.ownsSessionBearer(spec.Binding.TenantID, bearerOf(command), p.flow.original) {
		return identity.ForbiddenError{}
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.config().Session.Profile, p.flow.original, spec.Binding)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config().Session.Repository, p.flow.original); err != nil {
		return err
	}
	if _, err := mfapg.RequireOAuthLinkPreparationFactors(ctx, w, p, p.flow.binding.Input.FactorVersion); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.requireFresh(now); err != nil {
		return err
	}
	return p.service.requireCallbackTransaction(ctx, w, p.flow, now)
}

// Ordinary already-issued linking is deliberately not an alternate route for
// this callback owner. It cannot bypass acknowledged original-state admission.
func (*rpLinkPhase) PrepareAccountLink(context.Context, identity.Command) (identity.Command, kernel.CommandCounterPlan, kernel.CapabilityPlan, error) {
	return identity.Command{}, kernel.CommandCounterPlan{}, kernel.CapabilityPlan{}, identity.InvalidInputError{Field: "oauth_link_preparation_required"}
}

func (p *rpLinkPhase) ValidateAccountLink(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.declaration.AccountLinkState == nil || plan.Capability == nil {
		return identity.InvalidInputError{Field: "oauth_link_plan"}
	}
	spec, counters, ok := command.AccountLinkCounterCommand()
	original, _, _, valid := p.original.AccountLinkPreparationInput()
	if !ok || !valid || spec.Binding != original.Binding || spec.SessionID != original.SessionID || spec.SessionVersion != original.SessionVersion || !reflect.DeepEqual(counters, original.Counters) || spec.Change.Account.Provider != original.ProviderID || spec.Change.Account.Issuer != p.flow.binding.Provider.Issuer || spec.Change.ExpectedAccountVersion != 0 || spec.Change.Account.Version != 1 || spec.Proof.EnvelopeDigest() != plan.Capability.ProofFingerprint || !spec.Proof.Payload().ExpiresAt.Equal(plan.Capability.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	plan.Capability = nil
	if !sameRPLinkDeclaration(plan, p.declaration) {
		return identity.InvalidInputError{Field: "oauth_link_plan"}
	}
	return nil
}

func (p *rpLinkPhase) requireFresh(now time.Time) error {
	if p.flow.erased || now.Before(p.flow.loadedAt) || !now.Before(p.flow.loadedAt.Add(20*time.Second)) || now.Before(p.flow.binding.IssuedAt) || !now.Before(p.flow.binding.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	life, err := p.flow.original.Lifetime(now)
	if err != nil || !life.Fresh {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpLinkPhase) restoredWork(ctx context.Context, w kernel.AccountLinkWork) (rpLinkedOutput, identity.AccountLinkCommand, bool, error) {
	spec, terminal, err := w.Command(p)
	if err != nil {
		return rpLinkedOutput{}, spec, terminal, err
	}
	original, wire, generation, err := w.Preparation(p)
	if err != nil {
		return rpLinkedOutput{}, spec, terminal, err
	}
	defer clear(wire)
	if err := p.validateOriginal(ctx, original); err != nil {
		return rpLinkedOutput{}, spec, terminal, err
	}
	out, command, _, err := p.restoreLinkedOutput(ctx, original, generation, wire)
	restored, _, ok := command.AccountLinkCounterCommand()
	if err != nil || !ok || restored.Binding != spec.Binding || restored.Proof.EnvelopeDigest() != spec.Proof.EnvelopeDigest() || !reflect.DeepEqual(restored.Change, spec.Change) || restored.SessionID != spec.SessionID || restored.SessionVersion != spec.SessionVersion {
		return rpLinkedOutput{}, spec, terminal, identity.ForbiddenError{}
	}
	return out, spec, terminal, nil
}

func (p *rpLinkPhase) CheckAccountLink(ctx context.Context, w kernel.AccountLinkWork) error {
	out, spec, _, err := p.restoredWork(ctx, w)
	if err != nil {
		return err
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.config().Session.Profile, p.flow.original, spec.Binding)
	if err != nil {
		return err
	}
	// Only the original epoch or this exact Work's persisted successor may pass.
	// Never adopt the epoch from an unrelated concurrent credential mutation.
	if spec.Change.ExpectedCredentialVersion != credential.CredentialAuthorityVersion {
		return identity.ForbiddenError{}
	}
	version, err := w.CredentialAuthorityVersion(p)
	if err != nil {
		return err
	}
	credential.CredentialAuthorityVersion = version
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config().Session.Repository, p.flow.original); err != nil {
		return err
	}
	if _, err := mfapg.RequireOAuthLinkFactors(ctx, w, p, p.flow.binding.Input.FactorVersion); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(out.ReadBegan) || !now.Before(out.ReadBegan.Add(20*time.Second)) || !now.Before(out.SourceExpiresAt) || now.Before(spec.Proof.Payload().IssuedAt) || !now.Before(spec.Proof.Payload().ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if err := p.requireFresh(now); err != nil {
		return err
	}
	return p.service.requireCallbackTransaction(ctx, w, p.flow, now)
}

func (p *rpLinkPhase) PersistAccountLink(ctx context.Context, w kernel.AccountLinkWork) error {
	_, _, final, err := p.restoredWork(ctx, w)
	if err != nil {
		return err
	}
	if final {
		return identity.ForbiddenError{}
	}
	// Kernel account insertion follows this phase. Token-vault FK insertion
	// belongs in Finalize, still in this same transaction after that insertion.
	return ctx.Err()
}

func (p *rpLinkPhase) FinalizeAccountLink(ctx context.Context, w kernel.AccountLinkWork) error {
	out, _, final, err := p.restoredWork(ctx, w)
	if err != nil {
		return err
	}
	if !final {
		return identity.ForbiddenError{}
	}
	if err := p.service.persistProviderTokens(ctx, w, p, out.Tokens); err != nil {
		return err
	}
	return p.eraseExchangeSecrets(ctx, w)
}

// CleanupAccountLink is invoked only after the root proved rollback, in the
// same fenced terminal transaction as proof release and the failure receipt.
// It deliberately does not demand live signin authority: revoked or expired
// authority must not prevent erasing this exact failed transaction's secrets.
func (p *rpLinkPhase) CleanupAccountLink(ctx context.Context, w kernel.AccountLinkCleanupWork) error {
	binding, state, err := w.Scope(p)
	if err != nil {
		return err
	}
	if !p.matchesRetainedLinkScope(binding, state) {
		return identity.ForbiddenError{}
	}
	return p.eraseExchangeSecrets(ctx, w)
}

func (p *rpLinkPhase) eraseExchangeSecrets(ctx context.Context, w interface {
	Exec(context.Context, string, ...any) (int64, error)
}) error {
	args, err := p.retainedTransactionArguments()
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE `+rpQuotedSchema(p.service.config().Schema)+`.transactions
 SET pkce_ciphertext=NULL,state_proof_ciphertext=NULL,secrets_erased_at=clock_timestamp(),version=2
 `+retainedLinkTransactionPredicate, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpLinkPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, state, _, err := w.AccountLinkScope(p)
	if err != nil || !p.matchesRetainedLinkScope(b, state) {
		return kernel.RecoveryUnknown, identity.InvalidInputError{Field: "oauth_link_recovery"}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT user_id,account_id,origin_command_id FROM `+rpQuotedSchema(p.service.config().Schema)+`.token_sets WHERE tenant_id=$1 AND origin_operation=$2 AND origin_command_id=$3`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	// The attached final plan acknowledges provider output and final issuance,
	// not account commitment. Missing vault output is negative local evidence
	// only with that attachment and this exact intact original RP transaction.
	// The coordinator excludes unattached/ambiguous exchanges before invoking us.
	if !rows.Next() {
		failure := rows.Err()
		rows.Close()
		if failure != nil {
			return kernel.RecoveryUnknown, failure
		}
		args, err := p.retainedTransactionArguments()
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		original, err := w.Query(ctx, `SELECT transaction_id FROM `+rpQuotedSchema(p.service.config().Schema)+`.transactions `+retainedLinkTransactionPredicate, args...)
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		defer original.Close()
		var transaction string
		if !original.Next() {
			return kernel.RecoveryUnknown, original.Err()
		}
		if original.Scan(&transaction) != nil || transaction != p.flow.binding.Input.binding().RecordID || original.Next() || original.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var user, account string
	var origin []byte
	if rows.Scan(&user, &account, &origin) != nil || rows.Next() || rows.Err() != nil || user != string(b.UserID) || account != b.RecordID || !bytes.Equal(origin, id) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

func (p *rpLinkPhase) matchesRetainedLinkScope(b identity.CommandBinding, state kernel.CapabilityPlan) bool {
	if p == nil || p.service == nil || p.service.config == nil || p.flow.erased {
		return false
	}
	expected, err := callbackSpecification(p.flow)
	return err == nil && expected.Binding == b && state == p.flow.statePlan
}

// Historical erasure/recovery validates every original RP correlation, not
// current signin freshness. The authenticated flow and retained state plan are
// metadata only; neither a clock change nor a new browser supplies authority.
const retainedLinkTransactionPredicate = `WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND user_id=$4
 AND operation='identity.account.link-start' AND preauth_id IS NULL
 AND session_id=$5 AND session_version=$6::numeric AND provider_id=$7
 AND configuration_version=$8::numeric AND issuer=$9 AND client_id=$10
 AND redirect_uri=$11 AND response_mode='query' AND state_key_version=$12
 AND state_digest=$13 AND pkce_key_version=$14 AND pkce_commitment=$15
 AND issued_at=$16 AND expires_at=$17 AND version=1 AND secrets_erased_at IS NULL
 AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL`

func (p *rpLinkPhase) retainedTransactionArguments() ([]any, error) {
	b, profile := p.flow.binding.Input.binding(), p.flow.binding.Provider
	original, err := p.flow.original.Bindings()
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	return []any{string(b.TenantID), b.RecordID, id, string(b.UserID), original.SessionID, original.Version, profile.ID, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI, p.flow.binding.StateKeyVersion, p.flow.binding.StateDigest[:], p.flow.binding.PKCEKeyVersion, p.flow.binding.PKCECommitment[:], p.flow.binding.IssuedAt, p.flow.binding.ExpiresAt}, nil
}
