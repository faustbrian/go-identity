package postgres

import (
	"context"
	"encoding/base64"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// FinalAuthenticationConfig selects one trusted final-signin authority and its
// stable durable proof namespace. Neither may come from request input. Namespace
// is bounded to 256 bytes and must remain unchanged while use tombstones exist.
// Authority owns concurrent pure proof validation; this configuration performs
// no authentication workflow, network IO, current-state refresh or token issuance.
type FinalAuthenticationConfig struct {
	Authority *authentication.AuthorityAuthenticator
	Namespace string
}

// Pending-command reconciliation must not call the kernel effect-free once it
// owns committed proof-use tombstones. Positive/inconsistent evidence remains
// unknown; only absence can participate in unanimous noncommit recovery.
func recoverSignInProofUse(ctx context.Context, recovery RecoveryWork) (RecoveryStatus, error) {
	b, err := recovery.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := recovery.Query(ctx, "SELECT EXISTS(SELECT 1 FROM identity.signin_proof_uses WHERE command_id=$1)", id)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if err := rows.Scan(&exists); err != nil {
		return RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

// AuthenticatedFeatureContributor owns the exhaustive native mapping and the
// current eligibility of a final-authentication operation. Validate is pure,
// bounded and compares every original proof/credential field with native command
// intent. Check runs under the original Work before apply and again before
// terminalization (final=true); it must lock/check every applicable original
// authority, preserve freshness, and check original native session lifetime.
// It must not mutate state, mint tokens, consume proof, retain Work, perform
// network IO or close transactions. Errors/panics/unfinished rows poison Work.
// Only the exact registered feature owner is invoked. Current support is the
// authenticated session-issue profile; anonymous issuance is a separate profile.
type AuthenticatedFeatureContributor interface {
	FeatureExecutionContributor
	ValidateAuthenticatedFeature(identity.Command, authentication.AuthenticatedProofSpec) error
	CheckAuthenticatedFeature(context.Context, Work, identity.Command, authentication.AuthenticatedProofSpec, bool) error
}

type authenticatedCommand struct {
	command   identity.Command
	proof     authentication.AuthenticatedProof
	namespace string
}

func authenticatedOperation(b identity.CommandBinding) bool {
	return b.OperationID == "identity.session.issue"
}

// PrepareAuthenticatedCommandPlan freezes the exact original opaque proof into
// the existing keyed command intent and plan. It validates provenance against
// configured authority and the registered native mapping, not current authority
// or one-time use. No IO, reservation or credential delivery occurs. The same
// command and proof must accompany ReserveAuthenticatedCommand; an ordinary
// PrepareCommandPlan/ReserveCommand cannot substitute structural metadata.
func (c *Coordinator) PrepareAuthenticatedCommandPlan(b identity.CommandBinding, command identity.Command, proof authentication.AuthenticatedProof, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, _, err := c.prepareAuthenticated(b, command, proof, p)
	return snapshot, err
}

func (c *Coordinator) prepareAuthenticated(b identity.CommandBinding, command identity.Command, proof authentication.AuthenticatedProof, p CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, *authenticatedCommand, error) {
	fail := func() (claimRequest, CommandPlan, *admittedKernelPlan, *authenticatedCommand, error) {
		return claimRequest{}, CommandPlan{}, nil, nil, invalidPlan()
	}
	if c == nil || c.finalAuthentication == nil || !authenticatedOperation(b) {
		return fail()
	}
	q, snapshot, admitted, err := c.prepare(b, command, p)
	if err != nil || admitted == nil || admitted.feature == nil {
		return fail()
	}
	original := &authenticatedCommand{command: command, proof: proof, namespace: c.finalAuthentication.Namespace}
	metadata := proof.Bindings()
	if err := c.validateOriginalAuthentication(b, original, metadata.Proof.IssuedAt); err != nil {
		return fail()
	}
	entry, err := c.registry.selectFeatureOperation(*admitted.feature)
	if err != nil {
		return fail()
	}
	participant, ok := entry.contributor.(AuthenticatedFeatureContributor)
	if !ok || validateAuthenticatedFeature(participant, command, metadata) != nil {
		return fail()
	}
	q, err = bindAuthenticationClaim(q, original, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) {
		return fail()
	}
	fingerprint := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	snapshot.Digest, err = FeaturePlanDigest(b, fingerprint, snapshot)
	if err != nil {
		return fail()
	}
	admitted, err = c.registry.admitFeaturePlan(b, fingerprint, snapshot)
	if err != nil {
		return fail()
	}
	return q, snapshot, admitted, original, nil
}

// ReserveAuthenticatedCommand reserves only the original authenticated command
// through the existing global claim and scoped journal. Exact plan/proof intent
// is required; changed original metadata or namespace conflicts, including after
// fingerprint-key rotation. Primary time rechecks exclusive proof expiry after
// locks. Reservation consumes no proof and creates no session. Returned terminal
// replay is historical metadata only, never a bearer or refreshed authentication.
func (c *Coordinator) ReserveAuthenticatedCommand(ctx context.Context, b identity.CommandBinding, command identity.Command, proof authentication.AuthenticatedProof, p CommandPlan) (Reservation, identity.CommandResult, error) {
	if ctx == nil {
		return Reservation{}, identity.CommandResult{}, coordinatorError()
	}
	q, snapshot, admitted, original, err := c.prepareAuthenticated(b, command, proof, p)
	if err != nil {
		return Reservation{}, identity.CommandResult{}, err
	}
	if snapshot.Digest != p.Digest {
		return Reservation{}, identity.CommandResult{}, invalidPlan()
	}
	return c.reservePreparedCommand(ctx, b, command, q, snapshot, admitted, original)
}

func (c *Coordinator) validateOriginalAuthentication(b identity.CommandBinding, original *authenticatedCommand, now time.Time) error {
	if c == nil || c.finalAuthentication == nil || original == nil || original.namespace != c.finalAuthentication.Namespace || !authenticatedOperation(b) {
		return invalidPlan()
	}
	metadata := original.proof.Bindings()
	if metadata.ProofVersion == 0 || metadata.CredentialVersion == 0 || metadata.CredentialID == "" || metadata.Proof.IssuedAt.UTC().Year() < 1 || metadata.Proof.IssuedAt.UTC().Year() > 9999 || metadata.Proof.ExpiresAt.UTC().Year() < 1 || metadata.Proof.ExpiresAt.UTC().Year() > 9999 {
		return invalidPlan()
	}
	if err := c.finalAuthentication.Authority.ValidateAuthenticatedProof(original.proof, authentication.ProofUse{Tenant: string(b.TenantID), Subject: string(b.UserID), Purpose: "session-issue", Audience: metadata.Proof.Audience, Now: now}); err != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func validateAuthenticatedFeature(p AuthenticatedFeatureContributor, command identity.Command, metadata authentication.AuthenticatedProofSpec) (err error) {
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	if p.ValidateAuthenticatedFeature(command, metadata) != nil {
		return invalidPlan()
	}
	return nil
}

func bindAuthenticationClaim(q claimRequest, original *authenticatedCommand, key [32]byte) (claimRequest, error) {
	s := original.proof.Bindings()
	encoded := cborMap(map[string][]byte{
		"namespace": cborText(original.namespace), "id": cborText(string(s.Proof.ID)), "proof_version": cborUint(s.ProofVersion),
		"credential_id": cborText(s.CredentialID), "credential_version": cborUint(s.CredentialVersion),
		"tenant": cborText(s.Proof.Tenant), "subject": cborText(s.Proof.Subject), "purpose": cborText(string(s.Proof.Purpose)), "audience": cborText(s.Proof.Audience),
		"method": cborText(s.Proof.Method), "assurance": cborUint(uint64(s.Proof.Assurance)),
		"issued": cborText(s.Proof.IssuedAt.UTC().Format(signInExpiryLayout)), "expires": cborText(s.Proof.ExpiresAt.UTC().Format(signInExpiryLayout)),
	})
	digest, err := commandSecret(key, "final-authentication.original-v1", encoded, 4096)
	if err != nil {
		return claimRequest{}, err
	}
	q.canonical = cborMap(map[string][]byte{"profile": cborText("identity-authenticated-command-v1"), "command": cborBytes(q.canonical), "authentication": cborBytes(digest)})
	q.authentication = original
	return q, nil
}

func (c *Coordinator) checkAuthenticatedCommand(ctx context.Context, w Work, final bool) (err error) {
	original := w.state.execution.reservation.authentication
	if original == nil {
		return nil
	}
	fail := func(err error) error { return w.fail(w.state.ctx, err) }
	if ctx == nil {
		return fail(invalidWork())
	}
	if err := w.usable(); err != nil {
		return err
	}
	entry, err := c.registry.selectFeatureOperation(*w.state.feature)
	if err != nil {
		return fail(invalidPlan())
	}
	participant, ok := entry.contributor.(AuthenticatedFeatureContributor)
	if !ok {
		return fail(invalidPlan())
	}
	defer func() {
		if recover() != nil {
			err = fail(identity.UnavailableError{})
		}
	}()
	w.state.featureInvocation = participant
	defer func() { w.state.featureInvocation = nil }()
	if err := participant.CheckAuthenticatedFeature(ctx, w, original.command, original.proof.Bindings(), final); err != nil {
		return fail(err)
	}
	if err := w.usable(); err != nil {
		return err
	}
	if w.state.rows != nil {
		return fail(invalidWork())
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return fail(err)
	}
	if err := c.validateOriginalAuthentication(w.state.binding, original, now); err != nil {
		return fail(err)
	}
	if !final {
		s := original.proof.Bindings()
		if err := w.stageSignInProofUse(ctx, original.namespace, string(s.Proof.ID), s.ProofVersion, s.Proof.ExpiresAt); err != nil {
			return fail(err)
		}
		w.state.authenticationChecked = true
	} else if !w.state.authenticationChecked {
		return fail(invalidWork())
	}
	return nil
}
