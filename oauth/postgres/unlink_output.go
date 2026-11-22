package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type rpUnlinkOutput struct {
	Version    uint8
	AdmittedAt time.Time
	Deadline   time.Time
	Checkpoint []byte
	Issuance   rpStoredIssuancePlan
}

const unlinkOutputLimit = 1 << 20

func (s *LinkService) unlinkOutputAAD(original identity.Command, generation uint64) (envelope.Context, error) {
	spec, bearer, ok := original.AccountUnlinkPreparationInput()
	if s == nil || s.config == nil || !ok || spec.RevokeProvider || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	c := s.config()
	if c.IntentKey == ([32]byte{}) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	spec.Primary.Proof.IssuedAt = spec.Primary.Proof.IssuedAt.UTC()
	spec.Primary.Proof.ExpiresAt = spec.Primary.Proof.ExpiresAt.UTC()
	transport := []byte(bearer.Token())
	defer clear(transport)
	frame, err := json.Marshal(struct {
		Schema, ConfigurationID string
		Generation              uint64
		Binding                 rpStoredBinding
		Change                  identity.AccountUnlinkChange
		SessionID               string
		SessionVersion          uint64
		FactorAuthorityVersion  uint64
		CSRFCommitment          [32]byte
		Counters                rpStoredLinkCounters
		Primary                 auth.ReauthenticationProof
	}{
		c.Schema, c.ConfigurationID, generation, rpStoredBinding(spec.Binding), spec.Change, spec.SessionID, spec.SessionVersion,
		spec.FactorAuthorityVersion, spec.CSRFCommitment, rpStoredLinkCounters(spec.Counters), spec.Primary,
	})
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	defer clear(frame)
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write([]byte("identity-oauth-root-unlink-output-v1\x00"))
	_, _ = mac.Write(frame)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(transport)
	return envelope.NewContext(map[string]string{
		"profile": "identity-oauth-root-unlink-output-v1",
		"binding": base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
}

func (s *LinkService) unlinkPayload(original identity.Command, id string, admitted, deadline time.Time) (capability.Payload, error) {
	spec, _, ok := original.AccountUnlinkPreparationInput()
	if !ok || !rpUTCTime(admitted) || !rpUTCTime(deadline) || deadline.After(spec.Primary.Proof.ExpiresAt) {
		return capability.Payload{}, identity.ForbiddenError{}
	}
	issued := admitted.Truncate(time.Second)
	expires := admitted.Add(20 * time.Second)
	if deadline.Before(expires) {
		expires = deadline
	}
	expires = expires.Truncate(time.Second)
	if !expires.After(admitted) {
		return capability.Payload{}, identity.ForbiddenError{}
	}
	c := s.config()
	return identity.BuildAccountUnlinkProofPayload(identity.AccountUnlinkProofSpec{
		Preparation: original, Issuer: c.Capability.Crypto.Issuer, Audience: c.Capability.Audience,
		ID: id, IssuedAt: issued, ExpiresAt: expires,
	})
}

// This phase runs only after the kernel acknowledged the original preparation.
// The password admission supplies its original deadline; the caller does not
// supply times. Neither the bearer nor the upstream password proof is stored
// in the retained output. The kernel owns acknowledgement and persistence.
func (s *LinkService) sealUnlinkOutput(ctx context.Context, original identity.Command, generation uint64, admitted, deadline time.Time) ([]byte, error) {
	aad, err := s.unlinkOutputAAD(original, generation)
	if err != nil {
		return nil, err
	}
	payload, err := s.unlinkPayload(original, "unsigned-unlink", admitted, deadline)
	if err != nil {
		return nil, err
	}
	payload.ID = "" // The issuer allocates the actual cryptographic grant identity.
	spec, _, _ := original.AccountUnlinkPreparationInput()
	prepared, err := s.issuer.Prepare(ctx, spec.Binding, []capability.Payload{payload})
	if err != nil {
		return nil, err
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.ForbiddenError{}
	}
	checkpoint, err := s.checkpoint.CheckpointPreparation(ctx, prepared, generation, func(context.Context, uint16, []byte) error { return nil })
	if err != nil {
		return nil, err
	}
	defer clear(checkpoint)
	plain, err := json.Marshal(rpUnlinkOutput{
		Version: 1, AdmittedAt: admitted, Deadline: deadline, Checkpoint: checkpoint,
		Issuance: rpStoredIssuancePlan{Contributor: plan.Contributor, Grants: []rpStoredGrant{rpStoredGrant(plan.Grants[0])}},
	})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	return s.sealRP(ctx, aad, plain)
}

// Restoration authenticates the exact original generated output. It never
// signs again, exposes a bearer or substitutes the retry's clock and deadline.
// The original issuer still rejects expired executable grants.
func (s *LinkService) restoreUnlinkOutput(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CapabilityIssuancePlan, error) {
	fail := func(err error) (identity.Command, kernel.CapabilityIssuancePlan, error) {
		return identity.Command{}, kernel.CapabilityIssuancePlan{}, err
	}
	aad, err := s.unlinkOutputAAD(original, generation)
	if err != nil {
		return fail(err)
	}
	plain, err := s.openRP(ctx, aad, wire, unlinkOutputLimit)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	var out rpUnlinkOutput
	defer func() { clear(out.Checkpoint) }()
	if decodeRPOutput(plain, &out) != nil || out.Version != 1 || len(out.Checkpoint) == 0 || len(out.Issuance.Grants) != 1 {
		return fail(identity.ForbiddenError{})
	}
	plan := out.Issuance.native()
	spec, _, _ := original.AccountUnlinkPreparationInput()
	prepared, err := s.checkpoint.RestorePreparation(ctx, spec.Binding, generation, plan, out.Checkpoint)
	if err != nil {
		return fail(err)
	}
	grants, err := prepared.Grants()
	if err != nil || len(grants) != 1 {
		return fail(identity.ForbiddenError{})
	}
	payload := grants[0].Payload()
	expected, err := s.unlinkPayload(original, payload.ID, out.AdmittedAt, out.Deadline)
	if err != nil || !reflect.DeepEqual(payload, expected) {
		return fail(identity.ForbiddenError{})
	}
	base, err := identity.NewAccountUnlinkCommand(identity.AccountUnlinkCommand{
		Binding: spec.Binding, Change: spec.Change, Proof: grants[0],
		SessionID: spec.SessionID, SessionVersion: spec.SessionVersion,
	})
	if err != nil {
		return fail(err)
	}
	command, err := identity.NewAccountUnlinkCounterCommand(base, spec.Counters)
	if err != nil {
		return fail(err)
	}
	return command, plan, nil
}
