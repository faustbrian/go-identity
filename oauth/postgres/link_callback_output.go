package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type rpStoredLinkChange identity.AccountLinkChange
type rpStoredLinkCounters identity.AccountLinkCounterContext

// Provider tokens and the issuer's existing checkpoint are already encrypted.
// The outer envelope binds them to the original code/browser input and journal
// generation. It retains no verifier, callback-state proof or second journal.
type rpLinkedOutput struct {
	Schema                     uint8
	Generation                 uint64
	Change                     rpStoredLinkChange
	Tokens                     rpPreparedTokenSet
	Checkpoint                 []byte
	Issuance                   rpStoredIssuancePlan
	ReadBegan, SourceExpiresAt time.Time
}

func (p *rpLinkPhase) inputDigest(ctx context.Context, original identity.Command) ([32]byte, error) {
	if p == nil || p.service == nil || p.service.config == nil || ctx == nil {
		return [32]byte{}, identity.InvalidInputError{Field: "oauth_link_input"}
	}
	spec, callback, bearer, ok := original.AccountLinkPreparationInput()
	if !ok {
		return [32]byte{}, identity.InvalidInputError{Field: "oauth_link_input"}
	}
	frame, err := json.Marshal(struct {
		Binding         rpStoredBinding
		Provider, Flow  string
		ProviderVersion uint64
		FlowFingerprint [32]byte
		Session         string
		SessionVersion  uint64
		Counters        rpStoredLinkCounters
	}{rpStoredBinding(spec.Binding), spec.ProviderID, spec.FlowID, spec.ProviderConfigVersion, spec.FlowFingerprint, spec.SessionID, spec.SessionVersion, rpStoredLinkCounters(spec.Counters)})
	if err != nil {
		return [32]byte{}, identity.ForbiddenError{}
	}
	defer clear(frame)
	key := p.service.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-oauth-root-link-input-v1\x00"))
	field := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(value)
	}
	field(frame)
	if err := callback.Use(ctx, func(_ context.Context, code, state []byte) error {
		field(code)
		field(state)
		return nil
	}); err != nil {
		return [32]byte{}, err
	}
	transport := []byte(bearer.Token())
	defer clear(transport)
	field(transport)
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest, nil
}

func (p *rpLinkPhase) outputAAD(ctx context.Context, original identity.Command, generation uint64) (envelope.Context, error) {
	digest, err := p.inputDigest(ctx, original)
	if err != nil || generation == 0 {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_link_output"}
	}
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-root-link-output-v1", "input": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
}

func (p *rpLinkPhase) sealLinkedOutput(ctx context.Context, original identity.Command, generation uint64, spec identity.AccountLinkCommand, tokens rpPreparedTokenSet, readBegan, sourceExpires time.Time) ([]byte, error) {
	aad, err := p.outputAAD(ctx, original, generation)
	if err != nil {
		return nil, err
	}
	s := p.service
	issued, expires, err := p.linkProofLifetime(readBegan, sourceExpires)
	if err != nil {
		return nil, err
	}
	payload, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: spec, Issuer: s.config().Capability.Crypto.Issuer, Audience: s.config().Capability.Audience, ID: "unsigned-link-plan", IssuedAt: issued, ExpiresAt: expires})
	if err != nil {
		return nil, err
	}
	// The root helper needs a structural ID; only the real issuer allocates the
	// cryptographic grant ID. No locally constructed Grant can stand in for it.
	payload.ID = ""
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
	out := rpLinkedOutput{Schema: 1, Generation: generation, Change: rpStoredLinkChange(spec.Change), Tokens: tokens, Checkpoint: checkpoint, Issuance: rpStoredIssuancePlan{Contributor: plan.Contributor, Grants: []rpStoredGrant{rpStoredGrant(plan.Grants[0])}}, ReadBegan: readBegan, SourceExpiresAt: sourceExpires}
	plain, err := json.Marshal(out)
	if err != nil || len(plain) > 768<<10 {
		return nil, identity.InvalidInputError{Field: "oauth_link_output"}
	}
	defer clear(plain)
	return s.sealRP(ctx, aad, plain)
}

func (p *rpLinkPhase) linkProofLifetime(readBegan, sourceExpires time.Time) (time.Time, time.Time, error) {
	if !rpUTCTime(readBegan) || !rpUTCTime(sourceExpires) || readBegan.Before(p.flow.binding.IssuedAt) || !sourceExpires.After(readBegan) {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	issued, expires := readBegan.Truncate(time.Second), readBegan.Add(20*time.Second)
	for _, deadline := range []time.Time{sourceExpires, p.flow.binding.ExpiresAt} {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	expires = expires.Truncate(time.Second)
	if !expires.After(readBegan) || expires.Sub(issued) > 5*time.Minute {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	return issued, expires, nil
}

func (p *rpLinkPhase) restoreLinkedOutput(ctx context.Context, original identity.Command, generation uint64, wire []byte) (rpLinkedOutput, identity.Command, kernel.CapabilityIssuancePlan, error) {
	fail := func(err error) (rpLinkedOutput, identity.Command, kernel.CapabilityIssuancePlan, error) {
		return rpLinkedOutput{}, identity.Command{}, kernel.CapabilityIssuancePlan{}, err
	}
	aad, err := p.outputAAD(ctx, original, generation)
	if err != nil {
		return fail(err)
	}
	plain, err := p.service.openRP(ctx, aad, wire, 1<<20)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	var out rpLinkedOutput
	if decodeRPOutput(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || len(out.Checkpoint) == 0 || len(out.Checkpoint) > 512<<10 || len(out.Issuance.Grants) != 1 {
		return fail(identity.ForbiddenError{})
	}
	spec, _, _, ok := original.AccountLinkPreparationInput()
	expected, err := callbackSpecification(p.flow)
	change := identity.AccountLinkChange(out.Change)
	if !ok || err != nil || spec.Binding != expected.Binding || change.Mode != identity.AccountLinkExplicit || change.Account.ID != identity.AccountID(spec.Binding.RecordID) || change.Account.TenantID != spec.Binding.TenantID || change.Account.UserID != spec.Binding.UserID || change.Account.Provider != spec.ProviderID || change.Account.Issuer != p.flow.binding.Provider.Issuer || change.Account.Version != 1 || change.ExpectedAccountVersion != 0 || change.Method == nil || change.Method.Credential.Owner != "identity/oauth" || change.Method.Credential.Kind != identity.CredentialProvider || change.Method.Credential.ID != identity.CredentialID(change.Account.ID) || change.Method.AccountID != change.Account.ID || !change.Method.Usable || !change.Method.ExpiresAt.IsZero() {
		return fail(identity.ForbiddenError{})
	}
	vault := out.Tokens.Binding
	if vault.TenantID != change.Account.TenantID || vault.UserID != change.Account.UserID || vault.AccountID != change.Account.ID || vault.AccountVersion != change.Account.Version || vault.SocialLinkVersion != change.ExpectedSocialLinkVersion+1 || vault.ProviderID != change.Account.Provider || vault.Issuer != change.Account.Issuer || vault.ClientID != p.flow.binding.Provider.ClientID || vault.ConfigurationVersion != p.flow.binding.Provider.Version || p.service.validatePreparedProviderTokens(ctx, out.Tokens) != nil {
		return fail(identity.ForbiddenError{})
	}
	issued, expires, err := p.linkProofLifetime(out.ReadBegan, out.SourceExpiresAt)
	plan := out.Issuance.native()
	if err != nil || !plan.Grants[0].ExpiresAt.Equal(expires) {
		return fail(identity.ForbiddenError{})
	}
	prepared, err := p.service.checkpoint.RestorePreparation(ctx, spec.Binding, generation, plan, out.Checkpoint)
	if err != nil {
		return fail(err)
	}
	grants, err := prepared.Grants()
	if err != nil || len(grants) != 1 || !grants[0].Payload().IssuedAt.Equal(issued) {
		return fail(identity.ForbiddenError{})
	}
	command := identity.AccountLinkCommand{Binding: spec.Binding, Change: change, Proof: grants[0], SessionID: spec.SessionID, SessionVersion: spec.SessionVersion}
	unsigned := command
	unsigned.Proof = capability.Grant{}
	want, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: unsigned, Issuer: p.service.config().Capability.Crypto.Issuer, Audience: p.service.config().Capability.Audience, ID: grants[0].Payload().ID, IssuedAt: issued, ExpiresAt: expires})
	if err != nil || !reflect.DeepEqual(want, grants[0].Payload()) {
		return fail(identity.ForbiddenError{})
	}
	base, err := identity.NewAccountLinkCommand(command)
	if err != nil {
		return fail(err)
	}
	final, err := identity.NewAccountLinkCounterCommand(base, spec.Counters)
	if err != nil {
		return fail(err)
	}
	return out, final, plan, nil
}
