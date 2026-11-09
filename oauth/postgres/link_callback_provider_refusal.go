package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

var _ kernel.AccountLinkPreparationRefusalContributor = (*rpLinkPhase)(nil)

const rpRefusalPrefix = "identity-oauth-refusal-v1\x00"

// This closed variant contains no provider response or credential. The original
// input commitment is authenticated inside it, not required to reconstruct AAD
// after RP expiry. Stable RP metadata binds historical decoding to the exact
// flow/state/command; ordinary retry additionally checks original code/browser
// commitment. Successful preparation ciphertext retains its existing format.
type rpProviderRefusalOutput struct {
	Schema     uint8
	Generation uint64
	Input      [32]byte
}

func (p *rpLinkPhase) refusalAAD(b identity.CommandBinding, state kernel.CapabilityPlan, generation uint64) (envelope.Context, error) {
	if generation == 0 || !p.matchesRetainedLinkScope(b, state) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(struct {
		Binding rpStoredBinding
		State   rpStoredGrant
		Flow    rpStartBinding
	}{rpStoredBinding(b), rpStoredGrant(state), p.flow.binding})
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-link-refusal-v1", "scope": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
}

func (p *rpLinkPhase) sealProviderRefusal(ctx context.Context, original identity.Command, generation uint64) ([]byte, error) {
	if err := p.validateOriginal(ctx, original); err != nil {
		return nil, err
	}
	spec, _, _, ok := original.AccountLinkPreparationInput()
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	aad, err := p.refusalAAD(spec.Binding, p.flow.statePlan, generation)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(rpProviderRefusalOutput{Schema: 1, Generation: generation, Input: p.input})
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	defer clear(plain)
	wire, err := p.service.sealRP(ctx, aad, plain)
	if err != nil {
		return nil, err
	}
	return append([]byte(rpRefusalPrefix), wire...), nil
}

// RestoreAccountLinkPreparationRefusal authenticates retained definitive refusal
// evidence only. No proof is restored, verified, consumed or renewed; no final
// grant, account, vault or session can be produced. A historical owner has only
// authenticated original RP metadata, while a live owner also binds the exact
// original callback/browser commitment. Only the root-selected journal output
// and generation may cause terminal settlement through the coordinator.
func (p *rpLinkPhase) RestoreAccountLinkPreparationRefusal(ctx context.Context, binding identity.CommandBinding, state kernel.CapabilityPlan, generation uint64, wire []byte) (kernel.AccountLinkPreparationRefusal, error) {
	if !bytes.HasPrefix(wire, []byte(rpRefusalPrefix)) {
		return kernel.AccountLinkPreparationRefusal{}, nil
	}
	if ctx == nil || p == nil || p.service == nil || len(wire) > 8192 {
		return kernel.AccountLinkPreparationRefusal{}, identity.ForbiddenError{}
	}
	aad, err := p.refusalAAD(binding, state, generation)
	if err != nil {
		return kernel.AccountLinkPreparationRefusal{}, err
	}
	plain, err := p.service.openRP(ctx, aad, wire[len(rpRefusalPrefix):], 4096)
	if err != nil {
		return kernel.AccountLinkPreparationRefusal{}, err
	}
	defer clear(plain)
	var out rpProviderRefusalOutput
	if decodeRPOutput(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || out.Input == ([32]byte{}) || p.input != ([32]byte{}) && out.Input != p.input {
		return kernel.AccountLinkPreparationRefusal{}, identity.ForbiddenError{}
	}
	return kernel.AccountLinkPreparationRefusal{Binding: binding, State: state, Generation: generation}, nil
}
