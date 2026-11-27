package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const proxyStartOutputLimit = 128 << 10

// The temporary coordinator output is separate from the row's callback custody.
// Its AAD is derived from the already admitted original, so recovery can find
// the encrypted generated state without trusting identifiers carried inside it.
type proxyStartOutput struct {
	Version                                 uint8
	Locator                                 proxyBindingLocator
	State, Challenge                        string
	BindingCiphertext, StateProofCiphertext []byte
	PKCECiphertext, Checkpoint              []byte
	Grant                                   rpStoredGrant
}

func (o *proxyStartOutput) clear() {
	clear(o.BindingCiphertext)
	clear(o.StateProofCiphertext)
	clear(o.PKCECiphertext)
	clear(o.Checkpoint)
	*o = proxyStartOutput{}
}

func (o proxyStartOutput) valid(b identity.CommandBinding) bool {
	l, g := o.Locator, o.Grant
	return o.Version == 1 && l.Tenant == b.TenantID && l.OriginCommand == b.CommandID && string(l.Transaction) == b.RecordID &&
		proxyBindingNonce(o.State) && proxyBindingNonce(o.Challenge) && len(o.BindingCiphertext) > 0 && len(o.BindingCiphertext) <= 65536 &&
		len(o.StateProofCiphertext) > 0 && len(o.StateProofCiphertext) <= proxyStateProofLimit &&
		len(o.PKCECiphertext) > 0 && len(o.PKCECiphertext) <= 4096 && len(o.Checkpoint) > 0 && len(o.Checkpoint) <= 65536 &&
		g.CapabilityID != "" && g.Purpose == "identity.oauth.proxy-forward" && g.MaxUses == 1 &&
		g.ReplayKeyVersion != 0 && g.ReplayDigest != ([32]byte{}) && g.ProofFingerprint != ([32]byte{}) && g.ExpiresAt.Equal(l.ExpiresAt)
}

func proxyStartOutputAAD(b identity.CommandBinding, request [32]byte, generation uint64, key string) (secretenvelope.Context, error) {
	const purpose = "identity.oauth.proxy-start-preparation.v1"
	if generation == 0 || request == ([32]byte{}) || !rpDirectoryID(string(b.TenantID)) || !rpASCII(key, 1, 256) {
		return secretenvelope.Context{}, identity.ForbiddenError{}
	}
	command, commandErr := identity.ParseCommandID(string(b.CommandID))
	target, targetErr := identity.ParsePreAuthTransactionID(b.RecordID)
	if commandErr != nil || targetErr != nil || b.RecordID != b.AnonymousFlowID || b.RecordID == string(b.CommandID) {
		return secretenvelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal([]any{purpose, b.TenantID, command, target, request, strconv.FormatUint(generation, 10), key})
	if err != nil {
		return secretenvelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return secretenvelope.NewContext(map[string]string{"purpose": purpose, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func sealProxyStartOutput(ctx context.Context, svc *secretenvelope.Service, key string, b identity.CommandBinding, request [32]byte, generation uint64, output proxyStartOutput) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || svc == nil || !output.valid(b) {
		return nil, identity.ForbiddenError{}
	}
	aad, err := proxyStartOutputAAD(b, request, generation, key)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(output)
	defer clear(plain)
	if err != nil || len(plain) >= proxyStartOutputLimit {
		return nil, identity.UnavailableError{}
	}
	sealed, err := svc.Encrypt(ctx, secretenvelope.EncryptRequest{KeyReference: key, Context: aad, Plaintext: plain})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > proxyStartOutputLimit || ctx.Err() != nil {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func openProxyStartOutput(ctx context.Context, svc *secretenvelope.Service, b identity.CommandBinding, request [32]byte, generation uint64, wire []byte) (proxyStartOutput, error) {
	var out proxyStartOutput
	if ctx == nil || ctx.Err() != nil || svc == nil || len(wire) == 0 || len(wire) > proxyStartOutputLimit {
		return out, identity.ForbiddenError{}
	}
	sealed, err := secretenvelope.ParseEnvelope(wire)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	aad, err := proxyStartOutputAAD(b, request, generation, sealed.KeyReference())
	if err != nil {
		return out, err
	}
	plain, err := svc.Decrypt(ctx, secretenvelope.DecryptRequest{Context: aad, Envelope: sealed})
	defer clear(plain)
	if err != nil || ctx.Err() != nil || len(plain) >= proxyStartOutputLimit || decodeRPOutput(plain, &out) != nil || !out.valid(b) {
		out.clear()
		return out, identity.ForbiddenError{}
	}
	canonical, err := json.Marshal(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		out.clear()
		return out, identity.ForbiddenError{}
	}
	return out, nil
}
