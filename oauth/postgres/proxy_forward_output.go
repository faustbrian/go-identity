package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

type proxyCustodyPart string

const (
	proxyForwardPreparation proxyCustodyPart = "forward-preparation"
	proxyStateProof         proxyCustodyPart = "state-proof"
	proxyVerifier           proxyCustodyPart = "pkce-verifier"
)

func proxyPartAAD(l proxyBindingLocator, key string, part proxyCustodyPart, generation uint64) (secretenvelope.Context, error) {
	switch part {
	case proxyForwardPreparation:
		if generation == 0 {
			return secretenvelope.Context{}, identity.ForbiddenError{}
		}
	case proxyStateProof, proxyVerifier:
		if generation != 0 {
			return secretenvelope.Context{}, identity.ForbiddenError{}
		}
	default:
		return secretenvelope.Context{}, identity.ForbiddenError{}
	}
	base, err := proxyBindingAAD(l, key)
	if err != nil {
		return secretenvelope.Context{}, identity.ForbiddenError{}
	}
	values := base.Values()
	values["custody_part"] = string(part)
	values["generation"] = strconv.FormatUint(generation, 10)
	return secretenvelope.NewContext(values)
}

func sealProxyPart(ctx context.Context, svc *secretenvelope.Service, key string, l proxyBindingLocator, part proxyCustodyPart, generation uint64, plain []byte, limit int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || svc == nil || len(plain) == 0 || len(plain) >= limit {
		return nil, identity.UnavailableError{}
	}
	aad, err := proxyPartAAD(l, key, part, generation)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	value, err := svc.Encrypt(ctx, secretenvelope.EncryptRequest{KeyReference: key, Context: aad, Plaintext: plain})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err := value.MarshalBinary()
	if err != nil || len(wire) > limit || ctx.Err() != nil {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func openProxyPart(ctx context.Context, svc *secretenvelope.Service, l proxyBindingLocator, part proxyCustodyPart, generation uint64, wire []byte, limit int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || svc == nil || len(wire) == 0 || len(wire) > limit {
		return nil, identity.ForbiddenError{}
	}
	value, err := secretenvelope.ParseEnvelope(wire)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	aad, err := proxyPartAAD(l, value.KeyReference(), part, generation)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	plain, err := svc.Decrypt(ctx, secretenvelope.DecryptRequest{Context: aad, Envelope: value})
	if err != nil || len(plain) == 0 || len(plain) >= limit || ctx.Err() != nil {
		clear(plain)
		return nil, identity.ForbiddenError{}
	}
	return plain, nil
}

type proxyForwardOutput struct {
	Disposition oauthproxy.CallbackDisposition
	Artifact    []byte
	Until       time.Time
}

func (v proxyForwardOutput) valid(l proxyBindingLocator) bool {
	switch v.Disposition {
	case oauthproxy.CallbackRejected:
		return len(v.Artifact) == 0 && v.Until.IsZero()
	case oauthproxy.CallbackForwarded:
		return len(v.Artifact) > 0 && len(v.Artifact) <= 8192 && rpUTCTime(v.Until) && v.Until.After(l.IssuedAt) && !v.Until.After(l.ExpiresAt)
	default:
		return false
	}
}

func sealProxyForwardOutput(ctx context.Context, svc *secretenvelope.Service, key string, l proxyBindingLocator, generation uint64, value proxyForwardOutput) ([]byte, error) {
	if !value.valid(l) {
		return nil, identity.ForbiddenError{}
	}
	plain, err := json.Marshal(value)
	defer clear(plain)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealProxyPart(ctx, svc, key, l, proxyForwardPreparation, generation, plain, 16384)
}

func openProxyForwardOutput(ctx context.Context, svc *secretenvelope.Service, l proxyBindingLocator, generation uint64, wire []byte) (proxyForwardOutput, error) {
	plain, err := openProxyPart(ctx, svc, l, proxyForwardPreparation, generation, wire, 16384)
	if err != nil {
		return proxyForwardOutput{}, err
	}
	defer clear(plain)
	var value proxyForwardOutput
	if err := decodeRPOutput(plain, &value); err != nil || !value.valid(l) {
		clear(value.Artifact)
		return proxyForwardOutput{}, identity.ForbiddenError{}
	}
	canonical, err := json.Marshal(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		clear(value.Artifact)
		return proxyForwardOutput{}, identity.ForbiddenError{}
	}
	return value, nil
}
