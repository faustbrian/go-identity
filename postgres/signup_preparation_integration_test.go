//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// This owned participant tests the kernel preparation/transaction seam, not
// the production issuer's still-required durable restoration or SignupService.
type signupPreparationPhase struct {
	*registrationTestPhase
	declaration         CommandPlan
	delivery            *deliverySQLPhase
	token               string
	generated, restored atomic.Int64
	outputGeneration    uint64
	originalInput       bool
	generatedCommand    identity.Command
}

func (p *signupPreparationPhase) ValidateFeaturePreparation(c identity.Command, plan CommandPlan) error {
	if p.originalInput {
		secret, cookie, ok := c.PasswordSignupInputCustody()
		if !ok || secret.Len() == 0 || cookie.Token() == "" {
			return invalidPreparation()
		}
		return nil
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *signupPreparationPhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	s, ok := c.PasswordSignupFeature()
	if p.originalInput {
		s, ok = c.PasswordSignupInputFeature()
	}
	b, _, _, err := w.FeatureScope(p)
	if !ok || err != nil || b != s.Binding {
		return invalidWork()
	}
	_, err = w.DatabaseTime(ctx)
	return err
}

func signupPreparationAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{19}, 32))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func signupPreparationAAD(c identity.Command, generation uint64) ([]byte, error) {
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		return nil, err
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	return append(binary.BigEndian.AppendUint64(nil, generation), fp[:]...), nil
}

func (p *signupPreparationPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.generated.Add(1)
	aad, err := signupPreparationAAD(c, generation)
	if err != nil {
		return nil, err
	}
	aead, err := signupPreparationAEAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(p.token), aad), ctx.Err()
}

func (p *signupPreparationPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	p.restored.Add(1)
	aad, err := signupPreparationAAD(c, generation)
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	aead, err := signupPreparationAEAD()
	if err != nil || len(wire) < aead.NonceSize()+aead.Overhead() {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	plain, err := aead.Open(nil, wire[:aead.NonceSize()], wire[aead.NonceSize():], aad)
	if err != nil {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	defer clear(plain)
	verifier, err := capability.NewHMACSHA256Verifier([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	p.grant, err = capability.Verify(ctx, string(plain), capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Verifier: verifier}, nil
	}), capability.VerifyOptions{Now: time.Now().UTC(), Limits: capability.DefaultLimits()})
	if err != nil {
		return identity.Command{}, CommandPlan{}, err
	}
	p.outputGeneration = generation
	if p.originalInput {
		return p.generatedCommand, p.declaration, nil
	}
	return c, p.declaration, nil
}

func (p *signupPreparationPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, generation, err := w.FeaturePreparationOutput(p); err != nil || generation != p.outputGeneration {
		return identity.FeatureReceipt{}, invalidWork()
	}
	if !p.skip {
		var accepted bool
		var err error
		if p.accept {
			_, accepted, err = p.domain.ApplyOrAccept(ctx, w, p, c, p.intent)
		} else {
			_, err = p.domain.Apply(ctx, w, p, c, p.intent)
		}
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if accepted {
			p.accepted = true
			s, _ := c.PasswordSignupFeature()
			return identity.FeatureReceipt{Operation: s.Operation}, nil
		}
		b, _, _, err := w.FeatureScope(p)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_registration_material(command_id,user_id) VALUES($1,$2)`, string(b.CommandID), string(p.intent.Creation.Binding.UserID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := w.StageCapabilityIssuanceFor(p.issuer, 0, p.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.delivery != nil {
		wire, _, err := w.FeaturePreparationOutput(p)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := w.StageDeliveryFor(p.delivery, DeliveryEnvelope{KeyID: "synthetic-key", Ciphertext: wire}); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	s, _ := c.PasswordSignupFeature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
