package risk

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestEvidenceUseConfigurationBindsPolicyAndCompleteRetainedKeys(t *testing.T) {
	now := testContext().Now
	config := issuerConfig(t, &now, evidenceExecutor{resolve: missingEvidence})
	retained, e := NewEvidenceKey(2, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	if e != nil {
		t.Fatal(e)
	}
	config.Keys = append(config.Keys, retained)
	issuer, e := NewPhoneEvidenceIssuer(config)
	if e != nil {
		t.Fatal(e)
	}
	version := config.Evaluation.state.policy.state.version
	if e := issuer.ValidateUseConfiguration(version, []EvidenceKey{retained, config.Keys[0]}); e != nil {
		t.Fatal("matching retained set rejected", e)
	}
	for _, keys := range [][]EvidenceKey{nil, {}, config.Keys[:1], {config.Keys[0], config.Keys[0]}, {config.Keys[0], {}}, {config.Keys[0], retained, retained}} {
		if e := issuer.ValidateUseConfiguration(version, keys); !errors.Is(e, ErrInvalidPolicy) {
			t.Fatal("incomplete or duplicate custody admitted", e)
		}
	}
	for _, mutate := range []func(*EvidenceKey){
		func(k *EvidenceKey) { k.version++ }, func(k *EvidenceKey) { k.signing[0] ^= 1 }, func(k *EvidenceKey) { k.digest[0] ^= 1 },
	} {
		key := retained
		mutate(&key)
		if e := issuer.ValidateUseConfiguration(version, []EvidenceKey{config.Keys[0], key}); !errors.Is(e, ErrInvalidPolicy) {
			t.Fatal("foreign key lane admitted", e)
		}
	}
	for _, version := range []uint64{0, version + 1} {
		if e := issuer.ValidateUseConfiguration(version, config.Keys); !errors.Is(e, ErrInvalidPolicy) {
			t.Fatal("foreign policy admitted", e)
		}
	}
	if e := (PhoneEvidenceIssuer{}).ValidateUseConfiguration(version, config.Keys); !errors.Is(e, ErrInvalidPolicy) {
		t.Fatal("zero issuer admitted", e)
	}
	// Configuration comparison cannot sample time or perform any owned work.
	issuer.state.clock = func() time.Time { t.Fatal("sampled clock"); return time.Time{} }
	issuer.state.executor = evidenceExecutor{resolve: func(context.Context, EvidenceIntent) (EvidenceExecution, error) {
		t.Fatal("resolved evidence")
		return EvidenceExecution{}, nil
	}}
	for name, source := range issuer.state.evaluation.state.sources {
		source.Read = func(context.Context, Context) (Signal, error) { t.Fatal("read signal"); return Signal{}, nil }
		issuer.state.evaluation.state.sources[name] = source
	}
	if e := issuer.ValidateUseConfiguration(version, config.Keys); e != nil {
		t.Fatal("comparison dispatched work", e)
	}
	keys := append([]EvidenceKey(nil), config.Keys...)
	if e := issuer.ValidateUseConfiguration(version, keys); e != nil {
		t.Fatal(e)
	}
	keys[0] = EvidenceKey{}
	if e := issuer.ValidateUseConfiguration(version, config.Keys); e != nil {
		t.Fatal("retained caller slice", e)
	}
}
