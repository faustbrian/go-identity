package magiclinkpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func originCodecFixture(t testing.TB) (*RequestService, identity.CommandBinding, []byte) {
	t.Helper()
	op := requestOperation()
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", AnonymousFlowID: "AgICAgICAgICAgICAgICAg", ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: "AQEBAQEBAQEBAQEBAQEBAQ"}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "request.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-input-digest"}}}}
	provider, err := keyring.New(map[string][]byte{"origin-test": bytes.Repeat([]byte{55}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	s := &RequestService{crypto: crypto, configuration: [32]byte{3}}
	aad, err := requestOriginOutputAAD(b, 1, s.configuration)
	if err != nil {
		t.Fatal(err)
	}
	// Codec custody alone is not a valid recipient or authentication. The public
	// owner bridge separately validates that complete historical domain shape.
	plain, err := json.Marshal(storedOutput{Schema: 2, Global: 1, Tenant: 1, RequestSpec: &spec})
	defer clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: plain, Context: aad, KeyReference: "origin-test"})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	framed := append([]byte(requestOriginPrefix), wire...)
	clear(wire)
	return s, b, framed
}

func TestRequestOriginCodecFencesGenerationConfigurationAndSize(t *testing.T) {
	s, b, wire := originCodecFixture(t)
	defer clear(wire)
	if out, err := s.readOriginOutput(context.Background(), b, 1, wire); err != nil || out.RequestSpec == nil || out.RequestSpec.Binding != b {
		t.Fatal("origin codec lost retained full command", err)
	}
	if _, err := s.readOriginOutput(context.Background(), b, 2, wire); err == nil {
		t.Fatal("foreign original generation decoded")
	}
	s.configuration = [32]byte{4}
	if _, err := s.readOriginOutput(context.Background(), b, 1, wire); err == nil {
		t.Fatal("foreign configuration decoded")
	}
	s.configuration = [32]byte{3}
	for _, malformed := range [][]byte{nil, []byte(requestOriginPrefix), wire[len(requestOriginPrefix):], bytes.Repeat([]byte{1}, maximumRequestOutput+1)} {
		if _, err := s.readOriginOutput(context.Background(), b, 1, malformed); err == nil {
			t.Fatal("malformed/legacy/unbounded origin decoded")
		}
	}
}

func FuzzRequestOriginOutput(f *testing.F) {
	s, binding, wire := originCodecFixture(f)
	f.Add(wire)
	f.Add([]byte(requestOriginPrefix))
	f.Add([]byte{})
	f.Add(wire[len(requestOriginPrefix):])
	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := s.readOriginOutput(context.Background(), binding, 1, input)
		defer clear(out.IssuanceWire)
		defer clear(out.DeliveryWire)
		if err == nil && (out.Schema != 2 || out.RequestSpec == nil || out.RequestSpec.Binding != binding || out.RequestSpec.Operation != requestOperation() || out.Global == 0 || out.Tenant == 0) {
			t.Fatal("unauthenticated or noncanonical original command survived decoding")
		}
	})
}
