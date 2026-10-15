package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestPreparationRequestPolicyPreservesOriginalVersion(t *testing.T) {
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.otp.send"}
	fields := []identity.FeatureField{{Name: "intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}}}
	_, safe, err := requestIntentFingerprint(scope, fields, 7, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	version, err := preparationRequestPolicy(scope, safe)
	if err != nil || version != 7 {
		t.Fatal("original policy lost", err)
	}
	for _, wire := range [][]byte{nil, safe[:len(safe)-1], append(bytes.Clone(safe), 0), bytes.Repeat([]byte{1}, 65537)} {
		if version, err := preparationRequestPolicy(scope, wire); err == nil || version != 0 {
			t.Fatal("invalid input accepted")
		}
	}
	other := scope
	other.TenantID = "other"
	if _, err := preparationRequestPolicy(other, safe); err == nil {
		t.Fatal("foreign request provenance accepted")
	}
	_, zero, _ := requestIntentFingerprint(scope, fields, 0, [32]byte{1})
	if _, err := preparationRequestPolicy(scope, zero); err == nil {
		t.Fatal("zero policy accepted")
	}
	for _, fields := range [][]identity.FeatureField{nil, {{Name: "time", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Now().UTC().Truncate(time.Microsecond)}}}} {
		_, safe, err := requestIntentFingerprint(scope, fields, 7, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if version, err := preparationRequestPolicy(scope, safe); err != nil || version != 7 {
			t.Fatal("supported field grammar rejected", err)
		}
	}
	fields = nil
	for i := range 128 {
		fields = append(fields, identity.FeatureField{Name: "field.f" + strconv.Itoa(i), Value: identity.FeatureValue{Kind: identity.FeatureBool}})
	}
	_, safe, err = requestIntentFingerprint(scope, fields, 7, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if version, err := preparationRequestPolicy(scope, safe); err != nil || version != 7 {
		t.Fatal("maximum valid field count rejected", err)
	}
	for _, badFields := range [][]identity.FeatureField{append(fields, identity.FeatureField{Name: "extra", Value: identity.FeatureValue{Kind: identity.FeatureBool}}), {{Name: "Invalid", Value: identity.FeatureValue{Kind: identity.FeatureBool}}}} {
		_, safe, err := requestIntentFingerprint(scope, badFields, 7, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := preparationRequestPolicy(scope, safe); err == nil {
			t.Fatal("invalid field grammar accepted")
		}
	}
}

func FuzzPreparationRequestPolicy(f *testing.F) {
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.otp.send"}
	_, safe, _ := requestIntentFingerprint(scope, nil, 7, [32]byte{1})
	f.Add(safe)
	f.Add([]byte{0xa8})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65537 {
			return
		}
		version, err := preparationRequestPolicy(scope, wire)
		if err != nil && version != 0 || err == nil && version == 0 {
			t.Fatal("invalid parser result")
		}
	})
}

func TestPreparedFeatureRecordRedactionAndInvalidQuery(t *testing.T) {
	private := []byte("private-native-custody")
	r := PreparedFeatureRecord{InputCiphertext: private, OutputCiphertext: private, OutputGeneration: 1}
	if strings := fmt.Sprintf("%v %#v %+v", r, r, r); bytes.Contains([]byte(strings), private) {
		t.Fatal("diagnostic disclosed custody")
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("custody serialized")
	}
	var c *Coordinator
	got, err := c.QueryPreparedFeature(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}, FeatureRegistration{}, nil)
	if err == nil || got.OutputGeneration != 0 || got.InputCiphertext != nil || got.OutputCiphertext != nil {
		t.Fatal("invalid query returned custody")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("invalid configuration invented cancellation")
	}
}
