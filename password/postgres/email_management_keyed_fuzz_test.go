package passwordpostgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func FuzzKeyedEmailOriginalInput(f *testing.F) {
	operation := emailPrimaryOperation("identity.email.verification-send")
	now := time.Unix(1700000000, 0).UTC()
	input := keyedEmailInput{Schema: 1, Spec: identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser, RecordID: "mailbox", OperationID: operation.OperationID, SchemaID: operation.SchemaID, SchemaVersion: 1, PolicyID: "managed", PolicyVersion: 1, CorrelationID: "original"}, Operation: operation, Fields: []identity.FeatureField{{Name: "sample", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "bounded"}}}}, Proof: []byte("syntactic-proof-not-authority"), RequestInput: []identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "bounded"}}}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), TokenGeneration: 1, Counter: storedEmailCounter{PolicyVersion: 1, Fingerprint: [32]byte{1}}}
	valid, err := json.Marshal(input)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := decodeKeyedEmailInput(valid); err != nil {
		f.Fatal("valid syntactic seed", err)
	}
	for _, seed := range [][]byte{valid, nil, []byte(`{"Schema":1}`), []byte(`{"Schema":1,"Schema":2}`), append(bytes.Clone(valid), 'x'), []byte(`{"Schema":1,"Proof":"!"}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maximumKeyedPasswordCustody+1 {
			t.Skip()
		}
		out, err := decodeKeyedEmailInput(raw)
		if err != nil {
			if out.Schema != 0 || len(out.Proof) != 0 || len(out.RequestInput) != 0 {
				t.Fatal("invalid input returned custody")
			}
			return
		}
		canonical, err := json.Marshal(out)
		if err != nil || !bytes.Equal(raw, canonical) || out.Schema != 1 || len(out.Proof) == 0 || !out.ExpiresAt.After(out.IssuedAt) {
			t.Fatal("noncanonical or unbounded input accepted")
		}
	})
}
