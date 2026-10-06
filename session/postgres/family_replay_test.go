package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestFamilyReplayRejectsZeroComposition(t *testing.T) {
	if _, err := NewFamilyReplayGuard(nil, FamilyReplayGuardConfig{}); err == nil {
		t.Fatal("zero replay guard admitted")
	}
	for _, guard := range []*FamilyReplayGuard{nil, {}} {
		if got, err := guard.CheckReplay(context.Background(), FamilyReplayInput{}); err == nil || got.Binding.CommandID != "" || got.Feature != nil {
			t.Fatal("zero replay request admitted")
		}
	}
}

func TestFamilyReplayEvidenceIsClosedAndExact(t *testing.T) {
	b := revokeBinding()
	b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "replay-service"
	rotation, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	proof := replayEvidence{user: b.UserID, family: b.RecordID, version: 1, rotation: rotation, lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, source: [32]byte{2}, expires: time.Now().UTC()}
	command, err := mapReplayEvidence(b, proof)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := nativeReplayEvidence(command); err != nil || decoded != proof {
		t.Fatal("exact intent changed evidence", err)
	}
	for _, mode := range []string{"human actor", "missing field", "unknown field", "wrong kind", "zero version", "key overflow", "short digest", "zero source", "invalid rotation", "noncanonical expiry"} {
		t.Run(mode, func(t *testing.T) {
			spec, _ := command.Feature()
			switch mode {
			case "human actor":
				spec.Binding.ActorKind = authorization.SubjectUser
			case "missing field":
				spec.Fields = spec.Fields[:5]
			case "unknown field":
				spec.Fields[5].Name = "unknown"
			case "wrong kind":
				spec.Fields[0].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "1"}
			default:
				for i := range spec.Fields {
					field := &spec.Fields[i]
					switch {
					case mode == "zero version" && field.Name == "expected.version":
						field.Value.Uint64 = 0
					case mode == "key overflow" && field.Name == "replay.lookup.version":
						field.Value.Uint64 = 1 << 32
					case mode == "short digest" && field.Name == "replay.lookup.digest":
						field.Value.Bytes = []byte{1}
					case mode == "zero source" && field.Name == "replay.source.digest":
						field.Value.Bytes = make([]byte, 32)
					case mode == "invalid rotation" && field.Name == "replay.rotation-command":
						field.Value.Text = "invalid"
					case mode == "noncanonical expiry" && field.Name == "replay.expires-at":
						field.Value.Text = proof.expires.Format(time.RFC3339)
					}
				}
			}
			changed, err := identity.NewFeatureCommand(spec)
			if err == nil {
				if _, err = nativeReplayEvidence(changed); err == nil {
					t.Fatal("malformed replay evidence admitted")
				}
			}
		})
	}
}

func TestFamilyReplayCustodyIsRedacted(t *testing.T) {
	values := []any{FamilyReplayGuard{}, FamilyReplayGuardConfig{}, FamilyReplayInput{CorrelationID: "private-input"}}
	for i, value := range values {
		want := []string{"postgres.FamilyReplayGuard(redacted)", "postgres.FamilyReplayGuardConfig(redacted)", "postgres.FamilyReplayInput(redacted)"}[i]
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(verb, value) != want {
				t.Fatal("format disclosed custody")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("JSON disclosed custody", err)
		}
	}
}
