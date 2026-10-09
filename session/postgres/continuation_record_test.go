package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Bounded plan: durable/jsonb and command reconstruction must retain independent
// current credential linkage without renewing historical authentication or
// lifetime. Deny partial, duplicate, mixed and version-inconsistent extensions.
func continuedRecordFixture(t testing.TB, csrf bool) session.Session {
	t.Helper()
	source, _, _ := identifierSessionFixture(t)
	if csrf {
		source = withCSRFState(t, source, 9)
	}
	record, err := session.ContinuePasswordSession(source, session.CredentialContinuationSpec{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", BeforeAuthorityVersion: 7, BeforeCredentialVersion: 9})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestContinuedRecordCannotMintFreshProofIssuedSession(t *testing.T) {
	continued := continuedRecordFixture(t, false)
	spec, _ := continued.Bindings()
	spec.Version = 1
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version = 1
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	c, _ := continued.CredentialContinuation()
	record, err := session.NewContinuedPasswordSession(spec, session.CSRFState{}, c)
	if err != nil {
		t.Fatal(err)
	}
	b := revokeBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", spec.SessionID
	native, err := session.NewIssueCommand(b, record)
	if err != nil {
		t.Fatal("structural fixture invalid", err)
	}
	if _, err := MapCommand(native); err == nil {
		t.Fatal("continued historical proof admitted for fresh issuance")
	}
	// A consumer can construct the scalar command directly; mapping rejection
	// alone must not be mistaken for the coordinator's admission boundary.
	mapped, err := mapSessionRecord(b, session.IssueOperation(), record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nativeIssue(mapped); err == nil {
		t.Fatal("direct issue command reconstructed continuation")
	}
	_, _, profile := identifierSessionFixture(t)
	repo := &Repository{schema: "session_store", issueAdmission: (*IssueAdmissionConfig)(&profile)}
	a := spec.Authentication
	proof := authentication.AuthenticatedProofSpec{Proof: a.Proof, ProofVersion: a.ProofVersion, CredentialID: a.CredentialID, CredentialVersion: a.CredentialVersion}
	if err := repo.ValidateAuthenticatedFeature(mapped, proof); err == nil {
		t.Fatal("historical proof promoted to effective current credential")
	}
}

func TestContinuedRevocationSuccessorPreservesRecord(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		source := continuedRecordFixture(t, csrf)
		before, _ := source.Bindings()
		next, err := revokeSetSuccessor(source)
		if err != nil {
			t.Fatal(err)
		}
		after, _ := next.Bindings()
		want, _ := source.CredentialContinuation()
		got, ok := next.CredentialContinuation()
		if !ok || got != want || next.EffectiveCredentialVersion() != 10 || after.Version != before.Version+1 || after.Authentication != before.Authentication || after.LastActivityAt != before.LastActivityAt || after.Lookup != before.Lookup {
			t.Fatal("revocation erased continuation or renewed evidence")
		}
		va, _ := before.Authority.Bindings()
		vb, _ := after.Authority.Bindings()
		va.Session.Version++
		if va != vb {
			t.Fatal("unrelated authority changed")
		}
		if csrf {
			state, _ := next.CSRFState().Bindings()
			original, _ := source.CSRFState().Bindings()
			original.Binding.SessionVersion++
			if state != original {
				t.Fatal("successor lost synchronizer linkage")
			}
		}
	}
	if _, err := revokeSetSuccessor(session.Session{}); err == nil {
		t.Fatal("zero source accepted")
	}
	if _, err := revokeSetSuccessor(testSession(t)); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestContinuedCommandRejectsPartialOrSubstitutedExtension(t *testing.T) {
	record := continuedRecordFixture(t, true)
	binding := revokeBinding()
	op := session.RevokeOneOperation()
	binding.OperationID, binding.SchemaID, binding.RecordID = op.OperationID, op.SchemaID, "session-a"
	mapped, err := mapSessionRecord(binding, op, record)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"continuation.command", "continuation.authority", "continuation.credential"} {
		for _, mode := range []string{"absent", "wrong-kind", "zero"} {
			projection, _ := mapped.Feature()
			fields := projection.Fields[:0]
			for _, f := range projection.Fields {
				if f.Name == name {
					if mode == "absent" {
						continue
					}
					if mode == "wrong-kind" {
						f.Value = identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}
					} else if name == "continuation.command" {
						f.Value.Text = "bad"
					} else {
						f.Value.Uint64 = 0
					}
				}
				fields = append(fields, f)
			}
			projection.Fields = fields
			bad, err := identity.NewFeatureCommand(projection)
			if err == nil {
				if _, _, err = nativeSessionRecord(bad, op); err == nil {
					t.Fatal("partial or substituted extension accepted", name, mode)
				}
			}
		}
	}
}

func TestContinuedStoredRecordSurvivesRestart(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		original := continuedRecordFixture(t, csrf)
		payload, expiry, err := encodeRecord(original)
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(payload, &top); err != nil {
			t.Fatal(err)
		}
		canonical, _ := json.Marshal(top) // jsonb can reorder object keys.
		restored, err := decodeRecord(canonical)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := original.CredentialContinuation()
		got, ok := restored.CredentialContinuation()
		if !ok || got != want || restored.EffectiveCredentialVersion() != 10 {
			t.Fatal("restart lost effective credential linkage")
		}
		before, _ := original.Bindings()
		after, _ := restored.Bindings()
		if before.Authentication != after.Authentication || after.Authentication.CredentialVersion != 9 {
			t.Fatal("historical authentication rewritten")
		}
		again, restoredExpiry, err := encodeRecord(restored)
		if err != nil || !bytes.Equal(payload, again) || expiry != restoredExpiry {
			t.Fatal("complete record or lifetime changed", err)
		}
	}
}

func TestContinuedNativeCommandAndAdmission(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		record := continuedRecordFixture(t, csrf)
		_, cmd, profile := identifierSessionFixture(t)
		_, credential, _, err := sessionAdmissionBindings(profile, record, cmd.Binding, cmd.SessionID, cmd.SessionVersion)
		if err != nil || credential.Credential.Version != 10 || credential.CredentialAuthorityVersion != 8 || credential.UserAuthorityVersion != 5 {
			t.Fatal("admission used historical credential or advanced user authority", err)
		}
		binding := revokeBinding()
		operation := session.RevokeOneOperation()
		binding.OperationID, binding.SchemaID, binding.RecordID = operation.OperationID, operation.SchemaID, "session-a"
		mapped, err := mapSessionRecord(binding, operation, record)
		if err != nil {
			t.Fatal(err)
		}
		_, restored, err := nativeSessionRecord(mapped, operation)
		if err != nil {
			t.Fatal(err)
		}
		want, _, _ := encodeRecord(record)
		got, _, _ := encodeRecord(restored)
		if !bytes.Equal(want, got) || restored.EffectiveCredentialVersion() != 10 {
			t.Fatal("original command lost complete continuation")
		}
	}
}

func TestContinuedRotationMappingPreservesBothRecords(t *testing.T) {
	for _, sourceCSRF := range []bool{false, true} {
		for _, successorCSRF := range []bool{false, true} {
			request := rotationMappingProfileFixture(t, sourceCSRF, successorCSRF, true)
			command, _ := request.Command()
			want, _ := command.Rotation()
			mapped, err := MapRotationRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			restored, _, _, err := nativeRotationIntent(mapped)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := restored.Rotation()
			for _, pair := range [][2]session.Session{{want.Source, got.Source}, {want.Successor, got.Successor}} {
				a, _, _ := encodeRecord(pair[0])
				b, _, _ := encodeRecord(pair[1])
				if !bytes.Equal(a, b) || pair[1].EffectiveCredentialVersion() != 10 {
					t.Fatal("rotation intent changed continuation")
				}
			}
		}
	}
}

func TestContinuedStoredRecordRejectsMalformedExtension(t *testing.T) {
	payload, _, err := encodeRecord(continuedRecordFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]json.RawMessage){
		func(v map[string]json.RawMessage) { delete(v, "Continuation") },
		func(v map[string]json.RawMessage) { v["Continuation"] = json.RawMessage(`null`) },
		func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`2`) },
		func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`5`) },
		func(v map[string]json.RawMessage) { v["OTP"] = json.RawMessage(`{}`) },
		func(v map[string]json.RawMessage) {
			v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":7}`)
		},
		func(v map[string]json.RawMessage) {
			v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":7,"BeforeCredentialVersion":null}`)
		},
		func(v map[string]json.RawMessage) {
			v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":7,"BeforeCredentialVersion":9,"BeforeCredentialVersion":9}`)
		},
		func(v map[string]json.RawMessage) {
			v["Continuation"] = json.RawMessage(`{"CommandID":"bad","BeforeAuthorityVersion":7,"BeforeCredentialVersion":9}`)
		},
		func(v map[string]json.RawMessage) {
			v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":8,"BeforeCredentialVersion":9}`)
		},
		func(v map[string]json.RawMessage) {
			v["Continuation"] = json.RawMessage(`{"CommandID":"AQEBAQEBAQEBAQEBAQEBAQ","BeforeAuthorityVersion":7,"BeforeCredentialVersion":18446744073709551615}`)
		},
	} {
		var top map[string]json.RawMessage
		json.Unmarshal(payload, &top)
		mutate(top)
		bad, _ := json.Marshal(top)
		if record, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) || record != (session.Session{}) {
			t.Fatal("malformed continuation accepted", err)
		}
	}
}
