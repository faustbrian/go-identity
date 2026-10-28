package postgres

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func apiKeyVerificationCodecSeed(anonymous bool) (identity.CommandBinding, CommandPlan) {
	b := codecBinding()
	op := apiKeyVerificationOperation(anonymous)
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, ""
	b.ActorKind, b.ActorID = authorization.SubjectAPIKey, "key-a"
	authentication := AuditPlan{EventType: "identity.api_key.authenticate", SchemaVersion: 1, BindingDigest: [32]byte{1}, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true, RetentionClass: "protected"}
	update := authentication
	update.EventType, update.EventIndex = "identity.api_key.update", 1
	p := CommandPlan{
		Contributors: []ContributorDescriptor{
			{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1},
			{Owner: "audit/postgres", ContractID: "audit.records", Version: 1},
			{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1},
			apiKeyVerificationDescriptor(),
		},
		Feature:            &FeatureRegistration{Contributor: apiKeyVerificationDescriptor(), Operation: op},
		SubjectType:        "api_key",
		Audits:             []AuditPlan{authentication, update},
		Lifecycle:          &LifecyclePlan{EventType: "api_key.permissions_changed.v1"},
		APIKeyVerification: &APIKeyVerificationPlan{KeyVersion: 7},
	}
	if anonymous {
		b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
		b.ActorKind, b.ActorID = authorization.SubjectServiceAccount, "api-key-verifier"
		p.SubjectType, p.APIKeyVerification.KeyVersion = "authentication_attempt", 0
		p.Audits = p.Audits[:1]
	}
	return b, p
}

func FuzzAPIKeyVerificationPlan(f *testing.F) {
	fingerprint := [32]byte{9}
	for _, anonymous := range []bool{false, true} {
		b, p := apiKeyVerificationCodecSeed(anonymous)
		wire, err := encodeFeaturePlan(b, fingerprint, p)
		if err != nil {
			f.Fatal("valid closed verification corpus rejected")
		}
		f.Add(anonymous, wire)
		f.Add(anonymous, append(bytes.Clone(wire), 0))
		f.Add(anonymous, wire[:len(wire)-1])
		f.Add(anonymous, []byte{})
		f.Add(anonymous, []byte{0xbf, 0xff})
		f.Add(anonymous, make([]byte, 65537))
		p.APIKeyVerification = nil
		p.Feature.Operation.Owner = "identity/custom"
		p.Feature.Contributor.Owner = "identity/custom/postgres"
		p.Contributors[len(p.Contributors)-1] = p.Feature.Contributor
		foreign, err := encodeFeaturePlan(b, fingerprint, p)
		if err != nil {
			f.Fatal("valid generic compatibility corpus rejected")
		}
		f.Add(anonymous, foreign)
	}
	f.Fuzz(func(t *testing.T, anonymous bool, wire []byte) {
		b, _ := apiKeyVerificationCodecSeed(anonymous)
		p, err := decodeFeaturePlan(b, fingerprint, wire)
		if err != nil {
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || !reflect.DeepEqual(p, CommandPlan{}) {
				t.Fatal("hostile retained bytes returned partial authority or noncanonical error")
			}
			return
		}
		canonical, err := encodeFeaturePlan(b, fingerprint, p)
		// The binding does not select a feature owner. Compatible generic history
		// is valid; canonical encoding still requires the closed plan whenever
		// the exact native verification descriptor selects that profile.
		if err != nil || len(wire) > 65536 || p.APIKeyVerification != nil && !validAPIKeyVerificationPlan(b, p) || !bytes.Equal(canonical, wire) || p.Digest != sha256.Sum256(wire) {
			t.Fatal("retained bytes escaped their bounded canonical declared profile")
		}
	})
}
