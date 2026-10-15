package magiclinkpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestRequestOriginAADDoesNotRequireOriginalRequestSecrets(t *testing.T) {
	p, _ := signedRequestScopeFixture(t)
	spec, _ := p.original.Feature()
	spec.Fields = []identity.FeatureField{{Name: "request.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-input-digest"}}}
	p.original, _ = identity.NewFeatureCommand(spec)
	original, err := p.outputAAD(1, false)
	if err != nil {
		t.Fatal(err)
	}
	// The full original command belongs inside authenticated encrypted custody;
	// reconstructing AAD must not require the original email/cookie/request input.
	spec.Fields[0].Value.Text = "other-input-digest"
	p.original, _ = identity.NewFeatureCommand(spec)
	changed, err := p.outputAAD(1, false)
	if err != nil || !reflect.DeepEqual(original, changed) {
		t.Fatal("request-origin decryption still requires unrecoverable input fields")
	}
	otherGeneration, err := p.outputAAD(2, false)
	if err != nil || reflect.DeepEqual(original, otherGeneration) {
		t.Fatal("request-origin AAD lost original generation")
	}
}

func TestMFAOriginalPrimaryRejectsMissingCustody(t *testing.T) {
	for _, service := range []*RequestService{nil, {}} {
		result, err := service.ReadMFAMagicLinkPrimary(context.Background(), issuerpg.MFAMagicLinkParent{}, session.PreAuthTransaction{}, time.Now(), authorization.DecisionContext{})
		if err == nil || result != (MFAMagicLinkPrimary{}) {
			t.Fatal("missing origin custody retained primary metadata")
		}
	}
	if _, err := json.Marshal(MFAMagicLinkPrimary{}); err == nil {
		t.Fatal("original primary metadata implicitly serialized")
	}
	if fmt.Sprintf("%#v", MFAMagicLinkPrimary{}) != "magiclinkpostgres.MFAMagicLinkPrimary(redacted)" {
		t.Fatal("original primary metadata not redacted")
	}
}
