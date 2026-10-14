package passwordpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestMFAEnablePrimaryZeroCannotProduceAdmissionOrConsume(t *testing.T) {
	for _, source := range []*MFAEnablePrimarySource{nil, {}} {
		admission, err := source.Prepare(context.Background(), MFAEnablePrimaryRequest{})
		if err == nil || admission.custody != nil {
			t.Fatal("unconfigured source manufactured primary admission")
		}
	}
	if source, err := NewMFAEnablePrimarySource(nil, MFAEnablePrimaryConfig{}); err == nil || source != nil {
		t.Fatal("unconfigured native composition accepted")
	}
	var admission MFAEnableAdmission
	if deadline, err := admission.Deadline(); err == nil || !deadline.IsZero() {
		t.Fatal("zero admission manufactured freshness")
	}
	if err := admission.Admit(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero admission granted preparation authority")
	}
	if _, err := admission.Original(); err == nil {
		t.Fatal("zero admission manufactured an original session")
	}
	if wire, err := admission.Snapshot(); err == nil || len(wire) != 0 {
		t.Fatal("zero admission exported original custody")
	}
	for _, source := range []*MFAEnablePrimarySource{nil, {}} {
		if restored, err := source.Restore(context.Background(), MFAEnablePrimaryRequest{}, []byte(`{}`)); err == nil || restored.custody != nil {
			t.Fatal("unconfigured source restored original custody")
		}
	}
	if _, err := admission.Command(identity.CommandBinding{}, nil); err == nil {
		t.Fatal("zero admission manufactured command custody")
	}
	if err := admission.Consume(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero admission consumed proof")
	}
	if err := admission.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero admission granted primary permission")
	}
	if outcome, err := admission.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil || outcome != kernel.RecoveryUnknown {
		t.Fatal("zero admission certified recovery")
	}
}

func TestMFAURIPrimaryCannotRestoreUnconfiguredOrNakedCustody(t *testing.T) {
	for _, source := range []*MFAEnablePrimarySource{nil, {}} {
		if restored, err := source.RestoreEnrollmentForURI(context.Background(), mfa.TotpUriRequest{}, "", 0, []byte(`{}`)); err == nil || restored != nil {
			t.Fatal("unconfigured URI source manufactured current primary authority")
		}
	}
}

func TestMFAConfirmationPrimaryCannotRestoreUnconfiguredCustody(t *testing.T) {
	for _, source := range []*MFAEnablePrimarySource{nil, {}} {
		if restored, err := source.RestoreEnrollmentForConfirmation(context.Background(), mfa.TotpVerifyRequest{}, "", 0, []byte(`{}`)); err == nil || restored != nil {
			t.Fatal("unconfigured confirmation manufactured current authority")
		}
	}
}

func TestMFAEnablePrimaryDiagnosticsDoNotTraverseCustody(t *testing.T) {
	values := []any{MFAEnableAdmission{}, MFAEnablePrimaryRequest{}, MFAEnablePrimarySource{}}
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if !strings.Contains(fmt.Sprintf(verb, value), "redacted") {
				t.Fatal("native custody traversed by diagnostic formatting")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit admission/source/request export accepted")
		}
	}
}

func TestMFAURIPrimaryCSRFSelectionRejectsMissingOrDuplicateKeys(t *testing.T) {
	key, err := session.NewCSRFKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][]session.CSRFKey{nil, {}, {{}}, {key, key}, {key, key, key, key, key}} {
		if source, err := NewCookieMFAEnablePrimarySource(nil, keys); err == nil || source != nil {
			t.Fatal("missing primary or invalid synchronizer profile accepted")
		}
	}
}
