package identity_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestFeatureOneTimeCodeFreezesOpaqueSubmission(t *testing.T) {
	spec := featureCommandSpec()
	code, _ := auth.NewOneTimeCode("123456")
	command, err := identity.NewFeatureOneTimeCodeCommand(spec, code)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := command.OneTimeCode()
	if !ok {
		t.Fatal("opaque code custody missing")
	}
	key := [32]byte{1}
	want, _ := code.CommandDigest(key, "one-time-code")
	actual, err := got.CommandDigest(key, "one-time-code")
	if err != nil || actual != want {
		t.Fatal("exact code bytes changed")
	}
	spec.Binding.UserID = "changed"
	projected, ok := command.Feature()
	if !ok || projected.Binding != featureBinding() {
		t.Fatal("structural scope aliased")
	}
	if _, ok := (identity.Command{}).OneTimeCode(); ok {
		t.Fatal("zero command gained custody")
	}
	legacy, _ := identity.NewFeatureCommand(featureCommandSpec())
	if _, ok := legacy.OneTimeCode(); ok {
		t.Fatal("ordinary command gained code")
	}
}

func TestFeatureOneTimeCodeRejectsInvalidAndRedactsCopies(t *testing.T) {
	code, _ := auth.NewOneTimeCode("123456")
	for _, input := range []struct {
		spec identity.FeatureCommandSpec
		code auth.OneTimeCode
	}{
		{identity.FeatureCommandSpec{}, code}, {featureCommandSpec(), auth.OneTimeCode{}},
	} {
		command, err := identity.NewFeatureOneTimeCodeCommand(input.spec, input.code)
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) {
			t.Fatal("invalid custody accepted")
		}
		if _, ok := command.OneTimeCode(); ok {
			t.Fatal("failed construction retained code")
		}
	}
	command, err := identity.NewFeatureOneTimeCodeCommand(featureCommandSpec(), code)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
		if !strings.Contains(fmt.Sprintf(format, command), "redacted") || strings.Contains(fmt.Sprintf(format, command), "123456") {
			t.Fatal("command disclosed secret")
		}
	}
	if wire, err := json.Marshal(command); err == nil || bytes.Contains(wire, []byte("123456")) {
		t.Fatal("secret command serialized")
	}
	projected, _ := command.Feature()
	projected.Binding.ActorID = "other"
	projected.Fields[0].Name = "changed"
	repeated, _ := command.Feature()
	if repeated.Binding.ActorID == "other" || repeated.Fields[0].Name == "changed" {
		t.Fatal("returned metadata mutated command")
	}
	key := [32]byte{2}
	want, _ := code.CommandDigest(key, "one-time-code")
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			borrowed, ok := command.OneTimeCode()
			if !ok {
				t.Error("concurrent custody lost")
				return
			}
			got, err := borrowed.CommandDigest(key, "one-time-code")
			if err != nil || got != want {
				t.Error("concurrent code changed")
			}
		})
	}
	wg.Wait()
}
