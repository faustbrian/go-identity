package passwordhttp

import "testing"

func TestSigninLocalizationRejectsAbsentDefaultCatalog(t *testing.T) {
	if service, err := newSigninLocalization(SigninLocalizationConfig{DefaultLocale: "en"}); service != nil || err == nil {
		t.Fatal("selected localization accepted an absent default catalog")
	}
}
