package reference

import "testing"

func TestPasswordSignupHTTPRequiresOwnedDependencies(t *testing.T) {
	if h, err := composePasswordSignupHTTP(StoreConfiguration{}, nil); err != nil || h != nil {
		t.Fatal("unselected signup HTTP acquired dependencies", err)
	}
	c := StoreConfiguration{HTTPPasswordSignup: &HTTPPasswordSignupConfiguration{}}
	if h, err := composePasswordSignupHTTP(c, nil); err == nil || h != nil {
		t.Fatal("selected signup HTTP accepted absent native graph")
	}
}

func TestRegistrationVerificationHTTPRequiresOwnedDependencies(t *testing.T) {
	if h, err := composeRegistrationVerificationHTTP(StoreConfiguration{}, nil); err != nil || h != nil {
		t.Fatal("unselected confirmation HTTP acquired dependencies", err)
	}
	c := StoreConfiguration{HTTPRegistrationVerification: &HTTPRegistrationVerificationConfiguration{}}
	if h, err := composeRegistrationVerificationHTTP(c, nil); err == nil || h != nil {
		t.Fatal("selected confirmation HTTP accepted absent native graph")
	}
}
