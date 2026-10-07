package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func nativeContributorFixture(t *testing.T) (*Contributor, identity.Command, kernel.OTPAttemptPlan) {
	t.Helper()
	c, legacy, plan, _, _ := admissionFixture(t, time.Now().UTC())
	a, err := c.restoreAttempt(legacy, plan)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := legacy.Feature()
	fields := spec.Fields[:0]
	for _, f := range spec.Fields {
		if !otpField(f.Name) {
			fields = append(fields, f)
		}
	}
	spec.Fields = fields
	cookie, _ := legacy.PreAuthCookie()
	command, plan, err := c.MapPreAuthWithAuthority(context.Background(), a, 3, spec, cookie, AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewContributor(ContributorConfig{Schema: "otp_store", Codec: c, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	return p, command, plan
}

func TestContributorRequiresOriginalNativeAuthority(t *testing.T) {
	p, command, plan := nativeContributorFixture(t)
	if err := p.ValidateOTPAttemptCommand(command, plan); err != nil {
		t.Fatal(err)
	}
	_, legacy, oldPlan, _, _ := admissionFixture(t, time.Now().UTC())
	if p.ValidateOTPAttemptCommand(legacy, oldPlan) == nil {
		t.Fatal("legacy custody gained current authority")
	}
	for _, w := range []kernel.OTPAttemptWork{{}} {
		if _, err := p.RecordOTPAttemptDenial(context.Background(), w); err == nil {
			t.Fatal("zero work reached native comparison")
		}
	}
}

func TestContributorConfigurationAndCustodyAreOwned(t *testing.T) {
	p, command, plan := nativeContributorFixture(t)
	config := ContributorConfig{Schema: "otp_store", Codec: p.codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}}
	owned, err := NewContributor(config)
	if err != nil {
		t.Fatal(err)
	}
	config.LockoutKey[0]++
	config.PreAuthCookieKeys[3][0]++
	delete(config.PreAuthCookieKeys, 3)
	if err := owned.ValidateOTPAttemptCommand(command, plan); err != nil {
		t.Fatal("caller changed retained cookie key", err)
	}
	if owned.lockout.binding() != p.lockout.binding() {
		t.Fatal("caller changed retained lockout key")
	}
	for _, mutate := range []func(*ContributorConfig){
		func(c *ContributorConfig) { c.Schema = "public" },
		func(c *ContributorConfig) { c.Codec = nil },
		func(c *ContributorConfig) { c.Codec = &AttemptCodec{} },
		func(c *ContributorConfig) { c.GlobalAuthorityID = "" },
		func(c *ContributorConfig) { c.UserPolicyNamespace = "" },
		func(c *ContributorConfig) { c.LockoutKey = [32]byte{} },
		func(c *ContributorConfig) { c.PreAuth = sessionpg.Config{} },
		func(c *ContributorConfig) { c.PreAuthCookieKeys = nil },
	} {
		config.PreAuthCookieKeys = map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}
		candidate := config
		mutate(&candidate)
		if got, err := NewContributor(candidate); got != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid deployment profile admitted", err)
		}
	}
	var absent *Contributor
	if absent.ValidateOTPAttemptCommand(command, plan) == nil {
		t.Fatal("nil participant admitted")
	}
	changed := plan
	changed.Mode = kernel.OTPCheck
	if p.ValidateOTPAttemptCommand(command, changed) == nil {
		t.Fatal("unsupported successful-check path admitted")
	}
	foreign := *p
	foreign.global = "other-deployment"
	if foreign.ValidateOTPAttemptCommand(command, plan) == nil {
		t.Fatal("foreign deployment authority admitted")
	}
	for _, value := range []any{config, p} {
		if _, err := json.Marshal(value); !errors.Is(err, otp.ErrSensitiveSerialization) {
			t.Fatal("configuration serialized", err)
		}
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("configuration diagnostic disclosure")
		}
	}
	if _, err := absent.MarshalJSON(); !errors.Is(err, otp.ErrSensitiveSerialization) {
		t.Fatal("nil configuration export admitted")
	}
	if !strings.Contains(fmt.Sprintf("%#v", absent), "redacted") {
		t.Fatal("nil diagnostic changed")
	}
}
