package impersonationpostgres

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
	"github.com/faustbrian/go-identity/impersonation"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestImpersonationCustodyRequestRoundTrip(t *testing.T) {
	ctx := context.Background()
	service, provider := newCustodyTestService(t)
	original := custodyTestOriginal(t)
	id := impersonation.GrantID("AQEBAQEBAQEBAQEBAQEBAQ")
	encoded, err := sealRequest(ctx, service, "custody-v1", id, original)
	if err != nil {
		t.Fatal("seal original request", err)
	}
	if len(encoded) > 64<<10 || bytes.Contains(encoded, []byte(original.request.Reason().StorageText())) {
		t.Fatal("ciphertext is oversized or contains the reason")
	}
	opened, err := openRequest(ctx, service, original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), original.request.Digest(), encoded)
	if err != nil {
		t.Fatal("open original request", err)
	}
	if opened.request.Digest() != original.request.Digest() || opened.request.Target().Version() != 5 || opened.request.Policy().ID() != "support" || opened.request.Policy().Version() != 9 || opened.request.Duration() != 3*time.Minute || opened.request.Reason().StorageText() != original.request.Reason().StorageText() || opened.requesterAuthorityVersion != 7 || opened.requesterUserVersion != 11 {
		t.Fatal("opening changed exact typed intent or original requester versions")
	}
	if got := opened.request.Scope().Permissions(); len(got) != 2 || got[0] != "orders:read" || got[1] != "users:read" {
		t.Fatal("scope was not preserved canonically")
	}
	for _, value := range provider.binding.Values() {
		if strings.Contains(value, original.request.Reason().StorageText()) {
			t.Fatal("plaintext reason entered nonsecret AAD")
		}
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, opened), original.request.Reason().StorageText()) {
			t.Fatal("original request formatting disclosed reason")
		}
	}
	if value, err := json.Marshal(opened); err != nil || bytes.Contains(value, []byte(original.request.Reason().StorageText())) {
		t.Fatal("original request JSON disclosed reason")
	}
}

func TestImpersonationCustodyRequestRejectsSubstitution(t *testing.T) {
	ctx := context.Background()
	service, _ := newCustodyTestService(t)
	original := custodyTestOriginal(t)
	id := impersonation.GrantID("AQEBAQEBAQEBAQEBAQEBAQ")
	encoded, err := sealRequest(ctx, service, "custody-v1", id, original)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tenant", "grant", "requester", "target", "digest", "tamper", "truncated", "oversized", "missing"} {
		t.Run(name, func(t *testing.T) {
			tenant, grant, requester, target, digest := original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), original.request.Digest()
			selected := bytes.Clone(encoded)
			switch name {
			case "tenant":
				tenant = "foreign-tenant"
			case "grant":
				grant = "AgICAgICAgICAgICAgICAg"
			case "requester":
				requester = "foreign-requester"
			case "target":
				target = "foreign-target"
			case "digest":
				digest[0] ^= 1
			case "tamper":
				selected[len(selected)-1] ^= 1
			case "truncated":
				selected = selected[:len(selected)-1]
			case "oversized":
				selected = make([]byte, (64<<10)+1)
			case "missing":
				selected = nil
			}
			opened, err := openRequest(ctx, service, tenant, grant, requester, target, digest, selected)
			if err == nil || opened.request.Digest() != ([32]byte{}) || opened.requesterAuthorityVersion != 0 || opened.requesterUserVersion != 0 {
				t.Fatal("invalid custody exposed original intent")
			}
			assertCustodyTestRedacted(t, err, original.request.Reason().StorageText())
		})
	}
}

func TestImpersonationCustodyRequestRejectsAuthenticatedMalformedPlaintext(t *testing.T) {
	ctx := context.Background()
	service, provider := newCustodyTestService(t)
	original := custodyTestOriginal(t)
	id := impersonation.GrantID("AQEBAQEBAQEBAQEBAQEBAQ")
	encoded, err := sealRequest(ctx, service, "custody-v1", id, original)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	binding := provider.binding
	canonical, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: binding})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	for _, test := range []struct{ name, old, replacement string }{
		{"unknown-version", `"version":1`, `"version":2`},
		{"missing-authority", `"requester_authority_version":7`, `"requester_authority_version":0`},
		{"missing-account-version", `"requester_user_version":11`, `"requester_user_version":0`},
		{"changed-target-version", `"target_version":5`, `"target_version":6`},
		{"changed-policy", `"policy_version":9`, `"policy_version":10`},
		{"changed-duration", `"duration_ns":180000000000`, `"duration_ns":120000000000`},
		{"changed-reason", `private case context`, `different case context`},
		{"noncanonical-scope", `["orders:read","users:read"]`, `["users:read","orders:read"]`},
		{"duplicate-field", `"version":1`, `"version":1,"version":1`},
		{"unknown-field", `"version":1`, `"version":1,"extra":true`},
		{"noncanonical-whitespace", `"version":1`, `"version": 1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !bytes.Contains(canonical, []byte(test.old)) {
				t.Fatal("mutation did not match custody fixture")
			}
			changed := bytes.Replace(canonical, []byte(test.old), []byte(test.replacement), 1)
			defer clear(changed)
			altered, err := service.Encrypt(ctx, secretenvelope.EncryptRequest{Plaintext: changed, KeyReference: "custody-v1", Context: binding})
			if err != nil {
				t.Fatal(err)
			}
			selected, err := altered.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			opened, err := openRequest(ctx, service, original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), original.request.Digest(), selected)
			if err == nil || opened.request.Digest() != ([32]byte{}) {
				t.Fatal("authenticated malformed or changed intent was accepted")
			}
			assertCustodyTestRedacted(t, err, original.request.Reason().StorageText())
		})
	}
	for _, plaintext := range [][]byte{append(bytes.Clone(canonical), '\n'), append(bytes.Clone(canonical), []byte(`{}`)...), bytes.Repeat([]byte(" "), (32<<10)+1)} {
		altered, err := service.Encrypt(ctx, secretenvelope.EncryptRequest{Plaintext: plaintext, KeyReference: "custody-v1", Context: binding})
		clear(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := altered.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openRequest(ctx, service, original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), original.request.Digest(), selected); err == nil {
			t.Fatal("noncanonical, trailing or oversized plaintext was accepted")
		}
	}
}

func TestImpersonationCustodyApprovalReasonBindsActionAndApprover(t *testing.T) {
	ctx := context.Background()
	service, provider := newCustodyTestService(t)
	original := custodyTestOriginal(t)
	id := impersonation.GrantID("AQEBAQEBAQEBAQEBAQEBAQ")
	requestEncoded, err := sealRequest(ctx, service, "custody-v1", id, original)
	if err != nil {
		t.Fatal(err)
	}
	requestBinding := provider.binding
	reason, err := impersonation.NewReason("private approval case")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := sealApprovalReason(ctx, service, "custody-v1", original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), "approver", original.request.Digest(), reason)
	if err != nil {
		t.Fatal("seal approval reason", err)
	}
	approvalBinding := provider.binding
	envelope, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: approvalBinding})
	if err != nil {
		t.Fatal("open approval at exact owner", err)
	}
	defer clear(plaintext)
	var opened struct {
		Version int    `json:"version"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(plaintext, &opened); err != nil || opened.Version != 1 || opened.Reason != reason.StorageText() {
		t.Fatal("approval reason round trip changed")
	}
	if bytes.Contains(encoded, []byte(reason.StorageText())) {
		t.Fatal("approval ciphertext exposed reason")
	}
	for _, binding := range []secretenvelope.Context{requestBinding, approvalBinding} {
		for _, value := range binding.Values() {
			if strings.Contains(value, reason.StorageText()) {
				t.Fatal("approval reason entered nonsecret AAD")
			}
		}
	}
	if _, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: requestBinding}); err == nil {
		t.Fatal("approval reason substituted for request")
	}
	requestEnvelope, err := secretenvelope.ParseEnvelope(requestEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: requestEnvelope, Context: approvalBinding}); err == nil {
		t.Fatal("request substituted for approval reason")
	}
	for name, value := range approvalBinding.Values() {
		values := approvalBinding.Values()
		values[name] = value + "-wrong"
		wrong, err := secretenvelope.NewContext(values)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: wrong}); err == nil {
			t.Fatal("approval binding field not authenticated")
		}
	}
	if approvalBinding.Values()["approver"] != "approver" {
		t.Fatal("approval AAD does not identify exact approver")
	}
}

func TestImpersonationCustodyRejectsInvalidInputsAndRedactsProviderFailures(t *testing.T) {
	ctx := context.Background()
	service, provider := newCustodyTestService(t)
	original := custodyTestOriginal(t)
	id := impersonation.GrantID("AQEBAQEBAQEBAQEBAQEBAQ")
	for _, changed := range []originalRequest{{}, {request: original.request, requesterUserVersion: 11}, {request: original.request, requesterAuthorityVersion: 7}} {
		if encoded, err := sealRequest(ctx, service, "custody-v1", id, changed); err == nil || len(encoded) != 0 {
			t.Fatal("invalid original request sealed")
		}
	}
	if provider.calls != 0 {
		t.Fatal("invalid original called key provider")
	}
	for _, approver := range []identity.UserID{"", original.request.Actor().User(), original.request.Target().User()} {
		if encoded, err := sealApprovalReason(ctx, service, "custody-v1", original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), approver, original.request.Digest(), original.request.Reason()); err == nil || len(encoded) != 0 {
			t.Fatal("invalid approval owner sealed")
		}
	}
	if provider.calls != 0 {
		t.Fatal("invalid approval called key provider")
	}
	provider.failure = errors.New("sensitive provider diagnostic")
	if encoded, err := sealRequest(ctx, service, "custody-v1", id, original); err == nil || len(encoded) != 0 {
		t.Fatal("failed provider produced custody")
	} else {
		assertCustodyTestRedacted(t, err, "sensitive provider diagnostic", original.request.Reason().StorageText(), "custody-v1")
	}
	provider.failure = nil
	encoded, err := sealRequest(ctx, service, "custody-v1", id, original)
	if err != nil {
		t.Fatal(err)
	}
	provider.failure = errors.New("sensitive provider diagnostic")
	if _, err := openRequest(ctx, service, original.request.Tenant(), id, original.request.Actor().User(), original.request.Target().User(), original.request.Digest(), encoded); err == nil {
		t.Fatal("failed provider opened custody")
	} else {
		assertCustodyTestRedacted(t, err, "sensitive provider diagnostic", original.request.Reason().StorageText(), "custody-v1")
	}
}

func TestImpersonationCustodyPreservesMaximumTypedInputs(t *testing.T) {
	ctx := context.Background()
	service, _ := newCustodyTestService(t)
	original := custodyTestOriginal(t)
	input := original.request.Input()
	permissions := make([]string, 64)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("%02d", i) + strings.Repeat("<\\", 63)
	}
	var err error
	input.Scope, err = impersonation.NewScope(permissions)
	if err != nil {
		t.Fatal(err)
	}
	input.Reason, err = impersonation.NewReason(strings.Repeat("\x00", 1024))
	if err != nil {
		t.Fatal(err)
	}
	original.request, err = impersonation.NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	id := impersonation.GrantID("AQEBAQEBAQEBAQEBAQEBAQ")
	encoded, err := sealRequest(ctx, service, "custody-v1", id, original)
	if err != nil {
		t.Fatal("full typed request exceeded custody budget", err)
	}
	opened, err := openRequest(ctx, service, input.Tenant, id, input.Actor.User(), input.Target.User(), original.request.Digest(), encoded)
	if err != nil || opened.request.Digest() != original.request.Digest() {
		t.Fatal("maximum typed request did not round trip", err)
	}
}

type custodyTestProvider struct {
	delegate *keyring.Provider
	binding  secretenvelope.Context
	failure  error
	calls    int
}

func (p *custodyTestProvider) GenerateDataKey(ctx context.Context, key string, binding secretenvelope.Context) (secretenvelope.DataKey, error) {
	p.calls++
	p.binding = binding
	if p.failure != nil {
		return secretenvelope.DataKey{}, p.failure
	}
	return p.delegate.GenerateDataKey(ctx, key, binding)
}

func (p *custodyTestProvider) DecryptDataKey(ctx context.Context, key string, wrapped []byte, binding secretenvelope.Context) ([]byte, error) {
	p.calls++
	p.binding = binding
	if p.failure != nil {
		return nil, p.failure
	}
	return p.delegate.DecryptDataKey(ctx, key, wrapped, binding)
}

func newCustodyTestService(t *testing.T) (*secretenvelope.Service, *custodyTestProvider) {
	t.Helper()
	provider, err := keyring.New(map[string][]byte{"custody-v1": bytes.Repeat([]byte{0x19}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	recording := &custodyTestProvider{delegate: provider}
	service, err := secretenvelope.NewService(recording)
	if err != nil {
		t.Fatal(err)
	}
	return service, recording
}

func custodyTestOriginal(t *testing.T) originalRequest {
	t.Helper()
	actor, err := impersonation.NewActor("tenant", "requester")
	if err != nil {
		t.Fatal(err)
	}
	target, err := impersonation.NewTarget("tenant", "target", 5)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := impersonation.NewScope([]string{"users:read", "orders:read"})
	if err != nil {
		t.Fatal(err)
	}
	reason, err := impersonation.NewReason("private case context")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := impersonation.NewPolicy("support", 9)
	if err != nil {
		t.Fatal(err)
	}
	request, err := impersonation.NewRequest(impersonation.RequestInput{Tenant: "tenant", Actor: actor, Target: target, Scope: scope, Reason: reason, Duration: 3 * time.Minute, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	return originalRequest{request: request, requesterAuthorityVersion: 7, requesterUserVersion: 11}
}

func assertCustodyTestRedacted(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, err), secret) {
				t.Fatal("custody diagnostic disclosed protected input")
			}
		}
	}
}
