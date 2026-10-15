package session_test

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestPasswordSessionContinuationPreservesOriginalAuthentication(t *testing.T) {
	spec := sessionSpec(t)
	original, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := spec.Authority.Bindings()
	id, _ := identity.NewCommandID()
	c := session.CredentialContinuationSpec{CommandID: id, BeforeAuthorityVersion: a.Credential.Version, BeforeCredentialVersion: spec.Authentication.CredentialVersion}
	next, err := session.ContinuePasswordSession(original, c)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := next.Bindings()
	vector, _ := got.Authority.Bindings()
	if vector.Credential.Version != a.Credential.Version+1 || next.EffectiveCredentialVersion() != spec.Authentication.CredentialVersion+1 {
		t.Fatal("credential successor missing")
	}
	vector.Credential.Version = a.Credential.Version
	if vector != a {
		t.Fatal("unrelated authority changed")
	}
	got.Authority = spec.Authority
	if !reflect.DeepEqual(got, spec) || next.CSRFState() != original.CSRFState() {
		t.Fatal("continuation renewed authentication or changed session")
	}
	retained, ok := next.CredentialContinuation()
	if !ok || retained != c {
		t.Fatal("original command binding lost")
	}
	if original.EffectiveCredentialVersion() != spec.Authentication.CredentialVersion {
		t.Fatal("original record mutated")
	}
	second := c
	second.CommandID, _ = identity.NewCommandID()
	second.BeforeAuthorityVersion++
	second.BeforeCredentialVersion++
	latest, err := session.ContinuePasswordSession(next, second)
	if err != nil || latest.EffectiveCredentialVersion() != spec.Authentication.CredentialVersion+2 {
		t.Fatal("second exact continuation failed", err)
	}
	latestSpec, _ := latest.Bindings()
	if latestSpec.Authentication != spec.Authentication || latestSpec.IssuedAt != spec.IssuedAt || latestSpec.LastActivityAt != spec.LastActivityAt {
		t.Fatal("continued succession rewrote original login")
	}
	reconstructed, err := session.NewContinuedPasswordSession(latestSpec, session.CSRFState{}, second)
	if err != nil || reconstructed.EffectiveCredentialVersion() != latest.EffectiveCredentialVersion() {
		t.Fatal("reconstruction lost current linkage", err)
	}
	if _, err := session.NewContinuedPasswordSession(spec, session.CSRFState{}, c); err == nil {
		t.Fatal("predecessor reconstructed as successor")
	}
	nextSpec := latestSpec
	nextSpec.Version++
	nextSpec.Lookup.Sum[0]++
	remember, _ := spec.Remember.Bindings()
	nextSpec.LastActivityAt = nextSpec.LastActivityAt.Add(remember.RefreshAfter)
	nextAuthority, _ := nextSpec.Authority.Bindings()
	nextAuthority.Session.Version++
	nextSpec.Authority, _ = session.NewAuthoritySnapshot(nextAuthority)
	rotated, err := session.NewContinuedPasswordSession(nextSpec, session.CSRFState{}, second)
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(spec)
	b.CommandID, _ = identity.NewCommandID()
	op := session.RotateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	if _, err := session.NewRotateCommand(b, latest, rotated); err != nil {
		t.Fatal("rotation lost continued linkage", err)
	}
	lossy, _ := session.NewSession(nextSpec)
	if _, err := session.NewRotateCommand(b, latest, lossy); err == nil {
		t.Fatal("rotation accepted dropped continuation")
	}
	for _, mutate := range []func(*session.CredentialContinuationSpec){
		func(c *session.CredentialContinuationSpec) { c.CommandID = "" },
		func(c *session.CredentialContinuationSpec) { c.CommandID = "noncanonical" },
		func(c *session.CredentialContinuationSpec) { c.BeforeAuthorityVersion = 0 },
		func(c *session.CredentialContinuationSpec) { c.BeforeAuthorityVersion = ^uint64(0) },
		func(c *session.CredentialContinuationSpec) { c.BeforeAuthorityVersion++ },
		func(c *session.CredentialContinuationSpec) { c.BeforeCredentialVersion++ },
		func(c *session.CredentialContinuationSpec) { c.BeforeCredentialVersion = ^uint64(0) },
	} {
		bad := c
		mutate(&bad)
		if out, err := session.ContinuePasswordSession(original, bad); err == nil || out != (session.Session{}) {
			t.Fatal("unbound continuation admitted")
		}
	}
	if out, err := session.ContinuePasswordSession(session.Session{}, c); err == nil || out != (session.Session{}) {
		t.Fatal("zero session admitted")
	}
	for _, method := range []string{"oauth", "passkey"} {
		other := spec
		other.Authentication.Proof.Method = method
		record, err := session.NewSession(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.ContinuePasswordSession(record, c); err == nil {
			t.Fatal("unrelated authentication method continued")
		}
	}
	if (session.Session{}).EffectiveCredentialVersion() != 0 {
		t.Fatal("zero session has effective credential")
	}
}

func TestPasswordSessionContinuationEncryptedRestartDoesNotRenew(t *testing.T) {
	for _, withCSRF := range []bool{false, true} {
		t.Run(fmt.Sprint(withCSRF), func(t *testing.T) { testPasswordSessionContinuationCache(t, withCSRF) })
	}
}

func testPasswordSessionContinuationCache(t *testing.T, withCSRF bool) {
	service, request, clock, observed, config, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	if withCSRF {
		key, _ := session.NewCSRFKey(1, []byte(strings.Repeat("k", 32)))
		token, _ := session.NewCSRFToken()
		state, _ := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
		observed.Session, _ = session.NewSessionWithCSRF(spec, state)
	}
	a, _ := spec.Authority.Bindings()
	id, _ := identity.NewCommandID()
	c := session.CredentialContinuationSpec{CommandID: id, BeforeAuthorityVersion: a.Credential.Version, BeforeCredentialVersion: spec.Authentication.CredentialVersion}
	continued, err := session.ContinuePasswordSession(observed.Session, c)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := continued.Bindings()
	observed.Session, observed.Current = continued, current.Authority
	keys, _ := keyring.New(map[string][]byte{"cache-v1": make([]byte, 32)})
	crypto, _ := envelope.NewService(keys)
	profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: time.Minute, MaximumBytes: 32768}
	codec, _ := session.NewEncryptedCacheCodec(service, crypto, profile)
	original, err := service.Get(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := codec.Seal(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{}, session.ErrUnavailable
	}), config)
	cache, _ := session.NewEncryptedCacheCodec(restarted, crypto, profile)
	aad, _ := envelope.NewContext(map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": profile.Issuer, "environment": profile.Environment, "epoch": "1", "audience": config.Audience, "tenant": string(spec.TenantID), "clock-uncertainty": strconv.FormatInt(int64(config.ClockUncertainty), 10)})
	parsed, _ := envelope.ParseEnvelope(blob)
	plain, err := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: parsed, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	schema := []byte(`"Schema":5`)
	if withCSRF {
		schema = []byte(`"Schema":6`)
	}
	for _, bad := range [][]byte{
		bytes.Replace(plain, schema, []byte(`"Schema":1`), 1),
		bytes.Replace(plain, []byte(`"CommandID":"`+string(c.CommandID)+`"`), []byte(`"CommandID":"invalid"`), 1),
		bytes.Replace(plain, []byte(`"BeforeAuthorityVersion":`+strconv.FormatUint(c.BeforeAuthorityVersion, 10)), []byte(`"BeforeAuthorityVersion":0`), 1),
		bytes.Replace(plain, []byte(`"Continuation":{`), []byte(`"Continuation":null,"Continuation":{`), 1),
	} {
		if bytes.Equal(bad, plain) {
			t.Fatal("malformed continuation fixture unchanged")
		}
		enc, err := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: profile.KeyReference, Context: aad})
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := enc.MarshalBinary()
		if got, err := cache.Get(context.Background(), request, wire); got.Authenticated || err != session.ErrUnavailable {
			t.Fatal("malformed authenticated continuation accepted", err)
		}
	}
	warm, err := cache.Get(context.Background(), request, blob)
	retained, ok := warm.Session.CredentialContinuation()
	if err != nil || !warm.Authenticated || !ok || retained != c || warm.Session.EffectiveCredentialVersion() != continued.EffectiveCredentialVersion() || !warm.ValidUntil().Equal(original.ValidUntil()) {
		t.Fatal("cache lost credential continuation or renewed evidence", err)
	}
	if warm.Session.CSRFState() != (session.CSRFState{}) {
		before, _ := continued.CSRFState().Bindings()
		after, _ := warm.Session.CSRFState().Bindings()
		if before != after {
			t.Fatal("cache changed continued synchronizer state")
		}
	} else if withCSRF {
		t.Fatal("cache lost continued synchronizer state")
	}
	b := issueBinding(current)
	b.CommandID, _ = identity.NewCommandID()
	op := session.UpdateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := session.NewUpdateCommand(b, warm.Session, "label")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := command.Update()
	if retained, ok := u.Successor.CredentialContinuation(); !ok || retained != c {
		t.Fatal("metadata update dropped continuation")
	}
	if _, err := restarted.PrepareUpdate(warm, command); err != nil {
		t.Fatal("exact continued caller denied", err)
	}
	dropped, _ := session.NewSession(current)
	lossy, _ := session.NewUpdateCommand(b, dropped, "label")
	if _, err := restarted.PrepareUpdate(warm, lossy); err == nil {
		t.Fatal("lossy continued source substituted for original")
	}
	clock.now = original.ValidUntil()
	if denied, err := cache.Get(context.Background(), request, blob); err != session.ErrUnavailable || denied.Authenticated {
		t.Fatal("continued cache survived expired authority", err)
	}
}
