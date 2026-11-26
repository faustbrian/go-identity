package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOneTapCallbackCommandIsStableAndBoundToOriginalStart(t *testing.T) {
	startID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	start := identity.CommandBinding{
		CommandID: startID, CorrelationID: string(startID), TenantID: "tenant-a",
		ActorID: "native-service", ActorKind: authorization.SubjectServiceAccount,
		OperationID: "identity.oauth.onetap-start", SchemaID: "oauth-onetap-start-v1", SchemaVersion: 1,
		AnonymousFlowID: string(flow), RecordID: string(flow), PolicyID: "one-tap", PolicyVersion: 1,
	}
	callback, err := oneTapCallbackBinding(start)
	if err != nil {
		t.Fatal(err)
	}
	want := start
	want.OperationID, want.SchemaID = "identity.oauth.onetap-callback", "oauth-onetap-callback-v1"
	want.CommandID = callback.CommandID
	if callback != want || callback.CommandID == startID {
		t.Fatal("derived command replaced original tenant/actor/flow, correlation or policy")
	}
	if _, err := identity.ParseCommandID(string(callback.CommandID)); err != nil {
		t.Fatal("derived command is not a canonical opaque identifier", err)
	}
	if repeated, err := oneTapCallbackBinding(start); err != nil || repeated != callback {
		t.Fatal("same original flow got a different recovery identity", err)
	}
	for _, modify := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "tenant-b" },
		func(b *identity.CommandBinding) {
			b.CommandID, _ = identity.NewCommandID()
			b.CorrelationID = string(b.CommandID)
		},
		func(b *identity.CommandBinding) {
			other, _ := identity.NewPreAuthTransactionID()
			b.RecordID, b.AnonymousFlowID = string(other), string(other)
		},
	} {
		changed := start
		modify(&changed)
		other, err := oneTapCallbackBinding(changed)
		if err != nil || other.CommandID == callback.CommandID {
			t.Fatal("foreign tenant, start or flow reused callback identity", err)
		}
	}
	for _, modify := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.CorrelationID = "foreign-correlation" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.oauth.onetap-callback" },
		func(b *identity.CommandBinding) { b.RecordID = "foreign-flow" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
	} {
		changed := start
		modify(&changed)
		if got, err := oneTapCallbackBinding(changed); err == nil || got != (identity.CommandBinding{}) {
			t.Fatal("nonoriginal One Tap metadata selected a callback command")
		}
	}
}

func TestOneTapCallbackIntentBindsOriginalSubmittedEvidence(t *testing.T) {
	key := [32]byte{1}
	browser := session.TokenDigest{KeyVersion: 3, Sum: [32]byte{7}}
	submission := func() onetap.Callback {
		return onetap.Callback{Origin: "https://identity.example", CSRFCookies: []string{"gcsrf"}, CSRFBody: []string{"gcsrf"},
			Credential: oauth.GoogleCredential{IDToken: []byte("synthetic-local-test")}}
	}
	want := oneTapCallbackIntent(key, browser, submission())
	if want == ([32]byte{}) || oneTapCallbackIntent(key, browser, submission()) != want {
		t.Fatal("same bounded callback intent changed")
	}
	for _, change := range []func(*onetap.Callback){
		func(c *onetap.Callback) { c.Origin = "https://other.example" },
		func(c *onetap.Callback) { c.CSRFCookies[0] += "x" },
		func(c *onetap.Callback) { c.CSRFBody[0] += "x" },
		func(c *onetap.Callback) { c.Credential.IDToken[0] = 'b' },
	} {
		other := submission()
		change(&other)
		if oneTapCallbackIntent(key, browser, other) == want {
			t.Fatal("changed credential or transport evidence retained the original command intent")
		}
	}
	if oneTapCallbackIntent([32]byte{2}, browser, submission()) == want ||
		oneTapCallbackIntent(key, session.TokenDigest{KeyVersion: 4, Sum: browser.Sum}, submission()) == want ||
		oneTapCallbackIntent(key, session.TokenDigest{KeyVersion: browser.KeyVersion, Sum: [32]byte{8}}, submission()) == want {
		t.Fatal("intent was not separated by configured key and original browser proof")
	}
}

func TestOneTapCallbackAuthorityLifetimeNeverExceedsOriginalEvidence(t *testing.T) {
	read := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                           string
		provider, browser, grant, want time.Duration
	}{
		{"original observation", time.Minute, time.Minute, time.Minute, 20 * time.Second},
		{"provider", 12 * time.Second, time.Minute, time.Minute, 12 * time.Second},
		{"original browser", time.Minute, 11 * time.Second, time.Minute, 11 * time.Second},
		{"original grant", time.Minute, time.Minute, 9 * time.Second, 9 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := &oneTapCallbackPhase{readStarted: read.Add(5 * time.Second), grant: oneTapVerifiedCallbackGrant{Grant: kernel.CapabilityPlan{ExpiresAt: read.Add(test.grant)}}}
			p.browserSpec.Transaction.Binding.ExpiresAt = read.Add(test.browser)
			if got := p.validUntil(read.Add(test.provider), read); !got.Equal(read.Add(test.want)) {
				t.Errorf("validity ended at %v, want original bound %v", got, read.Add(test.want))
			}
		})
	}
}
