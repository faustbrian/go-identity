package postgres

import (
	"bytes"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOneTapCallbackSessionBindsOriginalFlowAndCommand(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		oauth, original, cookie := oauthSigninMappingFixture(t, csrf)
		selected := identity.FeatureOperation{Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", SchemaID: "oauth-onetap-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
		exact := oauth
		exact.Operation = selected
		exact.Binding.OperationID, exact.Binding.SchemaID = selected.OperationID, selected.SchemaID
		exact.Binding.RecordID = exact.Binding.AnonymousFlowID
		var err error
		exact.Fields, err = OneTapCallbackSessionFields(original)
		if err != nil {
			t.Fatal("freeze prospective One Tap session", err)
		}
		complete, err := identity.NewFeaturePreAuthCommand(exact, cookie)
		if err != nil {
			t.Fatal("construct original One Tap callback", err)
		}
		restored, err := OneTapCallbackSession(complete)
		if err != nil {
			t.Fatal("restore only the selected One Tap session", err)
		}
		want, _, _ := encodeRecord(original)
		got, _, _ := encodeRecord(restored)
		if !bytes.Equal(want, got) {
			t.Fatal("original provider credential, factor, CSRF or validity changed")
		}
		feature, _ := complete.Feature()
		if feature.Binding != exact.Binding || feature.Binding.UserID != "" {
			t.Fatal("session projection replaced the command's original anonymous scope")
		}
		if got, err := OAuthSigninSession(complete); !errors.Is(err, session.ErrInvalidSessionCommand) || got != (session.Session{}) {
			t.Fatal("ordinary OAuth accepted One Tap custody", err)
		}
		for _, mode := range []string{"ordinary OAuth", "foreign flow", "session credential", "metadata only", "wrong proof command"} {
			t.Run(mode, func(t *testing.T) {
				changed := exact
				var command identity.Command
				var err error
				switch mode {
				case "session credential":
					command, err = identity.NewFeatureSessionCommand(changed, cookie)
				case "metadata only":
					command, err = identity.NewFeatureCommand(changed)
				default:
					switch mode {
					case "ordinary OAuth":
						changed = oauth
					case "foreign flow":
						changed.Binding.RecordID = "different-flow"
					case "wrong proof command":
						changed.Binding.CommandID, err = identity.NewCommandID()
						if err != nil {
							t.Fatal(err)
						}
					}
					command, err = identity.NewFeaturePreAuthCommand(changed, cookie)
				}
				if err != nil {
					t.Fatal("construct structurally valid negative fixture", err)
				}
				if got, err := OneTapCallbackSession(command); !errors.Is(err, session.ErrInvalidSessionCommand) || got != (session.Session{}) {
					t.Fatal("One Tap decoded foreign authority", err)
				}
			})
		}
	}
}
