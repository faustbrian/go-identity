package passkeyhttp

import (
	"context"
	"net/http"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

func deliverSigninMFAChallenge(c SigninConfig, w http.ResponseWriter, r *http.Request, s SigninState, out passkey.SigninResult) {
	receipt, b := out.Receipt, out.Receipt.Binding
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	// Native completion is a self-human command after genuine UV verification.
	// Its original browser/ceremony binding is enforced by the borrowed owner;
	// the service-account ingress actor is not the authenticated human actor.
	if receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation != op || b.ValidateFor(op) != nil || b.CommandID != s.request.CommandID || b.TenantID != s.facts.TenantID() || b.RecordID != string(b.CommandID) || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.PolicyVersion != uint64(c.PolicyRevision) || b.CorrelationID != s.request.CorrelationID || receipt.Outcome == identity.CommitOutcomeCommitted && (receipt.Feature.BeforeVersion != 0 || receipt.Feature.AfterVersion != 1) {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		requestDelivery(r).observeCommitted(b.CommandID)
	}
	child, now := out.Challenge, c.Now()
	_, childErr := identity.ParseCommandID(string(child.ID))
	if !c.MFAContinuation || receipt.Outcome != identity.CommitOutcomeCommitted || out.Replayed || childErr != nil || child.ID == b.CommandID || child.Method != "totp" || now.IsZero() || !now.Before(child.ExpiresAt) || child.ExpiresAt.After(now.Add(5*time.Minute)) || out.Session.CommandID != "" || out.Session.Session != (session.Session{}) || out.Session.Token != (session.Token{}) || out.Session.Cookie.Name != "" || out.Session.Cookie.Value != "" || out.CSRF != (session.CSRFToken{}) || !signinFresh(c, s) {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	var token string
	if err := child.Proof.Transfer(r.Context(), func(_ context.Context, wire []byte) error {
		if len(wire) < 32 || !visible(string(wire), 4096) {
			return identityhttp.ErrUnavailable
		}
		token = string(wire)
		return nil
	}); err != nil {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	d := requestDelivery(r)
	d.challenge = token
	d.render(w, r, map[string]any{"signedIn": false, "challengeRequired": true, "commandID": b.CommandID, "commitOutcome": "committed", "challengeID": child.ID, "challengeMethod": child.Method, "challengeExpiresAt": child.ExpiresAt.UTC().Format(time.RFC3339Nano)}, func() bool {
		at := c.Now()
		return signinFresh(c, s) && !at.Before(now) && at.Before(child.ExpiresAt)
	})
}
