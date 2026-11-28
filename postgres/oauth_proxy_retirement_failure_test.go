package postgres

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestOAuthProxyAlreadyRetiredFailureRetainsExactNoChangeTerminal(t *testing.T) {
	for _, kind := range []OAuthProxyRetirementKind{OAuthProxyRetireProduction, OAuthProxyRetirePreview} {
		w, owner, command := proxyRetirementWork(t, kind)
		var conflict identity.ConflictError
		err := w.MarkOAuthProxyOriginAlreadyRetired(t.Context(), owner, command)
		if !errors.As(err, &conflict) || w.state.featureFailure != FeatureFailureOAuthProxyAlreadyRetired || w.state.sqlStarted {
			t.Fatal("exact native Apply did not stage only the closed no-change terminal", err)
		}
		q, err := prepareClaim(command, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		result := featureOutcome(proxyRetirementBinding(), q.feature, identity.CommitOutcomeNotCommitted, 0)
		wire, err := encodeJournalResultFailure(q, result, FeatureFailureOAuthProxyAlreadyRetired, "conflict")
		if err != nil {
			t.Fatal("retirement conflict was not encodable", err)
		}
		got, code, err := decodeJournalResultFailure(q, wire, "conflict")
		if err != nil || got.Binding != result.Binding || got.Outcome != identity.CommitOutcomeNotCommitted || code != FeatureFailureOAuthProxyAlreadyRetired {
			t.Fatal("the same original no-change result did not survive replay", err)
		}
		for _, badClass := range []string{"committed", "denied", "dependency-failure", ""} {
			if _, _, err := decodeJournalResultFailure(q, wire, badClass); err == nil {
				t.Fatal("retirement detail escaped the no-change conflict class", badClass)
			}
		}
		otherQ, otherResult := featureFailureResult(t)
		if _, err := encodeJournalResultFailure(otherQ, otherResult, FeatureFailureOAuthProxyAlreadyRetired, "conflict"); err == nil {
			t.Fatal("another feature encoded the retirement detail")
		}
	}
}

func TestOAuthProxyAlreadyRetiredFailureCannotComeFromForeignWork(t *testing.T) {
	w, owner, command := proxyRetirementWork(t, OAuthProxyRetireProduction)
	w.state.featureApplying = false
	if err := w.MarkOAuthProxyOriginAlreadyRetired(t.Context(), owner, command); err == nil || w.state.featureFailure != 0 {
		t.Fatal("a returned invocation staged a new terminal result", err)
	}
}
