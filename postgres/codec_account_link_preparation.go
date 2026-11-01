package postgres

import (
	"bytes"
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// Original OAuth custody and the authenticated post-exchange command have
// different keyed claims. Only the retained prepared root profile can select
// executionRequest; ordinary execution must continue matching original intent.
// This does not authenticate output: attachment owns that check before Work.
func accountLinkExecutionRequest(r *reservationState) (claimRequest, error) {
	if r == nil || r.plan == nil {
		return claimRequest{}, invalidPreparation()
	}
	if r.executionRequest == nil {
		if r.plan.accountLinkState != nil || r.preparation != nil {
			return claimRequest{}, invalidPreparation()
		}
		return r.request, nil
	}
	if r.plan.accountLinkState == nil || r.preparation == nil || r.preparation.generation == 0 || r.preparation.generation > r.journal.generation || len(r.preparation.ciphertext) == 0 || len(r.preparation.ciphertext) > maximumPreparationCiphertext || r.request.source == nil || r.executionRequest.source == nil || !bytes.Equal(r.request.safeFields, r.executionRequest.safeFields) || bytes.Equal(r.request.canonical, r.executionRequest.canonical) {
		return claimRequest{}, invalidPreparation()
	}
	original, _, _, ok := r.request.source.AccountLinkPreparationInput()
	final, counters, finalOK := r.executionRequest.source.AccountLinkCounterCommand()
	if !ok || !finalOK || original.Binding != r.plan.binding || final.Binding != original.Binding || original.ProviderID != final.Change.Account.Provider || original.SessionID != final.SessionID || original.SessionVersion != final.SessionVersion || counters.Network != original.Counters.Network || !counters.PreparedAt.Equal(original.Counters.PreparedAt) || !slices.Equal(counters.KeyVersions, original.Counters.KeyVersions) {
		return claimRequest{}, invalidPreparation()
	}
	return *r.executionRequest, nil
}

// Original callback custody stays in the existing keyed claim. Provider output
// will be a separately authenticated preparation attachment, not a replacement
// of this original claim or a different root command scope.
func encodeAccountLinkPreparation(command identity.Command, key [32]byte) (map[string][]byte, error) {
	spec, callback, bearer, ok := command.AccountLinkPreparationInput()
	if !ok {
		return nil, codecError()
	}
	counters, err := encodeAccountLinkCounters(spec.Counters, key)
	if err != nil {
		return nil, err
	}
	payload := map[string][]byte{
		"preparation_profile": cborText("account-link-oauth-v1"),
		"provider_id":         cborText(spec.ProviderID), "provider_configuration_version": cborUint(spec.ProviderConfigVersion),
		"flow_id": cborText(spec.FlowID), "flow_fingerprint": cborBytes(spec.FlowFingerprint[:]),
		"session_id": cborText(spec.SessionID), "session_version": cborUint(spec.SessionVersion),
		"protected_counters": counters,
	}
	err = callback.Use(context.Background(), func(_ context.Context, code, state []byte) error {
		codeDigest, err := commandSecret(key, "account.link.oauth.original-code", code, 1<<20)
		if err != nil {
			return err
		}
		stateDigest, err := commandSecret(key, "account.link.oauth.original-state", state, 86)
		if err != nil {
			return err
		}
		payload["authorization_code"] = cborBytes(codeDigest)
		payload["rp_state"] = cborBytes(stateDigest)
		return nil
	})
	if err != nil {
		return nil, codecError()
	}
	wire := []byte(bearer.Token())
	digest, err := commandSecret(key, "account.link.oauth.original-session", wire, 86)
	clear(wire)
	if err != nil {
		return nil, codecError()
	}
	payload["session_bearer"] = cborBytes(digest)
	return payload, nil
}

func encodeAccountLinkCounters(counters identity.AccountLinkCounterContext, key [32]byte) ([]byte, error) {
	network, err := commandSecret(key, "account.link.counter.network", []byte(counters.Network), 128)
	if err != nil || !postgresExactTime(counters.PreparedAt) {
		return nil, codecError()
	}
	versions := make([][]byte, len(counters.KeyVersions))
	for i, version := range counters.KeyVersions {
		versions[i] = cborUint(uint64(version))
	}
	return cborMap(map[string][]byte{
		"network": cborBytes(network), "prepared_at": cborInt(counters.PreparedAt.UnixMicro()),
		"key_versions": cborArray(versions),
	}), nil
}
