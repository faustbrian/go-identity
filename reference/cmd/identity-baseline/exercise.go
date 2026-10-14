package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
)

// exerciseBaseline is a consumer of the public HTTPS API and explicit local
// sender destination. It never looks up domain state, seeds users or bypasses
// authority. Candidates, cookies, CSRF and verification tokens stay private.
func exerciseBaseline(ctx context.Context, o options, secrets credentials, output io.Writer) error {
	bounded, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM([]byte(secrets.Certificate)) {
		return errCredentials
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS13}, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 10 * time.Second, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 6 * time.Second}
	defer transport.CloseIdleConnections()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return errLocalProfile
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	type response struct {
		status int
		body   []byte
		header http.Header
		cookie []*http.Cookie
	}
	call := func(method, path string, body any, idempotency, csrf string, retained []*http.Cookie) (response, error) {
		var content io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				return response{}, errLocalProfile
			}
			content = bytes.NewReader(encoded)
		}
		request, err := http.NewRequestWithContext(bounded, method, o.origin+path, content)
		if err != nil {
			return response{}, errLocalProfile
		}
		if method == http.MethodPost {
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", o.origin)
		}
		if idempotency != "" {
			request.Header.Set("Idempotency-Key", idempotency)
		}
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range retained {
			request.AddCookie(cookie)
		}
		requestClient := client
		if len(retained) != 0 {
			// Raw bearer proof must not depend on the jar, or duplicate-cookie
			// rejection could masquerade as authoritative session revocation.
			copy := *client
			copy.Jar = nil
			requestClient = &copy
		}
		result, err := requestClient.Do(request)
		if err != nil {
			return response{}, errLocalProfile
		}
		payload, readErr := io.ReadAll(io.LimitReader(result.Body, 16385))
		closeErr := result.Body.Close()
		if readErr != nil || closeErr != nil || len(payload) > 16384 || result.Header.Get("Cache-Control") != "no-store" {
			return response{}, errLocalProfile
		}
		return response{status: result.StatusCode, body: payload, header: result.Header, cookie: result.Cookies()}, nil
	}
	issue := func(method string) (sessionhttp.PreAuthResponse, error) {
		result, err := call(http.MethodPost, "/v1/session/preauth-issue", map[string]string{"method": method}, "", "", nil)
		var flow sessionhttp.PreAuthResponse
		if err != nil || result.status != 200 || json.Unmarshal(result.body, &flow) != nil || !flow.Issued {
			return flow, errLocalProfile
		}
		return flow, nil
	}
	var unique, candidate [32]byte
	if _, err := rand.Read(unique[:]); err != nil {
		return errLocalProfile
	}
	if _, err := rand.Read(candidate[:]); err != nil {
		return errLocalProfile
	}
	address := "baseline-" + hex.EncodeToString(unique[:16]) + "@example.invalid"
	password := hex.EncodeToString(candidate[:])
	credentialVersion := uint64(1)
	callback := o.origin + "/confirm"
	flow, err := issue("signup")
	if err != nil {
		return err
	}
	result, err := call(http.MethodPost, "/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": password, "callbackURL": callback}, hex.EncodeToString(unique[:]), "", nil)
	var signup passwordhttp.SignupResponse
	if err != nil || result.status != 200 || json.Unmarshal(result.body, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(result.cookie) != 0 {
		return fmt.Errorf("registration status %d: %w", result.status, errLocalProfile)
	}
	login := func(candidate string) (response, passwordhttp.SigninResponse, error) {
		flow, err := issue("password")
		if err != nil {
			return response{}, passwordhttp.SigninResponse{}, err
		}
		result, err := call(http.MethodPost, "/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": candidate, "callbackURL": callback}, "", "", nil)
		var signed passwordhttp.SigninResponse
		if err != nil || json.Unmarshal(result.body, &signed) != nil {
			return response{}, signed, errLocalProfile
		}
		return result, signed, nil
	}
	result, signed, err := login(password)
	if err != nil || result.status == 200 || signed.SignedIn || len(result.cookie) != 0 {
		return errLocalProfile
	}
	token, err := waitForVerification(bounded, o, address)
	if err != nil {
		return err
	}
	command, err := identity.NewCommandID()
	if err != nil {
		return errLocalProfile
	}
	result, err = call(http.MethodPost, "/v1/email/verification-confirm", map[string]string{"token": token, "callback": callback, "commandID": string(command)}, "", "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if err != nil || result.status != 200 || json.Unmarshal(result.body, &confirmed) != nil || !confirmed.Confirmed || confirmed.CommitOutcome != "committed" || len(result.cookie) != 0 {
		return fmt.Errorf("verification status %d: %w", result.status, errLocalProfile)
	}
	result, signed, err = login("incorrect-" + password)
	if err != nil || result.status == 200 || signed.SignedIn || len(result.cookie) != 0 {
		return errLocalProfile
	}
	result, signed, err = login(password)
	if err != nil || result.status != 200 || !signed.SignedIn || signed.CommitOutcome != "committed" || signed.SessionID == "" || len(result.cookie) != 1 {
		return fmt.Errorf("original signin status %d: %w", result.status, errLocalProfile)
	}
	retained := result.cookie
	csrf := result.header.Get("X-CSRF-Token")
	if csrf == "" {
		return errLocalProfile
	}
	result, err = call(http.MethodGet, "/v1/session/get", nil, "", "", nil)
	var read sessionhttp.GetResponse
	if err != nil || result.status != 200 || json.Unmarshal(result.body, &read) != nil || !read.Authenticated || read.Session == nil || read.Session.ID != signed.SessionID {
		return errLocalProfile
	}
	if o.passwordReset && o.operation != "exercise-change" {
		originalSessionID := signed.SessionID
		additional, additionalSignin, err := login(password)
		if err != nil || additional.status != 200 || !additionalSignin.SignedIn || additionalSignin.SessionID == originalSessionID || len(additional.cookie) != 1 {
			return fmt.Errorf("additional original signin status %d: %w", additional.status, errLocalProfile)
		}
		// Confirm the exact saved original bearer is usable before reset, then
		// prove denial after the committed native mutation, independently of jars.
		before, err := call(http.MethodGet, "/v1/session/get", nil, "", "", retained)
		var original sessionhttp.GetResponse
		if err != nil || before.status != 200 || json.Unmarshal(before.body, &original) != nil || !original.Authenticated {
			return errLocalProfile
		}
		resetRequest := func(identifier string, label string) (passwordhttp.ResetRequestResponse, map[string]any, string, error) {
			command, err := identity.NewCommandID()
			if err != nil {
				return passwordhttp.ResetRequestResponse{}, nil, "", errLocalProfile
			}
			body := map[string]any{"commandID": string(command), "identifier": identifier, "callbackURL": o.origin + "/reset"}
			key := label + hex.EncodeToString(unique[:])
			response, err := call(http.MethodPost, "/v1/password/reset-request", body, key, "", nil)
			var accepted passwordhttp.ResetRequestResponse
			if err != nil || response.status != 200 || json.Unmarshal(response.body, &accepted) != nil || !accepted.Accepted || accepted.CommitOutcome != "committed" || len(response.cookie) != 0 {
				return accepted, nil, "", fmt.Errorf("reset request status %d: %w", response.status, errLocalProfile)
			}
			return accepted, body, key, nil
		}
		if _, _, _, err := resetRequest("missing-"+address, "reset-missing-"); err != nil {
			return err
		}
		accepted, requested, requestKey, err := resetRequest(address, "reset-known-")
		if err != nil {
			return err
		}
		retry, err := call(http.MethodPost, "/v1/password/reset-request", requested, requestKey, "", nil)
		var retried passwordhttp.ResetRequestResponse
		if err != nil || retry.status != 200 || json.Unmarshal(retry.body, &retried) != nil || !retried.Accepted || retried.CommandID != accepted.CommandID || retried.CommitOutcome != "committed" {
			return fmt.Errorf("reset request replay status %d: %w", retry.status, errLocalProfile)
		}
		resetToken, err := waitForBaselineLink(bounded, o, address, "/password/reset")
		if err != nil {
			return err
		}
		inspect := func(want bool) error {
			response, err := call(http.MethodPost, "/v1/password/reset/inspect", map[string]string{"token": resetToken}, "", "", nil)
			var inspected passwordhttp.ResetInspectResponse
			var fields map[string]json.RawMessage
			if err != nil || response.status != 200 || json.Unmarshal(response.body, &inspected) != nil || json.Unmarshal(response.body, &fields) != nil || len(fields) != 1 || inspected.Valid != want || len(response.cookie) != 0 {
				return fmt.Errorf("reset inspection status %d: %w", response.status, errLocalProfile)
			}
			return nil
		}
		for range 2 {
			if err := inspect(true); err != nil {
				return err
			}
		}
		var replacement [32]byte
		if _, err := rand.Read(replacement[:]); err != nil {
			return errLocalProfile
		}
		newPassword := hex.EncodeToString(replacement[:])
		completeID, err := identity.NewCommandID()
		if err != nil {
			return errLocalProfile
		}
		completion := map[string]any{"commandID": string(completeID), "token": resetToken, "newPassword": newPassword}
		for range 2 {
			response, err := call(http.MethodPost, "/v1/password/reset-complete", completion, "", "", nil)
			var completed passwordhttp.ResetCompleteResponse
			if err != nil || response.status != 200 || json.Unmarshal(response.body, &completed) != nil || !completed.Completed || completed.CommitOutcome != "committed" || !completed.SessionsRevoked || completed.CredentialVersion != 2 || len(response.cookie) != 0 {
				return fmt.Errorf("reset completion status %d: %w", response.status, errLocalProfile)
			}
		}
		conflict := map[string]any{"commandID": string(completeID), "token": resetToken, "newPassword": newPassword + "-changed"}
		conflicted, err := call(http.MethodPost, "/v1/password/reset-complete", conflict, "", "", nil)
		var failedCompletion passwordhttp.ResetCompleteResponse
		if err != nil || conflicted.status != 409 || json.Unmarshal(conflicted.body, &failedCompletion) != nil || failedCompletion.Completed || len(conflicted.cookie) != 0 {
			return fmt.Errorf("changed reset replay status %d: %w", conflicted.status, errLocalProfile)
		}
		anotherID, err := identity.NewCommandID()
		if err != nil {
			return errLocalProfile
		}
		completion["commandID"] = string(anotherID)
		used, err := call(http.MethodPost, "/v1/password/reset-complete", completion, "", "", nil)
		failedCompletion = passwordhttp.ResetCompleteResponse{}
		if err != nil || used.status != 403 || json.Unmarshal(used.body, &failedCompletion) != nil || failedCompletion.Completed || len(used.cookie) != 0 {
			return fmt.Errorf("consumed reset under new command status %d: %w", used.status, errLocalProfile)
		}
		if err := inspect(false); err != nil {
			return err
		}
		denied, err := call(http.MethodGet, "/v1/session/get", nil, "", "", retained)
		original = sessionhttp.GetResponse{}
		if err != nil || denied.status != 200 || json.Unmarshal(denied.body, &original) != nil || original.Authenticated || original.Session != nil {
			return errLocalProfile
		}
		denied, err = call(http.MethodGet, "/v1/session/get", nil, "", "", additional.cookie)
		original = sessionhttp.GetResponse{}
		if err != nil || denied.status != 200 || json.Unmarshal(denied.body, &original) != nil || original.Authenticated || original.Session != nil {
			return fmt.Errorf("additional original session revocation status %d: %w", denied.status, errLocalProfile)
		}
		old, failed, err := login(password)
		if err != nil || old.status == 200 || failed.SignedIn || len(old.cookie) != 0 {
			return errLocalProfile
		}
		result, signed, err = login(newPassword)
		if err != nil || result.status != 200 || !signed.SignedIn || signed.CommitOutcome != "committed" || len(result.cookie) != 1 || signed.SessionID == originalSessionID {
			return errLocalProfile
		}
		retained, csrf = result.cookie, result.header.Get("X-CSRF-Token")
		if csrf == "" {
			return errLocalProfile
		}
		// The generic combined exercise continues from this successful reset,
		// not from the predecessor credential already proven unusable above.
		password, credentialVersion = newPassword, 2
	}
	if o.passwordChange && o.operation != "exercise-reset" {
		first := retained
		additional, second, err := login(password)
		if err != nil || additional.status != 200 || !second.SignedIn || second.SessionID == signed.SessionID || len(additional.cookie) != 1 {
			return fmt.Errorf("change second-session signin status %d: %w", additional.status, errLocalProfile)
		}
		csrf = additional.header.Get("X-CSRF-Token")
		verify := func(candidate, purpose string, token string) (passwordhttp.VerificationResponse, response, error) {
			result, err := call(http.MethodPost, "/v1/password/verify", map[string]string{"password": candidate, "purpose": purpose, "action": "identity.password.change", "audience": "local-password-change"}, "", token, nil)
			var verified passwordhttp.VerificationResponse
			if err != nil || json.Unmarshal(result.body, &verified) != nil || len(result.cookie) != 0 {
				return verified, result, errLocalProfile
			}
			return verified, result, nil
		}
		for _, denied := range []struct{ candidate, purpose, csrf string }{
			{password, "identity.password.verify", ""},
			{"incorrect-" + password, "identity.password.verify", csrf},
			{password, "unselected-purpose", csrf},
		} {
			verified, response, err := verify(denied.candidate, denied.purpose, denied.csrf)
			if err != nil || response.status == 200 || verified.Verified || verified.Proof != nil {
				return fmt.Errorf("change verification denial status %d: %w", response.status, errLocalProfile)
			}
		}
		before, err := call(http.MethodGet, "/v1/session/get", nil, "", "", nil)
		var current sessionhttp.GetResponse
		if err != nil || before.status != 200 || json.Unmarshal(before.body, &current) != nil || !current.Authenticated || current.Session == nil {
			return errLocalProfile
		}
		verified, checked, err := verify(password, "identity.password.verify", csrf)
		if err != nil || checked.status != 200 || !verified.Verified || verified.Proof == nil || verified.CommitOutcome != "committed" {
			return fmt.Errorf("fresh password verification status %d: %w", checked.status, errLocalProfile)
		}
		after, err := call(http.MethodGet, "/v1/session/get", nil, "", "", nil)
		var unchanged sessionhttp.GetResponse
		if err != nil || after.status != 200 || json.Unmarshal(after.body, &unchanged) != nil || !unchanged.Authenticated || unchanged.Session == nil || *current.Session != *unchanged.Session {
			return fmt.Errorf("verification changed original session: %w", errLocalProfile)
		}
		var replacement [32]byte
		if _, err := rand.Read(replacement[:]); err != nil {
			return errLocalProfile
		}
		newPassword := hex.EncodeToString(replacement[:])
		change := map[string]string{"proofID": verified.Proof.ProofID, "newPassword": newPassword}
		key := "change-" + hex.EncodeToString(unique[:])
		missing, err := call(http.MethodPost, "/v1/password/change", change, key, "", nil)
		if err != nil || missing.status != 403 || len(missing.cookie) != 0 {
			return fmt.Errorf("password change CSRF denial status %d: %w", missing.status, errLocalProfile)
		}
		reused, err := call(http.MethodPost, "/v1/password/change", map[string]string{"proofID": verified.Proof.ProofID, "newPassword": password}, key+"-reuse", csrf, nil)
		if err != nil || reused.status == 200 || len(reused.cookie) != 0 {
			return fmt.Errorf("password reuse denial status %d: %w", reused.status, errLocalProfile)
		}
		changed, err := call(http.MethodPost, "/v1/password/change", change, key, csrf, nil)
		var complete passwordhttp.ChangeResponse
		if err != nil || changed.status != 200 || json.Unmarshal(changed.body, &complete) != nil || !complete.Changed || complete.CommitOutcome != "committed" || complete.CredentialVersion != credentialVersion+1 || !complete.AuthorityInvalidated || complete.Recovery == nil || len(changed.cookie) != 0 {
			var observed passwordhttp.ChangeResponse
			_ = json.Unmarshal(changed.body, &observed)
			return fmt.Errorf("password change completion status %d (original command=%t, unknown=%t, rollback=%t): %w", changed.status, observed.CommandID != "", observed.CommitOutcome == "unknown", observed.CommitOutcome == "not_committed", errLocalProfile)
		}
		replayed, err := call(http.MethodPost, "/v1/password/change", change, key, csrf, nil)
		var denied passwordhttp.ChangeResponse
		if err != nil || replayed.status != 401 || json.Unmarshal(replayed.body, &denied) != nil || denied.Changed || len(replayed.cookie) != 0 {
			return fmt.Errorf("revoked source change replay status %d: %w", replayed.status, errLocalProfile)
		}
		for _, cookies := range [][]*http.Cookie{first, additional.cookie} {
			result, err := call(http.MethodGet, "/v1/session/get", nil, "", "", cookies)
			var denied sessionhttp.GetResponse
			if err != nil || result.status != 200 || json.Unmarshal(result.body, &denied) != nil || denied.Authenticated || denied.Session != nil {
				return fmt.Errorf("changed-password original session remained valid: %w", errLocalProfile)
			}
		}
		old, failed, err := login(password)
		if err != nil || old.status == 200 || failed.SignedIn || len(old.cookie) != 0 {
			return errLocalProfile
		}
		result, signed, err = login(newPassword)
		if err != nil || result.status != 200 || !signed.SignedIn || signed.CommitOutcome != "committed" || len(result.cookie) != 1 {
			return fmt.Errorf("changed-password signin status %d: %w", result.status, errLocalProfile)
		}
		// A previously consumed/session-bound proof cannot authorize another
		// change under the new credential/session, even with its fresh CSRF.
		stale, err := call(http.MethodPost, "/v1/password/change", map[string]string{"proofID": verified.Proof.ProofID, "newPassword": newPassword + "-stale"}, key+"-stale", result.header.Get("X-CSRF-Token"), nil)
		if err != nil || stale.status == 200 || len(stale.cookie) != 0 {
			return fmt.Errorf("stale password-change proof status %d: %w", stale.status, errLocalProfile)
		}
		retained, csrf = result.cookie, result.header.Get("X-CSRF-Token")
	}
	result, err = call(http.MethodPost, "/v1/session/signout", map[string]any{}, "", "", nil)
	if err != nil || result.status != 403 || len(result.cookie) != 0 {
		return errLocalProfile
	}
	result, err = call(http.MethodPost, "/v1/session/signout", map[string]any{}, "", csrf, nil)
	var logout sessionhttp.SignOutResponse
	if err != nil || result.status != 200 || json.Unmarshal(result.body, &logout) != nil || !logout.SignedOut || logout.CommitOutcome != "committed" {
		return errLocalProfile
	}
	// The jar's cookie was cleared by signout. Replay the saved original bearer
	// explicitly so this proves primary revocation, not just client deletion.
	result, err = call(http.MethodGet, "/v1/session/get", nil, "", "", retained)
	read = sessionhttp.GetResponse{}
	if err != nil || result.status != 200 || json.Unmarshal(result.body, &read) != nil || read.Authenticated || read.Session != nil {
		return errLocalProfile
	}
	message := "baseline passed: registration -> captured verification -> verification -> password signin -> authenticated session -> logout -> original session denied\n"
	if o.passwordReset {
		message = "reset passed: request -> captured delivery -> repeated read-only inspection -> completion -> old password denied -> new password signin -> original session denied -> logout\n"
	}
	if o.passwordChange && o.operation != "exercise-reset" {
		message = "change passed: fresh password verification -> change -> both original sessions denied -> old password denied -> new password signin -> stale proof denied -> logout -> original session denied\n"
	}
	if o.passwordReset && o.passwordChange && o.operation == "exercise" {
		message = "reset and change passed: reset -> replacement-password signin -> fresh verification -> change -> original sessions denied -> replacement-password signin -> logout -> original session denied\n"
	}
	_, err = io.WriteString(output, message)
	return err
}

func waitForVerification(ctx context.Context, o options, recipient string) (string, error) {
	return waitForBaselineLink(ctx, o, recipient, "/email/confirm")
}

func waitForBaselineLink(ctx context.Context, o options, recipient, expectedPath string) (string, error) {
	mailbox, err := openLocalMailbox(o.directory)
	if err != nil {
		return "", err
	}
	defer mailbox.Close()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		directory, err := mailbox.root.Open(".")
		if err != nil {
			return "", errLocalProfile
		}
		entries, readErr := directory.ReadDir(1025)
		closeErr := directory.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 1024 {
			return "", errLocalProfile
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			content, err := mailbox.read(entry.Name())
			var message mailboxMessage
			if err != nil || json.Unmarshal(content, &message) != nil {
				return "", errLocalProfile
			}
			if message.Recipient != recipient || !message.ValidUntil.After(time.Now()) {
				continue
			}
			link, err := url.Parse(message.Body)
			origin, _ := url.Parse(o.origin)
			if err != nil || link.Scheme != "https" || link.Host != origin.Host || link.User != nil || link.Fragment != "" || link.Path != "/email/confirm" && link.Path != "/password/reset" {
				return "", errLocalProfile
			}
			if link.Path != expectedPath {
				continue
			}
			tokens := link.Query()["token"]
			if len(tokens) != 1 || tokens[0] == "" || len(tokens[0]) > 4096 {
				return "", errLocalProfile
			}
			return tokens[0], nil
		}
		select {
		case <-ctx.Done():
			return "", errLocalProfile
		case <-timer.C:
		}
	}
}
