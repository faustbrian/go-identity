package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
		result, err := client.Do(request)
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
	callback := o.origin + "/confirm"
	flow, err := issue("signup")
	if err != nil {
		return err
	}
	result, err := call(http.MethodPost, "/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": password, "callbackURL": callback}, hex.EncodeToString(unique[:]), "", nil)
	var signup passwordhttp.SignupResponse
	if err != nil || result.status != 200 || json.Unmarshal(result.body, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(result.cookie) != 0 {
		return errLocalProfile
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
		return errLocalProfile
	}
	result, signed, err = login("incorrect-" + password)
	if err != nil || result.status == 200 || signed.SignedIn || len(result.cookie) != 0 {
		return errLocalProfile
	}
	result, signed, err = login(password)
	if err != nil || result.status != 200 || !signed.SignedIn || signed.CommitOutcome != "committed" || signed.SessionID == "" || len(result.cookie) != 1 {
		return errLocalProfile
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
	_, err = io.WriteString(output, "baseline passed: registration -> captured verification -> verification -> password signin -> authenticated session -> logout -> original session denied\n")
	return err
}

func waitForVerification(ctx context.Context, o options, recipient string) (string, error) {
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
			if err != nil || link.Scheme != "https" || link.Host != origin.Host || link.Path != "/email/confirm" || link.User != nil || link.Fragment != "" {
				return "", errLocalProfile
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
