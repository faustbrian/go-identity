//go:build integration && browser

package reference_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passkeyhttp "github.com/faustbrian/go-identity/http/passkey"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

// The browser owns secure cookies, Origin and navigator.credentials JSON. Only
// the external CTAP devices are simulated; HTTP, migrations and domain owners
// are the same public composition used by the retained signer journeys.
func TestBrowserReferencePasskeySignupManagementRecovery(t *testing.T) {
	for _, transport := range []string{"internal", "usb"} {
		for _, upgrade := range []bool{false, true} {
			t.Run(transport+"/"+map[bool]string{false: "fresh", true: "populated-upgrade"}[upgrade], func(t *testing.T) {
				mux := http.NewServeMux()
				mux.HandleFunc("/identity-browser-fixture", func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					_, _ = io.WriteString(w, "<!doctype html><title>Identity interoperability fixture</title>")
				})
				web := httptest.NewUnstartedServer(mux)
				web.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{referenceBrowserCertificate(t)}}
				web.StartTLS()
				t.Cleanup(web.Close)
				origin := strings.Replace(web.URL, "127.0.0.1", "identity.example", 1)
				selected := standalonePasskeyJourney{origin: origin, management: true, httpManagement: true, enrollment: true, enrollmentTransport: session.CredentialCookie, httpEnrollment: true, sessionDeletion: true, httpDeletion: true}
				selected.consume = func(t *testing.T, ctx context.Context, handler http.Handler, _ []byte) {
					mux.Handle("/", handler)
					browser := startReferencePasskeyBrowser(t, ctx, origin, web.Certificate(), transport)
					proveBrowserPasskeyJourney(t, browser)
				}
				proveReferencePasskeyStandalone(t, upgrade, selected)
			})
		}
	}
}

type referenceBrowserHTTP struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	CSRF   string          `json:"csrf"`
	Cache  string          `json:"cache"`
}

func (b *referencePasskeyBrowser) request(t *testing.T, method, path string, body any, key, csrf string) referenceBrowserHTTP {
	t.Helper()
	raw := b.operation(t, map[string]any{"op": "fetch", "method": method, "path": path, "body": body, "key": key, "csrf": csrf})
	var result referenceBrowserHTTP
	if json.Unmarshal(raw, &result) != nil || result.Status < 100 || len(result.Body) == 0 {
		t.Fatal("invalid browser HTTP observation", method, path)
	}
	return result
}

func proveBrowserPasskeyJourney(t *testing.T, b *referencePasskeyBrowser) {
	t.Helper()
	request := func(path string, body any, key, csrf string) referenceBrowserHTTP {
		return b.request(t, http.MethodPost, path, body, key, csrf)
	}
	flow := func(method string) string {
		t.Helper()
		got := request("/v1/session/preauth-issue", map[string]any{"method": method, "remember": false}, "", "")
		var result struct {
			Issued bool   `json:"issued"`
			Flow   string `json:"flowID"`
		}
		if got.Status != 200 || json.Unmarshal(got.Body, &result) != nil || !result.Issued || result.Flow == "" {
			t.Fatal("browser could not obtain original flow", got.Status)
		}
		return result.Flow
	}
	type optionsResult struct {
		Command string          `json:"commandID"`
		Options json.RawMessage `json:"options"`
	}
	options := func(path string, body any, key, csrf string) optionsResult {
		t.Helper()
		got := request(path, body, key, csrf)
		var result optionsResult
		if got.Status != 200 || json.Unmarshal(got.Body, &result) != nil || result.Command == "" || len(result.Options) == 0 {
			t.Fatal("browser could not obtain original protocol options", path, got.Status)
		}
		return result
	}
	authenticator := func(op string, device int, options json.RawMessage) json.RawMessage {
		t.Helper()
		return b.operation(t, map[string]any{"op": op, "device": device, "options": options})
	}
	command := func() identity.CommandID {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	flowID := flow("passkey-signup")
	creation := options("/v1/passkey/register-options", map[string]any{"mode": "signup", "flowID": flowID}, "browser-signup", "")
	issued := request("/v1/passkey/register-verify", map[string]any{"mode": "signup", "flowID": flowID, "commandID": command(), "ceremonyID": creation.Command, "response": authenticator("create", 0, creation.Options), "label": "Browser first key"}, "", "")
	var signup struct {
		Registered bool `json:"registered"`
		SignedIn   bool `json:"signedIn"`
	}
	if issued.Status != 200 || json.Unmarshal(issued.Body, &signup) != nil || !signup.Registered || !signup.SignedIn || issued.CSRF == "" {
		t.Fatal("browser signup did not issue a real session", issued.Status)
	}
	csrf := issued.CSRF
	var user identity.UserID
	read := func(want bool) {
		t.Helper()
		got := b.request(t, http.MethodGet, "/v1/session/get", nil, "", "")
		var result sessionhttp.GetResponse
		if got.Status != 200 || json.Unmarshal(got.Body, &result) != nil || result.Authenticated != want || got.Cache != "no-store" {
			t.Fatal("browser session read disagrees with committed authority", got.Status, want)
		}
		if want {
			if result.Principal == nil || result.Principal.TenantID != otpTenant || user != "" && result.Principal.UserID != user {
				t.Fatal("browser session selected another identity")
			}
			user = result.Principal.UserID
		}
	}
	read(true)
	inventory := func(want int) []passkeyhttp.CredentialMetadata {
		t.Helper()
		got := b.request(t, http.MethodGet, "/v1/passkey/list", nil, "", "")
		var result passkeyhttp.InventoryResponse
		if got.Status != 200 || json.Unmarshal(got.Body, &result) != nil || len(result.Credentials) != want {
			t.Fatal("browser credential inventory", got.Status, want)
		}
		return result.Credentials
	}
	first := inventory(1)[0]
	// Genuine current-key UV authorizes a distinct resident key on another device.
	intent := map[string]any{"mode": "session", "phase": "assertion", "label": "Browser second key"}
	a := options("/v1/passkey/register-options", intent, "browser-enroll-A", csrf)
	intent["phase"], intent["ceremonyID"], intent["response"] = "registration", a.Command, authenticator("get", 0, a.Options)
	registration := options("/v1/passkey/register-options", intent, "browser-enroll-B", csrf)
	added := request("/v1/passkey/register-verify", map[string]any{"mode": "session", "label": "Browser second key", "commandID": command(), "ceremonyID": registration.Command, "response": authenticator("create", 1, registration.Options)}, "", csrf)
	var enrollment struct {
		Registered bool `json:"registered"`
	}
	if added.Status != 200 || json.Unmarshal(added.Body, &enrollment) != nil || !enrollment.Registered || added.CSRF != "" {
		t.Fatal("browser second-key enrollment", added.Status)
	}
	inventory(2)
	intent = map[string]any{"phase": "options", "referenceID": first.ReferenceID, "expectedVersion": first.Version, "name": "Browser renamed key"}
	a = options("/v1/passkey/update", intent, "browser-rename-A", csrf)
	intent["phase"], intent["ceremonyID"], intent["response"] = "complete", a.Command, authenticator("get", 0, a.Options)
	renamed := request("/v1/passkey/update", intent, "browser-rename-B", csrf)
	var update passkeyhttp.UpdateResponse
	if renamed.Status != 200 || json.Unmarshal(renamed.Body, &update) != nil || update.Credential == nil || update.Credential.Version != first.Version+1 || update.Credential.Label != "Browser renamed key" {
		t.Fatal("browser UV rename", renamed.Status)
	}
	first = *update.Credential
	intent = map[string]any{"phase": "options", "referenceID": first.ReferenceID, "expectedVersion": first.Version}
	if denied := request("/v1/passkey/delete", intent, "browser-remove-denied", strings.Repeat("A", 43)); denied.Status != 403 {
		t.Fatal("browser removal ignored original CSRF", denied.Status)
	}
	a = options("/v1/passkey/delete", intent, "browser-remove-A", csrf)
	intent["phase"], intent["ceremonyID"], intent["response"] = "complete", a.Command, authenticator("get", 0, a.Options)
	removed := request("/v1/passkey/delete", intent, "browser-remove-B", csrf)
	var removal passkeyhttp.DeleteResponse
	if removed.Status != 200 || json.Unmarshal(removed.Body, &removal) != nil || removal.CommandID == "" || removal.CommitOutcome != "committed" || removal.Replayed {
		t.Fatal("browser UV removal", removed.Status)
	}
	read(false)
	if repeated := request("/v1/passkey/delete", intent, "browser-remove-B", csrf); repeated.Status != 401 || repeated.CSRF != "" {
		t.Fatal("browser invalidated source regained removal authority", repeated.Status)
	}
	// Credential selection and its user handle are generated by the browser,
	// not supplied as an identity hint by the application.
	signin := func(device int) referenceBrowserHTTP {
		t.Helper()
		id := flow("passkey")
		original := options("/v1/passkey/signin-options", map[string]any{"mode": "discoverable", "flowID": id}, "browser-signin-"+id, "")
		return request("/v1/passkey/signin-verify", map[string]any{"mode": "discoverable", "flowID": id, "commandID": command(), "ceremonyID": original.Command, "response": authenticator("get", device, original.Options)}, "", "")
	}
	newSession := signin(1)
	var loggedIn struct {
		SignedIn bool `json:"signedIn"`
	}
	if newSession.Status != 200 || json.Unmarshal(newSession.Body, &loggedIn) != nil || !loggedIn.SignedIn || newSession.CSRF == "" {
		t.Fatal("browser surviving key did not sign in", newSession.Status)
	}
	csrf = newSession.CSRF
	read(true)
	recovered := request("/v1/passkey/delete", map[string]any{"phase": "recover", "referenceID": first.ReferenceID, "expectedVersion": first.Version, "commandID": removal.CommandID}, "browser-recover-rate-only", csrf)
	var historical passkeyhttp.DeleteResponse
	if recovered.Status != 200 || json.Unmarshal(recovered.Body, &historical) != nil || !historical.Replayed || historical.CommandID != removal.CommandID || historical.CommitOutcome != "committed" || recovered.CSRF != "" {
		t.Fatal("browser original removal recovery", recovered.Status)
	}
	remaining := inventory(1)[0]
	if remaining.ReferenceID == first.ReferenceID {
		t.Fatal("browser removal retained deleted mapping")
	}
	if denied := request("/v1/passkey/delete", map[string]any{"phase": "options", "referenceID": remaining.ReferenceID, "expectedVersion": remaining.Version}, "browser-last-key", csrf); denied.Status != 403 {
		t.Fatal("browser could remove last usable key", denied.Status)
	}
	if denied := signin(0); denied.Status < 400 || denied.CSRF != "" {
		t.Fatal("browser removed key regained signin authority", denied.Status)
	}
	read(true)
	if denied := request("/v1/session/signout", map[string]any{}, "", strings.Repeat("A", 43)); denied.Status != 403 {
		t.Fatal("browser logout ignored original CSRF", denied.Status)
	}
	read(true)
	if loggedOut := request("/v1/session/signout", map[string]any{}, "", csrf); loggedOut.Status != 200 {
		t.Fatal("browser logout failed", loggedOut.Status)
	}
	read(false)
}

func referenceBrowserCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "identity.example"}, DNSNames: []string{"identity.example"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type referencePasskeyBrowser struct {
	input  io.WriteCloser
	output *bufio.Scanner
}

func (b *referencePasskeyBrowser) operation(t *testing.T, request any) json.RawMessage {
	t.Helper()
	if err := json.NewEncoder(b.input).Encode(request); err != nil {
		t.Fatal("browser pipe write")
	}
	if !b.output.Scan() {
		t.Fatal("bounded browser pipe read")
	}
	var result struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(b.output.Bytes(), &result) != nil || result.Error != "" || len(result.Result) == 0 {
		t.Fatal("browser operation failed", result.Error)
	}
	return result.Result
}

// Adapted from go-passkey/postgres/browser_integration_test.go@16ac977 (MIT).
// The SPKI allowlist applies only to this ephemeral certificate, unlike global
// --ignore-certificate-errors. Chromium's allowlist behavior is documented at
// chromium.googlesource.com/chromium/src/+/HEAD/services/network/ignore_errors_cert_verifier.h.
func startReferencePasskeyBrowser(t *testing.T, ctx context.Context, origin string, certificate *x509.Certificate, transport string) *referencePasskeyBrowser {
	t.Helper()
	binary := os.Getenv("WEBAUTHN_BROWSER_BINARY")
	if binary == "" {
		t.Fatal("WEBAUTHN_BROWSER_BINARY required for selected interoperability")
	}
	profile := t.TempDir()
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	browserCtx, stop := context.WithCancel(ctx)
	chrome := exec.CommandContext(browserCtx, binary, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--password-store=basic", "--use-mock-keychain", "--no-proxy-server", "--host-resolver-rules=MAP identity.example 127.0.0.1", "--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(pin[:]), "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	chrome.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	chrome.Stdout, chrome.Stderr = io.Discard, io.Discard
	if err := chrome.Start(); err != nil {
		stop()
		t.Fatal("isolated browser startup")
	}
	t.Cleanup(func() { stop(); _ = syscall.Kill(-chrome.Process.Pid, syscall.SIGTERM); _ = chrome.Wait() })
	var endpoint string
	for range 400 {
		wire, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(wire)), "\n")
			if len(parts) == 2 {
				endpoint = "ws://127.0.0.1:" + parts[0] + parts[1]
				break
			}
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("browser startup deadline")
		case <-timer.C:
		}
	}
	if endpoint == "" {
		t.Fatal("browser loopback endpoint unavailable")
	}
	node := exec.CommandContext(ctx, "node", "--input-type=module", "-e", referencePasskeyBrowserDriver, endpoint, origin, transport)
	node.Stderr = io.Discard
	input, err := node.StdinPipe()
	if err != nil {
		t.Fatal("browser driver input")
	}
	output, err := node.StdoutPipe()
	if err != nil {
		_ = input.Close()
		t.Fatal("browser driver output")
	}
	if err := node.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		t.Fatal("browser driver startup")
	}
	t.Cleanup(func() { _ = input.Close(); _ = node.Process.Kill(); _ = node.Wait() })
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 512<<10)
	if !scanner.Scan() {
		t.Fatal("browser driver initialization")
	}
	var ready struct {
		Ready   bool   `json:"ready"`
		Secure  bool   `json:"secure"`
		Version string `json:"version"`
		Driver  string `json:"driver"`
		Stage   string `json:"stage"`
	}
	if json.Unmarshal(scanner.Bytes(), &ready) != nil || !ready.Ready || !ready.Secure {
		t.Fatal("secure browser origin unavailable", ready.Stage)
	}
	t.Logf("isolated browser %s; driver %s; CTAP2.1 %s transport", ready.Version, ready.Driver, transport)
	return &referencePasskeyBrowser{input: input, output: scanner}
}

// CDP virtual devices follow ChromeDevTools/devtools-protocol WebAuthn.pdl.
// No credential private key is exported, injected or reconstructed. Browser
// fetch supplies actual Origin/secure cookies; no request interceptor is used.
const referencePasskeyBrowserDriver = `
import readline from 'node:readline';
let setupStage='connect';
async function main(){
const [endpoint,origin,transport]=process.argv.slice(1);
const socket=new WebSocket(endpoint);
await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
let next=0;const pending=new Map();let load;
socket.addEventListener('message',event=>{const m=JSON.parse(event.data);if(m.method==='Page.loadEventFired')load?.();if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(new Error(p.method+': '+m.error.message)):p.resolve(m.result);}}});
function send(method,params={},sessionId){setupStage=method;const id=++next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(id);reject(new Error('cdp-timeout'));},7000);pending.set(id,{resolve,reject,timer,method});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});}
const version=await send('Browser.getVersion');
const {targetId}=await send('Target.createTarget',{url:'about:blank'});
const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
await send('Page.enable',{},sessionId);
await send('WebAuthn.enable',{enableUI:false},sessionId);
const devices=[];
// Chromium permits only one internal authenticator per environment. The
// independent recovery key therefore uses USB when the first key is internal.
for(let i=0;i<2;i++){const d=await send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:i===0?transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:i===0}},sessionId);devices.push(d.authenticatorId);}
const loaded=new Promise(resolve=>{load=resolve;});
const navigation=await send('Page.navigate',{url:origin+'/identity-browser-fixture'},sessionId);
if(navigation.errorText)throw new Error('navigation-failed');
await loaded;
const secure=await send('Runtime.evaluate',{expression:'isSecureContext && location.origin === '+JSON.stringify(origin),returnByValue:true},sessionId);
process.stdout.write(JSON.stringify({ready:true,secure:secure.result.value===true,version:version.product+' '+version.revision,driver:process.version})+'\n');
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of lines){try{
 const r=JSON.parse(line);let expression;
 if(r.op==='fetch'){
  if(!['GET','POST'].includes(r.method)||!/^\/v1\/[a-z0-9\/-]+$/.test(r.path))throw new Error('invalid-request');
  expression='(async()=>{const r='+JSON.stringify(r)+';const headers={};if(r.method==="POST")headers["Content-Type"]="application/json";if(r.key)headers["Idempotency-Key"]=r.key;if(r.csrf)headers["X-CSRF-Token"]=r.csrf;const response=await fetch(r.path,{method:r.method,headers,credentials:"same-origin",redirect:"error",signal:AbortSignal.timeout(5000),...(r.method==="POST"?{body:JSON.stringify(r.body)}:{})});const reader=response.body.getReader();const chunks=[];let size=0;try{for(;;){const {value,done}=await reader.read();if(done)break;if(value.length>65536-size){await reader.cancel();throw new Error("response-bound");}size+=value.length;chunks.push(value);}}finally{reader.releaseLock();}const wire=new Uint8Array(size);let offset=0;for(const chunk of chunks){wire.set(chunk,offset);offset+=chunk.length;}const text=new TextDecoder().decode(wire);let body;try{body=JSON.parse(text);}catch{body=text;}return {status:response.status,body,csrf:response.headers.get("X-CSRF-Token")||"",cache:response.headers.get("Cache-Control")||""};})()';
 }else if(['create','get'].includes(r.op)&&[0,1].includes(r.device)){
  for(let i=0;i<devices.length;i++)await send('WebAuthn.setAutomaticPresenceSimulation',{authenticatorId:devices[i],enabled:i===r.device},sessionId);
  const method=r.op==='create'?'parseCreationOptionsFromJSON':'parseRequestOptionsFromJSON';
  expression='(async()=>{const options=PublicKeyCredential.'+method+'('+JSON.stringify(r.options.publicKey)+');const credential=await navigator.credentials.'+r.op+'({publicKey:options,signal:AbortSignal.timeout(5000)});return credential.toJSON();})()';
 }else throw new Error('unsupported-operation');
 const out=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);
 if(out.exceptionDetails||out.result.value===undefined)throw new Error('browser-evaluation-failed');
 process.stdout.write(JSON.stringify({result:out.result.value})+'\n');
 }catch(error){process.stdout.write(JSON.stringify({error:error.message==='cdp-timeout'?'browser-timeout':'browser-operation-failed'})+'\n');}}
await send('Browser.close');socket.close();
}
main().catch(()=>process.stdout.write(JSON.stringify({ready:false,stage:setupStage})+'\n',()=>process.exit(1)));
`
