# OAuth device authorization

Use this profile to approve a configured public or confidential Basic device
client using a recent password session on the existing PostgreSQL Reference
backend. It does not serve a device verification page, OAuth discovery,
OIDC, ordinary authorization-code or refresh requests at the token endpoint,
managed clients, or workload clients. The existing workload profile remains
separate. Native issuance and approval own the device, consent and token
state; the application does not implement an additional store.

1. Start with the durable PostgreSQL password-session graph. Use a secure
   session cookie, its retained CSRF keys, and the shared strict `HTTPRate`
   backend when enabling routes. The primary pool must use `search_path=public`.
2. Select `StoreConfiguration.OAuthDevice` with a separate OAuth schema,
   the existing authorization service and policy version, a retained token
   digest keyring, a distinct device lookup keyring, and the local envelope
   keyring. Register the selected clients with `DeviceAuthorization` and
   permitted scopes/resource. The policy must bind the device tenant to the
   password graph's bootstrapped tenants. Protected command counters use the
   graph's exact digest keys and the selected native OAuth privileged
   velocity policy.
3. Plan and apply the selected Reference migrations before starting the
   feature. Include `oauth-server/postgres`, `identity/postgres`,
   `identity/risk/postgres`, and `rate-limit/postgres` with the baseline
   owners. This appends the human consent and device history in a separate
   native namespace. It is not a migration from the machine-only OAuth schema.
4. Select `StoreConfiguration.HTTPOAuthDevice` with a rate namespace to
   expose the routes. Configure the issuer's exact HTTPS hostname as a tenant
   host for the device tenant. Without this selector the history can be
   installed, but no device route or OpenAPI operation is exposed.

The device calls `POST /oauth2/device_authorization` and displays `user_code`
and `verification_uri`. The deployment owns that verification page. A
signed-in browser calls `GET /v1/oauth-server/device-inspect` to obtain the
canonical code and client/scope prompt. It must display the code even when
the page was reached through `verification_uri_complete`. After the user
explicitly compares it, send `user_code` and `confirmed_user_code` to
`POST /v1/oauth-server/device-approve`. Send `user_code` alone to
`POST /v1/oauth-server/device-deny`. Both mutations require the normal session
cookie, exact issuer `Origin`, and `X-CSRF-Token` from that session.

The device polls `POST /oauth2/token` with the device grant type and original
`device_code` no faster than `interval`, increasing its interval by five
seconds after `slow_down`. Stop on denial or expiry. Treat tokens as secrets
and do not retry a successful exchange; a consumed code cannot redisclose
credentials. This Reference transport does not redeem refresh tokens.

See the [PostgreSQL HTTPS consumer](oauth_device_integration_test.go) for the
complete selected journey and its failure cases.
