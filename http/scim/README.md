# SCIM Bulk HTTP

`scimhttp.NewBulkFeature` selects exactly `POST /scim/v2/Bulk` and
`GET /scim/v2/ServiceProviderConfig`. Nothing is installed by importing the
module. Use the same configured network policy for the feature and the
identity HTTPS router. Every enabled host must resolve to the resource tenant
proved by the native executor before rate admission or work starts.

Pass the configured `scimpostgres.BulkService` as the executor, after
installing its required migrations and bootstrapping its native authority.
Use a shared strict-atomic rate backend, a deployment namespace, a stable
owned 32-byte digest key, a clock and bounded deadlines. Reuse the same quota
settings for both operations and independent HTTP instances; rotating the key
or namespace resets effective quotas. No local fallback exists.

```go
feature, err := scimhttp.NewBulkFeature(scimhttp.BulkFeatureConfig{
    Network: network, // identityhttp.NetworkConfig used by routerPolicy
    Executor: nativeBulk,
    Rate: scimhttp.ProtocolRateConfig{
        Shared: sharedRate, Namespace: "identity-protocol",
        Key: rateDigestKey, Now: time.Now, MaximumDuration: time.Second,
    },
    MaximumDuration: 5 * time.Second,
})
if err != nil {
    return err
}
operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{
    Features: []identityhttp.Feature{feature},
})
if err != nil {
    return err
}
handler, document, err := identityhttp.NewRouter(routerPolicy, operations, nil)
```

Configure the real HTTP server's read/write bounds; a context cannot interrupt
an arbitrary caller body reader. These handlers cannot expose separate generic
middleware authentication phases because the native executor owns the only
authentication and holds current authority through the operation. The common
router still owns network admission, exact route selection and optional CORS.

Send a SCIM bearer via `Authorization` and a BulkRequest with
`Content-Type: application/scim+json`. The server limits the raw body to the
executor's advertised size; only identity content encoding is accepted.
`Idempotency-Key` is an optional header alias, not a command identifier. Retry
the same input, and the same header if supplied, after an uncertain result.
The transport never streams partially settled children. Discovery returns
the actual Bulk capability and limits; unrelated CRUD and reconciliation
routes are not installed. Both endpoints consume a fresh atomic quota attempt
even when the executor returns a retained result.
