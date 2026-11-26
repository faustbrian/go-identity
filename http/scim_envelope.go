package identityhttp

// SCIM Bulk's protocol maximum is 2 MiB. One sentinel byte lets the feature
// detect a chunked overrun and return SCIM 413 inside the outer stream cap.
const scimBulkStreamBytes = (2 << 20) + 1

type scimEnvelopeKey struct{}

// NewSCIMRequestBoundary builds the ordinary network, framing, and credential
// checks for the canonical SCIM protocol only. It leaves media, encoding, and
// payload-size decisions to a trusted SCIM feature. Neither result consumes or
// bounds the body; use the selected router's stream ceiling and the feature's
// smaller effective byte limit. Ordinary body codecs retain their own limits.
func NewSCIMRequestBoundary(config NetworkConfig) (*NetworkResolver, *RequestDecoder, error) {
	network, err := NewNetworkResolver(config)
	if err != nil {
		return nil, nil, err
	}
	network.decoder.scim = true
	return network, network.decoder, nil
}
