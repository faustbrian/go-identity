package identityhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Limits bounds untrusted ordinary HTTP input. Header bytes are 1024..65536,
// URL bytes 1024..8192, raw/decoded bytes 1024..1048576, fields 1..1000 and
// nesting depth 1..32. Every field is explicit; zero is invalid. Header limits
// here cover net/http's parsed representation, not original normalized wire
// bytes; the server must also enforce its raw header and read deadlines.
type Limits struct {
	MaximumHeaderBytes  uint32
	MaximumURLBytes     uint32
	MaximumBodyBytes    uint64
	MaximumDecodedBytes uint64
	MaximumFields       uint32
	MaximumDepth        uint32
}

// DecodeError is a redacted invalid-request classification. It retains no
// submitted data, field names or underlying reader/codec diagnostics.
type DecodeError struct{}

// Error returns the stable invalid-request identity without submitted data.
func (DecodeError) Error() string { return "identity.http.invalid_request" }

// RequestDecoder owns immutable copied limits and no request state. Its zero
// value is invalid. Concurrent independent requests may share one decoder;
// callers must not concurrently mutate a request or consume its body.
type RequestDecoder struct {
	limits Limits
	valid  bool
}

// Form reads application/x-www-form-urlencoded body parameters only; it never
// merges URL query parameters. Empty body is valid. Names must be nonempty;
// missing '=' means an empty value. Empty segments, bare semicolons, invalid
// percent escapes/UTF-8, duplicate or case-alias names and idempotency-key body
// alternatives reject atomically. Percent decoding uses '+' as space. Limits
// count entries globally and decoded UTF-8 name/value bytes before allocation.
// Body ownership, cancellation and blocking-read rules match DecodeJSON.
func (d *RequestDecoder) Form(r *http.Request) (url.Values, error) {
	if d == nil || !d.valid || r == nil {
		return nil, ErrInvalidInput
	}
	if err := d.envelope(r); err != nil {
		return nil, err
	}
	if !media(r.Header, "application/x-www-form-urlencoded") {
		return nil, DecodeError{}
	}
	body, err := d.body(r)
	if err != nil {
		return nil, err
	}
	return d.parameters(string(body))
}

// Query parses URL.RawQuery only and never reads or closes the body or merges
// cached Request.Form/PostForm fields. It uses Form's duplicate/encoding and
// decoded-byte rules, plus MaximumURLBytes for the complete represented URI.
// It does not authorize credential acquisition from query parameters.
func (d *RequestDecoder) Query(r *http.Request) (url.Values, error) {
	if d == nil || !d.valid || r == nil {
		return nil, ErrInvalidInput
	}
	if err := d.envelope(r); err != nil {
		return nil, err
	}
	return d.parameters(r.URL.RawQuery)
}

func (d *RequestDecoder) parameters(raw string) (url.Values, error) {
	result := make(url.Values)
	seen := make(map[string]bool)
	var fields uint32
	var decoded uint64
	for raw != "" {
		part, remainder, more := strings.Cut(raw, "&")
		fields++
		if part == "" || strings.Contains(part, ";") || fields > d.limits.MaximumFields || more && remainder == "" {
			return nil, DecodeError{}
		}
		nameRaw, valueRaw, _ := strings.Cut(part, "=")
		name, ok := formComponent(nameRaw, &decoded, d.limits.MaximumDecodedBytes)
		if !ok || name == "" {
			return nil, DecodeError{}
		}
		value, ok := formComponent(valueRaw, &decoded, d.limits.MaximumDecodedBytes)
		if !ok {
			return nil, DecodeError{}
		}
		folded := foldName(name)
		if seen[folded] || forbiddenKeyName(folded) {
			return nil, DecodeError{}
		}
		seen[folded] = true
		result[name] = []string{value}
		raw = remainder
	}
	return result, nil
}

func formComponent(raw string, decoded *uint64, bound uint64) (string, bool) {
	length := uint64(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			continue
		}
		if len(raw)-i < 3 || !hexByte(raw[i+1]) || !hexByte(raw[i+2]) {
			return "", false
		}
		length -= 2
		i += 2
	}
	if length > bound-*decoded {
		return "", false
	}
	*decoded += length
	value, err := url.QueryUnescape(raw)
	return value, err == nil && utf8.ValidString(value)
}

func hexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func forbiddenKeyName(folded string) bool {
	return folded == "idempotencykey" || folded == "idempotency-key" || folded == "idempotency_key"
}

// NewRequestDecoder validates every limit without IO or implicit defaults.
func NewRequestDecoder(limits Limits) (*RequestDecoder, error) {
	if limits.MaximumHeaderBytes < 1024 || limits.MaximumHeaderBytes > 65536 || limits.MaximumURLBytes < 1024 || limits.MaximumURLBytes > 8192 || limits.MaximumBodyBytes < 1024 || limits.MaximumBodyBytes > 1048576 || limits.MaximumDecodedBytes < 1024 || limits.MaximumDecodedBytes > 1048576 || limits.MaximumFields < 1 || limits.MaximumFields > 1000 || limits.MaximumDepth < 1 || limits.MaximumDepth > 32 {
		return nil, ErrInvalidInput
	}
	return &RequestDecoder{limits: limits, valid: true}, nil
}

// DecodeJSON reads one ordinary application/json object into T. It rejects
// unknown typed fields, trailing values, duplicate/case-alias member names at
// every depth, invalid UTF-8/surrogates, and idempotency-key body alternatives.
// Root depth is one. MaximumFields counts all object members and array elements
// globally; decoded bytes count unescaped UTF-8 string/key bytes and scalar
// lexical bytes, excluding whitespace/punctuation. This validation precedes
// typed decoding and its caller-owned custom unmarshaling methods.
//
// On any error the returned T is zero, even after partial codec assignment.
// Standard encoding/json field matching otherwise applies. Custom unmarshaling
// methods are trusted caller code and must be bounded/cancellation-cooperative.
// The body is borrowed, never closed or drained beyond the configured bound
// plus one byte. The HTTP server/direct caller retains closure and blocking-read
// interruption ownership; no detached read goroutine is created. Cancellation
// preserves context errors; other input/reader errors become DecodeError.
func DecodeJSON[T any](decoder *RequestDecoder, request *http.Request) (T, error) {
	var zero T
	if decoder == nil || !decoder.valid || request == nil {
		return zero, ErrInvalidInput
	}
	if err := decoder.envelope(request); err != nil {
		return zero, err
	}
	if !media(request.Header, "application/json") {
		return zero, DecodeError{}
	}
	body, err := decoder.body(request)
	if err != nil {
		return zero, err
	}
	if !utf8.Valid(body) {
		return zero, DecodeError{}
	}
	scanner := jsonBoundary{data: body, limits: decoder.limits}
	scanner.space()
	if scanner.pos == len(body) || body[scanner.pos] != '{' || !scanner.value(0) {
		return zero, DecodeError{}
	}
	scanner.space()
	if scanner.pos != len(body) {
		return zero, DecodeError{}
	}
	if err := request.Context().Err(); err != nil {
		return zero, err
	}
	var result T
	typed := json.NewDecoder(bytes.NewReader(body))
	typed.DisallowUnknownFields()
	if err := typed.Decode(&result); err != nil {
		return zero, DecodeError{}
	}
	if err := request.Context().Err(); err != nil {
		return zero, err
	}
	return result, nil
}

// envelope rejects metadata errors before borrowing the body. Subsequent
// trusted-network, credential and route policy owners still validate semantics.
func (d *RequestDecoder) envelope(r *http.Request) error {
	if err := r.Context().Err(); err != nil {
		return err
	}
	if r.URL == nil || r.ContentLength < -1 {
		return DecodeError{}
	}
	maxURL := int(d.limits.MaximumURLBytes)
	if len(r.RequestURI) > maxURL || len(r.URL.Path) > maxURL || len(r.URL.RawPath) > maxURL || len(r.URL.RawQuery) > maxURL || r.URL.Fragment != "" || r.URL.User != nil {
		return DecodeError{}
	}
	uri := r.URL.RequestURI()
	if len(uri) > maxURL || (r.RequestURI != "" && r.RequestURI != uri) {
		return DecodeError{}
	}
	// Count each represented field as name + ': ' + value + CRLF, final CRLF,
	// and Host when carried in Request.Host rather than the Header map.
	headerBytes := uint64(2)
	seen := make(map[string]bool)
	for name, values := range r.Header {
		if !headerToken(name) || len(values) == 0 {
			return DecodeError{}
		}
		lower := strings.ToLower(name)
		if sensitiveHeader(lower) && (seen[lower] || len(values) != 1) {
			return DecodeError{}
		}
		seen[lower] = true
		for _, value := range values {
			headerBytes += uint64(len(name)) + uint64(len(value)) + 4
			if headerBytes > uint64(d.limits.MaximumHeaderBytes) {
				return DecodeError{}
			}
			for i := range value {
				if value[i] == 127 || value[i] < 32 && value[i] != '\t' {
					return DecodeError{}
				}
			}
		}
	}
	if host, present := singleHeader(r.Header, "Host"); present && host != r.Host {
		return DecodeError{}
	}
	if !seen["host"] {
		headerBytes += uint64(len(r.Host)) + 8
	}
	if headerBytes > uint64(d.limits.MaximumHeaderBytes) || len(r.Trailer) != 0 || seen["trailer"] || seen["transfer-encoding"] {
		return DecodeError{}
	}
	length, hasLength := singleHeader(r.Header, "Content-Length")
	if hasLength {
		if length == "" {
			return DecodeError{}
		}
		for i := range length {
			if length[i] < '0' || length[i] > '9' {
				return DecodeError{}
			}
		}
		parsed, err := strconv.ParseInt(length, 10, 64)
		if err != nil || parsed != r.ContentLength {
			return DecodeError{}
		}
	}
	if len(r.TransferEncoding) != 0 && (len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" || r.ContentLength != -1 || hasLength) {
		return DecodeError{}
	}
	encoding, hasEncoding := singleHeader(r.Header, "Content-Encoding")
	if hasEncoding && !strings.EqualFold(encoding, "identity") {
		return DecodeError{}
	}
	if r.ContentLength > int64(d.limits.MaximumBodyBytes) {
		return DecodeError{}
	}
	return nil
}

func sensitiveHeader(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "content-type", "content-length", "content-encoding", "transfer-encoding", "trailer", "idempotency-key", "origin", "host", "if-match", "x-csrf-token":
		return true
	}
	return false
}

func headerToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func singleHeader(headers http.Header, name string) (string, bool) {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			if len(values) == 1 {
				return values[0], true
			}
			return "", true
		}
	}
	return "", false
}

func media(headers http.Header, expected string) bool {
	value, ok := singleHeader(headers, "Content-Type")
	if !ok || strings.Count(value, ";") > 1 {
		return false
	}
	kind, parameters, err := mime.ParseMediaType(value)
	if err != nil || kind != expected || len(parameters) > 1 {
		return false
	}
	for key, value := range parameters {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func (d *RequestDecoder) body(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		if r.ContentLength > 0 {
			return nil, DecodeError{}
		}
		return nil, nil
	}
	bound := d.limits.MaximumBodyBytes
	if r.ContentLength >= 0 {
		bound = uint64(r.ContentLength)
	}
	buffer := make([]byte, int(bound)+1)
	reader := &contextBodyReader{ctx: r.Context(), reader: r.Body}
	n, err := io.ReadFull(reader, buffer)
	if cancellation := r.Context().Err(); cancellation != nil {
		return nil, cancellation
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, DecodeError{}
	}
	if uint64(n) > bound || r.ContentLength >= 0 && int64(n) != r.ContentLength {
		return nil, DecodeError{}
	}
	return buffer[:n], nil
}

type contextBodyReader struct {
	ctx    context.Context
	reader io.Reader
	empty  int
}

func (r *contextBodyReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if n == 0 && err == nil {
		r.empty++
		if r.empty >= 100 {
			return 0, io.ErrNoProgress
		}
	} else {
		r.empty = 0
	}
	return n, err
}

type jsonBoundary struct {
	data    []byte
	limits  Limits
	pos     int
	fields  uint32
	decoded uint64
}

func (s *jsonBoundary) space() {
	for s.pos < len(s.data) && (s.data[s.pos] == ' ' || s.data[s.pos] == '\t' || s.data[s.pos] == '\r' || s.data[s.pos] == '\n') {
		s.pos++
	}
}

func (s *jsonBoundary) charge(n uint64) bool {
	if n > s.limits.MaximumDecodedBytes-s.decoded {
		return false
	}
	s.decoded += n
	return true
}

func (s *jsonBoundary) field() bool { s.fields++; return s.fields <= s.limits.MaximumFields }

func (s *jsonBoundary) value(depth uint32) bool {
	s.space()
	if s.pos >= len(s.data) {
		return false
	}
	switch s.data[s.pos] {
	case '{':
		return s.object(depth + 1)
	case '[':
		if depth+1 > s.limits.MaximumDepth {
			return false
		}
		s.pos++
		s.space()
		if s.take(']') {
			return true
		}
		for {
			if !s.field() || !s.value(depth+1) {
				return false
			}
			s.space()
			if s.take(']') {
				return true
			}
			if !s.take(',') {
				return false
			}
		}
	case '"':
		_, _, ok := s.stringToken()
		return ok
	case 't', 'f', 'n':
		for _, literal := range []string{"true", "false", "null"} {
			if bytes.HasPrefix(s.data[s.pos:], []byte(literal)) {
				s.pos += len(literal)
				return s.charge(uint64(len(literal)))
			}
		}
		return false
	default:
		start := s.pos
		for s.pos < len(s.data) && strings.ContainsRune("-+0123456789.eE", rune(s.data[s.pos])) {
			s.pos++
		}
		return s.pos > start && json.Valid(s.data[start:s.pos]) && s.charge(uint64(s.pos-start))
	}
}

func (s *jsonBoundary) object(depth uint32) bool {
	if depth > s.limits.MaximumDepth {
		return false
	}
	s.pos++
	s.space()
	if s.take('}') {
		return true
	}
	names := make(map[string]bool)
	for {
		if !s.field() {
			return false
		}
		s.space()
		start, end, ok := s.stringToken()
		if !ok {
			return false
		}
		var name string
		if json.Unmarshal(s.data[start:end], &name) != nil {
			return false
		}
		folded := foldName(name)
		if forbiddenKeyName(folded) || names[folded] {
			return false
		}
		names[folded] = true
		s.space()
		if !s.take(':') || !s.value(depth) {
			return false
		}
		s.space()
		if s.take('}') {
			return true
		}
		if !s.take(',') {
			return false
		}
	}
}

func foldName(name string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < minimum {
				minimum = folded
			}
		}
		// ASCII aliases use lowercase for reserved-name comparisons.
		if minimum >= 'A' && minimum <= 'Z' {
			minimum += 'a' - 'A'
		}
		return minimum
	}, name)
}

func (s *jsonBoundary) take(c byte) bool {
	if s.pos < len(s.data) && s.data[s.pos] == c {
		s.pos++
		return true
	}
	return false
}

func (s *jsonBoundary) stringToken() (int, int, bool) {
	start := s.pos
	if !s.take('"') {
		return 0, 0, false
	}
	for s.pos < len(s.data) {
		c := s.data[s.pos]
		s.pos++
		if c == '"' {
			return start, s.pos, true
		}
		if c < 32 {
			return 0, 0, false
		}
		if c != '\\' {
			if !s.charge(1) {
				return 0, 0, false
			}
			continue
		}
		if s.pos >= len(s.data) {
			return 0, 0, false
		}
		escape := s.data[s.pos]
		s.pos++
		if strings.ContainsRune("\"\\/bfnrt", rune(escape)) {
			if !s.charge(1) {
				return 0, 0, false
			}
			continue
		}
		if escape != 'u' {
			return 0, 0, false
		}
		r, ok := s.hexRune()
		if !ok {
			return 0, 0, false
		}
		if r >= 0xd800 && r <= 0xdbff {
			if !s.take('\\') || !s.take('u') {
				return 0, 0, false
			}
			low, ok := s.hexRune()
			if !ok || low < 0xdc00 || low > 0xdfff {
				return 0, 0, false
			}
			r = utf16.DecodeRune(r, low)
		} else if r >= 0xdc00 && r <= 0xdfff {
			return 0, 0, false
		}
		if !s.charge(uint64(utf8.RuneLen(r))) {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

func (s *jsonBoundary) hexRune() (rune, bool) {
	if len(s.data)-s.pos < 4 {
		return 0, false
	}
	var value rune
	for range 4 {
		c := s.data[s.pos]
		s.pos++
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value += rune(c - '0')
		case c >= 'a' && c <= 'f':
			value += rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			value += rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}
