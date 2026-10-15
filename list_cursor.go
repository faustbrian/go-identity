package identity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

const cursorPurpose = "golib.identity.user.list.cursor.v1"

type cursorClaims struct {
	Binding [32]byte
	Cursor  Cursor
	Issued  int64
	Expires int64
	Last    UserID
}

// The wire form is private and versioned; snapshot positions contain no user
// records. Encryption hides even filtered positions from unauthorized viewers.
type cursorWire struct {
	Binding  [32]byte
	Snapshot SubjectID
	Position uint64
	Issued   int64
	Expires  int64
	Last     UserID
}

func listBinding(req UserListRequest, config UserQueryConfig) [32]byte {
	body, _ := json.Marshal(struct {
		Tenant  TenantID
		Viewer  authorization.SubjectID
		Kind    authorization.SubjectKind
		Filters UserListFilters
		Limit   uint32
		Policy  string
		Version uint64
	}{req.TenantID, req.Context.Request.Subject.ID, req.Context.Request.Subject.Kind, req.Filters, req.Limit, config.PolicyID, config.PolicyVersion})
	// This closed value contains no cyclic/interface/float data; Marshal cannot
	// fail. The digest binds normalized filter ordering, not mutable aliases.
	return sha256.Sum256(body)
}

func (c UserListConfig) cursorKeys() (cipher.AEAD, []byte) {
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, c.CursorKey[:])
		mac.Write([]byte(cursorPurpose + "/" + label))
		return mac.Sum(nil)
	}
	// SHA-256 always produces a supported 32-byte AES key, and this concrete
	// standard-library AES cipher always supports random-nonce GCM construction.
	block, _ := aes.NewCipher(derive("encryption"))
	aead, _ := cipher.NewGCMWithRandomNonce(block)
	return aead, derive("signature")
}

func (c UserListConfig) sealCursor(claims cursorClaims) string {
	body := encodeCursorWire(cursorWire{claims.Binding, claims.Cursor.snapshot, claims.Cursor.position, claims.Issued, claims.Expires, claims.Last})
	aead, key := c.cursorKeys()
	signed := append([]byte{1}, aead.Seal(nil, nil, body, []byte(cursorPurpose))...)
	mac := hmac.New(sha256.New, key)
	mac.Write(signed)
	return base64.RawURLEncoding.EncodeToString(append(signed, mac.Sum(nil)...))
}

func (c UserListConfig) openCursor(token string, binding [32]byte, now time.Time) (cursorClaims, error) {
	invalid := InvalidInputError{Field: "cursor"}
	if len(token) == 0 || len(token) > 1024 {
		return cursorClaims{}, invalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) < 1+12+16+32 || raw[0] != 1 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return cursorClaims{}, invalid
	}
	aead, key := c.cursorKeys()
	signed, tag := raw[:len(raw)-32], raw[len(raw)-32:]
	mac := hmac.New(sha256.New, key)
	mac.Write(signed)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return cursorClaims{}, invalid
	}
	body, err := aead.Open(nil, nil, signed[1:], []byte(cursorPurpose))
	if err != nil {
		return cursorClaims{}, invalid
	}
	var wire cursorWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil {
		return cursorClaims{}, invalid
	}
	canonical := encodeCursorWire(wire)
	if !bytes.Equal(body, canonical) || wire.Binding != binding || wire.Issued <= 0 || wire.Issued > now.UnixNano() || wire.Expires <= now.UnixNano() || wire.Expires <= wire.Issued || wire.Expires-wire.Issued > int64(c.CursorTTL) || !validDirectoryID(string(wire.Last)) {
		return cursorClaims{}, invalid
	}
	cursor, err := NewCursor(wire.Snapshot, wire.Position)
	if err != nil {
		return cursorClaims{}, invalid
	}
	return cursorClaims{Binding: binding, Cursor: cursor, Issued: wire.Issued, Expires: wire.Expires, Last: wire.Last}, nil
}

func encodeCursorWire(wire cursorWire) []byte {
	// This closed string/integer/array value cannot fail JSON encoding. The
	// encrypted body is never HTML: HTML escaping can inflate a valid 128-byte
	// canonical ID sixfold and violate the admitted 1024-byte cursor bound.
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(wire)
	return bytes.TrimSuffix(body.Bytes(), []byte("\n"))
}
