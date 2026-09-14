package dockerapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const InternalHeader = "X-Dockauthz-Internal-Token"

// Token is a per-process capability; its representation is deliberately private.
type Token struct{ value string }

// NewToken uses 256 bits of operating-system randomness and no persistent storage.
func NewToken() (*Token, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return nil, err
	}
	return &Token{value: hex.EncodeToString(bytes[:])}, nil
}

// Check treats duplicate case-insensitive header spellings as invalid.
func (t *Token) Check(headers map[string]string) (present, valid bool) {
	count := 0
	for key, value := range headers {
		if strings.EqualFold(key, InternalHeader) {
			count++
			valid = subtle.ConstantTimeCompare([]byte(value), []byte(t.value)) == 1
		}
	}
	return count > 0, count == 1 && valid
}
