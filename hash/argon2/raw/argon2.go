// Package raw provides a raw implementation of
// the modular-crypt-wrapped Argon2i primitive.
package raw

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	RecommendedTime    uint32 = 4         // Current recommended time value for interactive logins
	RecommendedMemory  uint32 = 32 * 1024 // Current recommended memory for interactive logins
	RecommendedThreads uint8  = 4         // Current recommended number of threads for interactive logins.
)

// Wrapper for golang.org/x/crypto/argon2
// that implements a sensible hashing interface.
//
// password must be in UTF-8 format.
// salt must be a random salt value in binary form.
// time, memory and threads are parameters for argon2.
//
// Returns hash in argon2 encoding.
func Argon2(password string, salt []byte, time, memory uint32, threads uint8) string {
	bytePassword := []byte(password)

	hash := argon2.Key(bytePassword, salt, time, memory, threads, 32)

	strHash := base64.RawStdEncoding.EncodeToString(hash)
	strSalt := base64.RawStdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, time, threads, strSalt, strHash)
}
