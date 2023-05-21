// Package raw provides a raw implementation of
// the modular-crypt-wrapped scrypt primitive.
package raw

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	// The current recommended N value for interactive logins.
	RecommendedN = 16384
	// The current recommended r value for interactive logins.
	Recommendedr = 8
	// The current recommended p value for interactive logins.
	Recommendedp = 1
)

// Wrapper for golang.org/x/crypto/scrypt that implements a sensible modular crypt interface.
//
// password must be a plaintext password in UTF-8 format.
// salt must be a random salt value in binary form.
// N, r, and p are parameters for scrypt.
//
// Returns a modular crypt hash.
func ScryptSHA256(password string, salt []byte, N, r, p int) string {
	passwordb := []byte(password)
	hash, err := scrypt.Key(passwordb, salt, N, r, p, 32)
	if err != nil {
		panic(err)
	}

	strHash := base64.StdEncoding.EncodeToString(hash)
	strSalt := base64.StdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$s2$%d$%d$%d$%s$%s", N, r, p, strSalt, strHash)
}
