// Package raw provides a raw implementation of
// the modular-crypt-wrapped scrypt primitive.
package raw

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

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

var ErrInvalidStub = fmt.Errorf("invalid scrypt password stub")

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

// Parse parses a scrypt modular hash or stub string.
// The format is as follows:
//
//	$s2$N$r$p$salt$hash    // hash
//	$s2$N$r$p$salt         // stub
func Parse(stub string) (salt, hash []byte, N, r, p int, err error) {
	if len(stub) < 10 || !strings.HasPrefix(stub, "$s2$") {
		err = ErrInvalidStub
		return
	}

	// $s2$  N$r$p$salt-base64$hash-base64
	parts := strings.Split(stub[4:], "$")

	if len(parts) < 4 {
		err = ErrInvalidStub
		return
	}

	var Ni, ri, pi uint64

	Ni, err = strconv.ParseUint(parts[0], 10, 31)
	if err != nil {
		return
	}

	ri, err = strconv.ParseUint(parts[1], 10, 31)
	if err != nil {
		return
	}

	pi, err = strconv.ParseUint(parts[2], 10, 31)
	if err != nil {
		return
	}

	N, r, p = int(Ni), int(ri), int(pi)

	salt, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return
	}

	if len(parts) >= 5 {
		hash, err = base64.StdEncoding.DecodeString(parts[4])
	}

	return
}
