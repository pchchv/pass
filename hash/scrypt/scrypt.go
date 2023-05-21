// Package scrypt implements the scrypt password hashing mechanism,
// wrapped in the modular crypt format.
package scrypt

import (
	"crypto/rand"
	"encoding/base64"
	"expvar"
	"fmt"
	"strings"

	"github.com/pchchv/pass/hash/scrypt/raw"
	"github.com/pchchv/pass/scheme"
)

var (
	cScryptSHA256HashCalls   = expvar.NewInt("passlib.scryptsha256.hashCalls")
	cScryptSHA256VerifyCalls = expvar.NewInt("passlib.scryptsha256.verifyCalls")
)

type scryptSHA256Crypter struct {
	nN int
	r  int
	p  int
}

func (c *scryptSHA256Crypter) Hash(password string) (hash string, err error) {
	cScryptSHA256HashCalls.Add(1)
	stub, err := c.makeStub()
	if err != nil {
		return "", err
	}

	_, hash, _, _, _, _, err = c.hash(password, stub)

	return
}

func (c *scryptSHA256Crypter) Verify(password, hash string) (err error) {
	cScryptSHA256VerifyCalls.Add(1)
	_, newHash, _, _, _, _, err := c.hash(password, hash)
	if err == nil && !scheme.SecureCompare(hash, newHash) {
		return scheme.ErrInvalidPassword
	}

	return
}

func (c *scryptSHA256Crypter) SetParams(N, r, p int) error {
	c.nN = N
	c.r = r
	c.p = p

	return nil
}

func (c *scryptSHA256Crypter) SupportsStub(stub string) bool {
	return strings.HasPrefix(stub, "$s2$")
}

func (c *scryptSHA256Crypter) makeStub() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	salt := base64.StdEncoding.EncodeToString(buf)

	return fmt.Sprintf("$s2$%d$%d$%d$%s", c.nN, c.r, c.p, salt), nil
}

func (c *scryptSHA256Crypter) hash(password, stub string) (oldHashRaw []byte, newHash string, salt []byte, N, r, p int, err error) {
	salt, oldHashRaw, N, r, p, err = raw.Parse(stub)
	if err != nil {
		return
	}

	return oldHashRaw, raw.ScryptSHA256(password, salt, N, r, p), salt, N, r, p, nil
}
