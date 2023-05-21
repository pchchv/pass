// Package scrypt implements the scrypt password hashing mechanism,
// wrapped in the modular crypt format.
package scrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/pchchv/pass/hash/scrypt/raw"
)

type scryptSHA256Crypter struct {
	nN int
	r  int
	p  int
}

func (c *scryptSHA256Crypter) makeStub() (string, error) {
	buf := make([]byte, 18)
	_, err := rand.Read(buf)
	if err != nil {
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
