// Package scrypt implements the scrypt password hashing mechanism,
// wrapped in the modular crypt format.
package scrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
