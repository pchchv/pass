// Package sha2crypt implements sha256-crypt and sha512-crypt.
package sha2crypt

import (
	"crypto/rand"
	"fmt"

	"github.com/pchchv/pass/hash/sha2/raw"
)

type sha2Crypter struct {
	sha512 bool
	rounds int
}

func (c *sha2Crypter) makeStub() (string, error) {
	ch := "5"
	if c.sha512 {
		ch = "6"
	}

	buf := make([]byte, 12)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	salt := raw.EncodeBase64(buf)[0:16]

	if c.rounds == raw.DefaultRounds {
		return fmt.Sprintf("$%s$%s", ch, salt), nil
	}

	return fmt.Sprintf("$%s$rounds=%d$%s", ch, c.rounds, salt), nil
}
