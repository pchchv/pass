// Package argon2 implements the argon2 password hashing mechanism,
// wrapped in the argon2 encoded format.
package argon2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)
type argon2Scheme struct {
	time, memory uint32
	threads      uint8
}

const saltLength = 16

func (c *argon2Scheme) makeStub() (string, error) {
	buf := make([]byte, saltLength)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	salt := base64.RawStdEncoding.EncodeToString(buf)

	return fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$", argon2.Version, c.memory, c.time, c.threads, salt), nil
}
