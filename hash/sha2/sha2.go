// Package sha2crypt implements sha256-crypt and sha512-crypt.
package sha2crypt

import (
	"crypto/rand"
	"expvar"
	"fmt"

	"github.com/pchchv/pass/hash/sha2/raw"
	"github.com/pchchv/pass/scheme"
)

var (
	errInvalidStub        = fmt.Errorf("invalid sha2 password stub")
	cSHA2CryptHashCalls   = expvar.NewInt("passlib.sha2crypt.hashCalls")
	cSHA2CryptVerifyCalls = expvar.NewInt("passlib.sha2crypt.verifyCalls")
)

type sha2Crypter struct {
	sha512 bool
	rounds int
}

func (c *sha2Crypter) Hash(password string) (hash string, err error) {
	cSHA2CryptHashCalls.Add(1)

	stub, err := c.makeStub()
	if err != nil {
		return "", err
	}

	_, hash, _, _, err = c.hash(password, stub)

	return
}

func (c *sha2Crypter) Verify(password, hash string) (err error) {
	cSHA2CryptVerifyCalls.Add(1)

	_, newHash, _, _, err := c.hash(password, hash)
	if err == nil && !scheme.SecureCompare(hash, newHash) {
		return scheme.ErrInvalidPassword
	}

	return
}

// Changes the default rounds for the crypter.
// Be warned that this is a global setting.
// The default default value is RecommendedRounds.
func (c *sha2Crypter) SetRounds(rounds int) error {
	if rounds < raw.MinimumRounds || rounds > raw.MaximumRounds {
		return raw.ErrInvalidRounds
	}

	c.rounds = rounds
	return nil
}

func (c *sha2Crypter) SupportsStub(stub string) bool {
	if len(stub) < 3 || stub[0] != '$' || stub[2] != '$' {
		return false
	}

	return (stub[1] == '5' && !c.sha512) || (stub[1] == '6' && c.sha512)
}

func (c *sha2Crypter) NeedsUpdate(stub string) bool {
	_, salt, _, rounds, err := raw.Parse(stub)
	if err != nil {
		return false
	}

	return c.needsUpdate(salt, rounds)
}

func (c *sha2Crypter) String() string {
	if c.sha512 {
		return fmt.Sprintf("sha512-crypt(%d)", c.rounds)
	}

	return fmt.Sprintf("sha256-crypt(%d)", c.rounds)
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

func (c *sha2Crypter) hash(password, stub string) (oldHash, newHash, salt string, rounds int, err error) {
	isSHA512, salt, oldHash, rounds, err := raw.Parse(stub)
	if err != nil {
		return "", "", "", 0, err
	}

	if isSHA512 != c.sha512 {
		return "", "", "", 0, errInvalidStub
	}

	if c.sha512 {
		return oldHash, raw.Crypt512(password, salt, rounds), salt, rounds, nil
	}

	return oldHash, raw.Crypt256(password, salt, rounds), salt, rounds, nil
}

func (c *sha2Crypter) needsUpdate(salt string, rounds int) bool {
	return rounds < c.rounds || len(salt) < 16
}
