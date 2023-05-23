// bcryptsha256 package implements bcrypt with
// a SHA256 prehash in a format compatible with
// the equivalent bcrypt-sha256 scheme from Python passlib.
// This is preferable to bcrypt because the prehash makes
// the password length restriction in bcrypt irrelevant.
package bcryptsha256

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pchchv/pass/hash/bcrypt"
	"github.com/pchchv/pass/scheme"
)

// The recommended cost for bcrypt-sha256.
const RecommendedCost = bcrypt.RecommendedCost

type schemeSHA256 struct {
	underlying scheme.Scheme
	cost       int
}

// Instantiates a new Scheme implementing bcrypt with the given cost.
func New(cost int) scheme.Scheme {
	return &schemeSHA256{
		underlying: bcrypt.New(cost),
		cost:       cost,
	}
}

func (s *schemeSHA256) Hash(password string) (string, error) {
	p := s.prehash(password)
	h, err := s.underlying.Hash(p)
	if err != nil {
		return "", err
	}

	return mangle(h), nil
}

func (s *schemeSHA256) Verify(password, hash string) error {
	p := s.prehash(password)
	return s.underlying.Verify(p, demangle(hash))
}

func (s *schemeSHA256) NeedsUpdate(stub string) bool {
	return s.underlying.NeedsUpdate(demangle(stub))
}

func (s *schemeSHA256) SupportsStub(stub string) bool {
	return strings.HasPrefix(stub, "$bcrypt-sha256$") && s.underlying.SupportsStub(demangle(stub))
}

func (s *schemeSHA256) String() string {
	return fmt.Sprintf("bcrypt-sha256(%d)", s.cost)
}

func (s *schemeSHA256) prehash(password string) string {
	h := sha256.New()
	h.Write([]byte(password))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func mangle(hash string) string {
	parts := strings.Split(hash[1:], "$")
	salt := parts[2][0:22]
	h := parts[2][22:]

	return "$bcrypt-sha256$" + parts[0] + "," + parts[1] + "$" + salt + "$" + h
}

func demangle(stub string) string {
	if strings.HasPrefix(stub, "$bcrypt-sha256$2") {
		parts := strings.Split(stub[15:], "$")
		parts0 := strings.Split(parts[0], ",")

		return "$" + parts0[0] + "$" + fmt.Sprintf("%02s", parts0[1]) + "$" + parts[1] + parts[2]
	} else {
		return stub
	}
}
