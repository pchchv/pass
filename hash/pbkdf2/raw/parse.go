package raw

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

var (
	ErrInvalidRounds = errors.New("invalid number of rounds")
	ErrInvalidStub   = errors.New("invalid stub")
	hashMap          = map[string]func() hash.Hash{
		"pbkdf2":        sha1.New,
		"pbkdf2-sha256": sha256.New,
		"pbkdf2-sha512": sha512.New,
	}
)

func Parse(stub string) (hashFunc func() hash.Hash, rounds int, salt []byte, hash string, err error) {
	var n uint64

	// does not start with $pbkdf2
	if !strings.HasPrefix(stub, "$pbkdf2") {
		err = ErrInvalidStub
		return
	}

	parts := strings.Split(stub, "$")
	if f, ok := hashMap[parts[1]]; ok {
		hashFunc = f
	} else {
		err = ErrInvalidStub
		return
	}

	roundsStr := parts[2]
	n, err = strconv.ParseUint(roundsStr, 10, 31)
	if err != nil {
		err = ErrInvalidStub
		return
	}

	rounds = int(n)
	if rounds < MinRounds || rounds > MaxRounds {
		err = ErrInvalidRounds
		return
	}

	salt, err = Base64Decode(parts[3])
	if err != nil {
		err = fmt.Errorf("could not decode base64 salt")
		return
	}

	hash = parts[4]

	return
}
