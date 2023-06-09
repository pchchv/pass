// Package raw provides a raw implementation of
// the modular-crypt-wrapped Argon2i primitive.
package raw

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	RecommendedTime    uint32 = 4         // Current recommended time value for interactive logins
	RecommendedMemory  uint32 = 32 * 1024 // Current recommended memory for interactive logins
	RecommendedThreads uint8  = 4         // Current recommended number of threads for interactive logins.
)

var (
	ErrInvalidStub         = errors.New("invalid argon2 password stub")
	ErrMissingTime         = errors.New("time parameter (t) is missing")
	ErrParseConfig         = errors.New("hash config section has wrong number of parameters")
	ErrParseVersion        = errors.New("version section has wrong number of parameters")
	ErrMissingMemory       = errors.New("memory parameter (m) is missing")
	ErrMissingVersion      = errors.New("version parameter (v) is missing")
	ErrMissingParallelism  = errors.New("parallelism parameter (p) is missing")
	ErrInvalidKeyValuePair = errors.New("invalid argon2 key-value pair")
)

// Wrapper for golang.org/x/crypto/argon2
// that implements a sensible hashing interface.
//
// password must be in UTF-8 format.
// salt must be a random salt value in binary form.
// time, memory and threads are parameters for argon2.
//
// Returns hash in argon2 encoding.
func Argon2(password string, salt []byte, time, memory uint32, threads uint8) string {
	bytePassword := []byte(password)

	hash := argon2.Key(bytePassword, salt, time, memory, threads, 32)

	strHash := base64.RawStdEncoding.EncodeToString(hash)
	strSalt := base64.RawStdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, time, threads, strSalt, strHash)
}

// Parse parses an argon2 encoded hash.
// The format is as follows:
//
//	    $argon2i$v=version$m=memory,t=time,p=threads$salt$hash   // hash
//		$argon2i$v=version$m=memory,t=time,p=threads$salt        // stub
func Parse(stub string) (salt, hash []byte, version int, time, memory uint32, parallelism uint8, err error) {
	if len(stub) < 26 || !strings.HasPrefix(stub, "$argon2i$") {
		err = ErrInvalidStub
		return
	}

	// $argon2i$  v=version$m=memory,t=time,p=threads$salt-base64$hash-base64
	parts := strings.Split(stub[9:], "$")

	// version-params$hash-config-params$salt[$hash]
	if len(parts) < 3 || len(parts) > 4 {
		err = ErrInvalidStub
		return
	}

	// Parse the first configuration part, the version parameters.
	versionParams, err := parseKeyValue(parts[0])
	if err != nil {
		return
	}

	// Must be exactly one parameter in the version part.
	if len(versionParams) != 1 {
		err = ErrParseVersion
		return
	}

	// It must be "v".
	val, ok := versionParams["v"]
	if !ok {
		err = ErrMissingVersion
		return
	}

	version = int(val)

	// Parse the second configuration part, the hash config parameters.
	hashParams, err := parseKeyValue(parts[1])
	if err != nil {
		return
	}

	// It must have exactly three parameters.
	if len(hashParams) != 3 {
		err = ErrParseConfig
		return
	}

	// Memory parameter.
	val, ok = hashParams["m"]
	if !ok {
		err = ErrMissingMemory
		return
	}

	memory = uint32(val)

	// Time parameter.
	val, ok = hashParams["t"]
	if !ok {
		err = ErrMissingTime
		return
	}

	time = uint32(val)

	// Parallelism parameter.
	val, ok = hashParams["p"]
	if !ok {
		err = ErrMissingParallelism
		return
	}

	parallelism = uint8(val)

	// Decode salt.
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}

	// Decode hash if present.
	if len(parts) >= 4 {
		hash, err = base64.RawStdEncoding.DecodeString(parts[3])
	}

	return
}

func parseKeyValue(pairs string) (result map[string]uint64, err error) {
	parameterParts := strings.Split(pairs, ",")

	for _, parameter := range parameterParts {
		parts := strings.SplitN(parameter, "=", 2)
		if len(parts) != 2 {
			return result, ErrInvalidKeyValuePair
		}

		parsedint, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return result, err
		}

		result[parts[0]] = parsedint
	}

	return
}
