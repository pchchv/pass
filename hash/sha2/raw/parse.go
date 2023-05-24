package raw

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrInvalidStub   = errors.New("invalid stub")
	ErrInvalidRounds = errors.New("invalid number of rounds")
)

// Parse scans a modular sha256-crypt or sha512-crypt or
// modular cryptohash to determine configuration parameters.
func Parse(stub string) (isSHA512 bool, salt, hash string, rounds int, err error) {
	// $5$
	if len(stub) < 3 || stub[0] != '$' || stub[2] != '$' {
		err = ErrInvalidStub
		return
	}

	if stub[1] == '6' {
		isSHA512 = true
	} else if stub[1] != '5' {
		err = ErrInvalidStub
		return
	}

	rest := stub[3:]
	parts := strings.Split(rest, "$")
	roundsStr := ""

	switch len(parts) {
	case 1:
		// $5$
		// $5$salt
		salt = parts[0]
	case 2:
		// $5$salt$hash
		// $5$rounds=1000$salt
		if strings.HasPrefix(parts[0], "rounds=") {
			roundsStr = parts[0]
			salt = parts[1]
		} else {
			salt = parts[0]
			hash = parts[1]
		}
	case 3:
		// $5$rounds=1000$salt$hash
		roundsStr = parts[0]
		salt = parts[1]
		hash = parts[2]
	default:
		err = ErrInvalidStub
	}

	if roundsStr != "" {
		if !strings.HasPrefix(roundsStr, "rounds=") {
			err = ErrInvalidStub
			return
		}

		roundsStr = roundsStr[7:]
		var n uint64
		n, err = strconv.ParseUint(roundsStr, 10, 31)
		if err != nil {
			err = ErrInvalidStub
			return
		}

		rounds = int(n)

		if rounds < MinimumRounds || rounds > MaximumRounds {
			err = ErrInvalidRounds
			return
		}
	} else {
		rounds = DefaultRounds
	}

	return
}
