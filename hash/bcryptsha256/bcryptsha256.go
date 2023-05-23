// bcryptsha256 package implements bcrypt with
// a SHA256 prehash in a format compatible with
// the equivalent bcrypt-sha256 scheme from Python passlib.
// This is preferable to bcrypt because the prehash makes
// the password length restriction in bcrypt irrelevant.
package bcryptsha256

import (
	"github.com/pchchv/pass/scheme"
)

type schemeSHA256 struct {
	underlying scheme.Scheme
	cost       int
}
