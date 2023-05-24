// Raw package provides a raw implementation of the sha256-crypt and sha512-crypt primitives.
package raw

import (
	"io"
)

func repeat(w io.Writer, b []byte, sz int) {
	var i int

	for i = 0; (i + len(b)) <= sz; i += len(b) {
		w.Write(b)
	}

	w.Write(b[0 : sz-i])
}

func repeatTo(out []byte, b []byte) {
	if len(b) == 0 {
		return
	}

	var i int

	for i = 0; (i + len(b)) <= len(out); i += len(b) {
		copy(out[i:], b)
	}

	copy(out[i:], b)
}
