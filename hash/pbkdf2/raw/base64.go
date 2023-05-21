package raw

import (
	"encoding/base64"
	"strings"
)

var b64 = base64.RawStdEncoding

func Base64Encode(src []byte) (dst string) {
	dst = b64.EncodeToString(src)

	return strings.Replace(dst, "+", ".", -1)
}

func Base64Decode(src string) ([]byte, error) {
	src = strings.Replace(src, ".", "+", -1)

	return b64.DecodeString(src)
}
