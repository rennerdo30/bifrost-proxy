package device

import (
	"crypto/rand"
	"io"
)

// randomRead is a variable to allow testing with deterministic random.
var randomRead = func(b []byte) (int, error) {
	return io.ReadFull(rand.Reader, b)
}
