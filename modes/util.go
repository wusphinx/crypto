package modes

import (
	"crypto/rand"
)

func GenKeyBySize(size int) []byte {
	key := make([]byte, size)
	_, _ = rand.Read(key)
	return key
}
