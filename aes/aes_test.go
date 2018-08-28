package aes_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/wusphinx/crypto/aes"
)

func getKeyBySize(size int) []byte {
	key := make([]byte, size)
	_, _ = rand.Read(key)
	return key
}

func TestAes(t *testing.T) {
	var keys [][]byte

	// AES-128, AES-192, or AES-256
	keys = append(keys, getKeyBySize(16), getKeyBySize(24), getKeyBySize(32))

	for _, key := range keys {
		text := []byte("aes")
		t.Logf("key:%v", key)

		cipherText, err := aes.AESEncrypt(text, key)
		if err != nil {
			t.Fatalf("AESEncrypt err:%s", err.Error())
		}

		originData, err := aes.AESDecrypt(cipherText, key)
		if err != nil {
			t.Fatalf("AESDecrypt err:%s", err.Error())
		}

		if bytes.Compare(text, originData) != 0 {
			t.Fatalf("The Implemention of AES Algorithm is not correct text:%s, originData:%s", string(text), string(originData))
		}
	}
}
