package aes_test

import (
	"bytes"
	"testing"

	"github.com/wusphinx/crypto/aes"
	"github.com/wusphinx/crypto/modes"
)

func getKeyBySize(size int) []byte {
	return modes.GenKeyBySize(size)
}

func TestAes(t *testing.T) {
	var keys [][]byte

	// AES-128, AES-192, or AES-256
	keys = append(keys, getKeyBySize(16), getKeyBySize(24), getKeyBySize(32))

	for _, key := range keys {
		text := []byte("aes")
		t.Logf("key:%v", key)

		cipherText, err := aes.AESEncryptECB(text, key)
		if err != nil {
			t.Fatalf("AESEncryptECB err:%s", err.Error())
		}

		originData, err := aes.AESDecryptECB(cipherText, key)
		if err != nil {
			t.Fatalf("AESDecryptECB err:%s", err.Error())
		}

		if bytes.Compare(text, originData) != 0 {
			t.Fatalf("The Implemention of AES ECB Algorithm is not correct text:%s, originData:%s", string(text), string(originData))
		}
	}
}
