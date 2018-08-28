package rsa_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/wusphinx/crypto/rsa"
)

func readKey(filePath string) []byte {
	file, _ := os.Open(filePath)
	key, _ := ioutil.ReadAll(file)
	return key
}

func TestGenRsa(t *testing.T) {
	if err := rsa.GenRsaKeyPair(1024); err != nil {
		t.Fatalf("gen ras key pair err:%s", err.Error())
	}
	if err := rsa.GenRsaKeyPair(2048); err != nil {
		t.Fatalf("gen ras key pair err:%s", err.Error())
	}

	text := []byte("crypto")
	publicKey := readKey("public.pem")
	privateKey := readKey("private.pem")

	cipherText, err := rsa.RSAEncrypt(text, publicKey)
	if err != nil {
		t.Fatalf("RSAEncrypt err:%s", err.Error())
	}

	origin, err := rsa.RSADecrypt(cipherText, privateKey)
	if err != nil {
		t.Fatalf("RSADecrypt err:%s", err.Error())
	}

	if bytes.Compare(text, origin) != 0 {
		t.Fatalf("The Implemention of RSA Algorithm is not correct text:%s, origin:%s", string(text), string(origin))
	}
}
