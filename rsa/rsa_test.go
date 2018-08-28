package rsa_test

import (
	"bytes"
	"crypto"
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
	byteSizes := []int{1024, 2048}
	for _, bs := range byteSizes {
		if err := rsa.GenRsaKeyPair(bs); err != nil {
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

		signData, err := rsa.SignPKCS1v15(text, privateKey, crypto.SHA1)
		if err != nil {
			t.Fatalf("SignPKCS1v15 err:%s", err.Error())
		}

		err = rsa.VerifyPKCS1v15(text, signData, publicKey, crypto.SHA1)
		if err != nil {
			t.Fatalf("VerifyPKCS1v15 err:%s", err.Error())
		}

		signData, err = rsa.SignPKCS1v15(text, privateKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("SignPKCS1v15 err:%s", err.Error())
		}

		err = rsa.VerifyPKCS1v15(text, signData, publicKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("VerifyPKCS1v15 err:%s", err.Error())
		}
	}
}
