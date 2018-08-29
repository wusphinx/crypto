package des_test

import (
	"bytes"
	"testing"

	"github.com/wusphinx/crypto/des"
	"github.com/wusphinx/crypto/modes"
)

var (
	text = []byte("des")
	key  = modes.GenKeyBySize(8)
	key3 = modes.GenKeyBySize(24)
)

func TestDesCBC(t *testing.T) {
	cipherText, err := des.DesEncryptCBC(text, key)
	if err != nil {
		t.Fatalf("DesEncryptCBC err:%s", err.Error())
	}
	originData, err := des.DesDecryptCBC(cipherText, key)
	if err != nil {
		t.Fatalf("DesDecryptCBC err:%s", err.Error())
	}
	if bytes.Compare(text, originData) != 0 {
		t.Fatalf("The Implemention of DES CBC Algorithm is not correct text:%s, originData:%s", string(text), string(originData))
	}

}

func TestDesECB(t *testing.T) {
	cipherText, err := des.DesEncryptECB(text, key)
	if err != nil {
		t.Fatalf("DesEncryptECB err:%s", err.Error())
	}
	originData, err := des.DesDecryptECB(cipherText, key)
	if err != nil {
		t.Fatalf("DesDecryptECB err:%s", err.Error())
	}
	if bytes.Compare(text, originData) != 0 {
		t.Fatalf("The Implemention of DES ECB Algorithm is not correct text:%s, originData:%s", string(text), string(originData))
	}
}

func TestTripleDesCBC(t *testing.T) {
	cipherText, err := des.TripleDesEncryptCBC(text, key3)
	if err != nil {
		t.Fatalf("TripleDesEncryptCBC err:%s", err.Error())
	}
	originData, err := des.TripleDesDecryptCBC(cipherText, key3)
	if err != nil {
		t.Fatalf("TripleDesDecryptCBC err:%s", err.Error())
	}
	if bytes.Compare(text, originData) != 0 {
		t.Fatalf("The Implemention of Triple DES CBC Algorithm is not correct text:%s, originData:%s", string(text), string(originData))
	}
}

func TestTripleDesECB(t *testing.T) {
	cipherText, err := des.TripleDesEncryptECB(text, key3)
	if err != nil {
		t.Fatalf("TripleDesEncryptECB err:%s", err.Error())
	}
	originData, err := des.TripleDesDecryptECB(cipherText, key3)
	if err != nil {
		t.Fatalf("TripleDesDecryptECB err:%s", err.Error())
	}
	if bytes.Compare(text, originData) != 0 {
		t.Fatalf("The Implemention of Triple DES ECB Algorithm is not correct text:%s, originData:%s", string(text), string(originData))
	}
}
