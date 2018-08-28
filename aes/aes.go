package aes

import (
	"crypto/aes"

	"github.com/wusphinx/crypto/modes"
)

func AESDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := modes.NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = modes.PKCS5UnPadding(origData)

	return origData, nil
}

func AESEncrypt(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ecb := modes.NewECBEncrypter(block)
	content := []byte(src)
	content = modes.PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted, nil
}
