package des

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/wusphinx/crypto/modes"
)

func DesEncryptCBC(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	origData = modes.PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func DesDecryptCBC(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = modes.PKCS5UnPadding(origData)
	return origData, nil
}

func DesEncryptECB(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	origData = modes.PKCS5Padding(origData, block.BlockSize())
	crypted := make([]byte, len(origData))
	blockMode := modes.NewECBEncrypter(block)
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func DesDecryptECB(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := modes.NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = modes.PKCS5UnPadding(origData)
	return origData, nil
}
