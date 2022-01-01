package aesEncode

import "bytes"

func padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

// PaddingByte padding to the tail of cipherText.
func PaddingByte(cipherText []byte) []byte {
	return padding(cipherText, 16)
}

// UnPaddingByte unpadding the tail of cipherText.
func UnPaddingByte(cipherText []byte) []byte {

	length := len(cipherText)
	lastChar := cipherText[length-1]
	pad := bytes.Repeat([]byte{byte(lastChar)}, int(lastChar))

	if !bytes.HasSuffix(cipherText, pad) {
		return cipherText
	}
	return cipherText[:length-int(lastChar)]
}
