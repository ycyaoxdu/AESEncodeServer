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
