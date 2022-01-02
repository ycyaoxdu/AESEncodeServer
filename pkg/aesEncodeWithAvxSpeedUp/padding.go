package aesEncodeWithAvxSpeedUp

import (
	"bytes"
)

// calculate length of padding, then padding the number padding for padding times.
func padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	if padding == 0 {
		return append(cipherText, bytes.Repeat([]byte{byte(padding)}, 16)...)
	}
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
	if lastChar == byte(0) {
		return cipherText[:length-16]
	}
	pad := bytes.Repeat([]byte{byte(lastChar)}, int(lastChar))

	if !bytes.HasSuffix(cipherText, pad) {
		return cipherText
	}
	return cipherText[:length-int(lastChar)]
}
