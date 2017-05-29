// Package aes provides simple wrappers for encrypting and decrypting with
// AES256 with Galois Counter Mode (GCM) as AEAD.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

// encryptAesGcm encrypts a given byte slice with the given 256bit key
// and nonce using Galois Conter Mode as AEAD.
// The nonce has to be 12 bytes long and will be prepended to the ciphertext.
func EncryptAesGcm(key []byte, nonce []byte, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	aesGcm, err := cipher.NewGCM(block)
	check(err)

	ciphertext := aesGcm.Seal(nil, nonce, msg, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext
}

// decryptAesGcm decrypts a byte slice that has been encrypted with
// encryptAesGcm.
func DecryptAesGcm(key []byte, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	aesGcm, err := cipher.NewGCM(block)
	check(err)

	plaintext, err := aesGcm.Open(nil, msg[:12], msg[12:], nil)
	check(err)

	return plaintext
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
