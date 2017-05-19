package main

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// encryptChacha20Poly1305 encrypts a byte slice using the given 256bit key
// and 12byte nonce.
func encryptChacha20Poly1305(key []byte, nonce []byte, msg []byte) []byte {
	chacha, err := chacha20poly1305.New(key)
	check(err)

	ciphertext := chacha.Seal(nil, nonce, msg, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext
}

// decryptChacha20Poly1305 decrypts a byte slice that has been encrypted with
// encryptChacha20Poly1305.
func decryptChacha20Poly1305(key []byte, msg []byte) []byte {
	chacha, err := chacha20poly1305.New(key)
	check(err)

	plaintext, err := chacha.Open(nil, msg[:12], msg[12:], nil)
	check(err)

	return plaintext
}