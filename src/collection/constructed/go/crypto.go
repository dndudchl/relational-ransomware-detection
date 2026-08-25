// crypto.go - The encryption step that separates shape J from shape D.
//
// Kept in its own file so that the difference between the two shapes is one
// function call in one place, and so that a reader comparing the C, Go and
// Rust ports can see that all three do the same thing here.
//
// The C port calls CryptEncrypt through the Windows CryptoAPI, which the
// sandbox hooks and records. Go's crypto/aes is a pure implementation with
// no system call behind it, so nothing is recorded at all. That difference
// is not a flaw in the port -- it is the same difference the ransomware set
// shows, where a third of encrypting runs never call a Windows crypto API
// because they carry their own. Whether the detector notices either is the
// question the D/J pair exists to ask.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

func encrypt(plain []byte) []byte {
	key := sha256.Sum256([]byte("matrix-experiment-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return plain
	}
	// A fixed IV. This is not protecting anything -- the point is to produce
	// the file operations and the CPU work of encrypting, not to be secure.
	iv := make([]byte, block.BlockSize())
	out := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(out, plain)
	return out
}
