// Package crypter performs simple (i.e opinionated) data encryption and decryption with the
// intention of being compatible with NodeJS cipher functions
package crypter

import (
  "crypto/aes"
  "crypto/cipher"
  "encoding/base64"
  "log"
)

// Encrypt encrypts a value using a generally static key and a necessarily variable
// initialization vector (IV). Returns a Base64 encoded encrypted result.  The IV is not
// prepended to the ciphertext.
func Encrypt(key, iv, plaintext []byte) string {
  if len(key) != 32 {
    log.Fatal("Key length must be 32 bytes")
  }
  if len(iv) != 12 {
    log.Fatal("initialization vector must be 12 bytes")
  }
  block, err := aes.NewCipher(key)
  if err != nil {
    log.Fatal(err)
  }
  gcm, _ := cipher.NewGCM(block)
  ciphertext := gcm.Seal(nil, iv, plaintext, nil)
  return base64.StdEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts a Base64 encoded encrypted value using a generally static key and a
// necessarily variable initialization vector (IV). The IV is not prepended to the ciphertext.
func Decrypt(key, iv []byte, b64ciphertext string) []byte {
  if len(key) != 32 {
    log.Fatal("Key length must be 32 bytes")
  }
  if len(iv) != 12 {
    log.Fatal("initialization vector must be 12 bytes")
  }
  cipherblob, _ := base64.StdEncoding.DecodeString(b64ciphertext)
  ciphertext := []byte(cipherblob)
  block, err := aes.NewCipher(key)
  if err != nil {
    log.Fatal(err)
  }
  gcm, _ := cipher.NewGCM(block)
  plaintext, _ := gcm.Open(nil, iv, ciphertext, nil)
  return []byte(plaintext)
}
