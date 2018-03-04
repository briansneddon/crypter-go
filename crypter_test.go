package crypter

import (
  "testing"
)

var plaintext []byte = []byte("ERISQUODSUM")
var ciphertext string = "xaC0vVMUjqW2R3Ls9oJb8ZaKm1MRYg9G1gZe"
var key []byte = []byte("12345678901234567890123456789012")
var iv []byte = []byte("123456789012")

func TestEncrypt(t *testing.T) {
  result := Encrypt(key, iv, plaintext)
  if result != ciphertext {
    t.Errorf("Incorrect Encrypt() result: %s", result)
  }
}

func TestDecrypt(t *testing.T) {
  result := Decrypt(key, iv, ciphertext)
  if string(result) != string(plaintext) {
    t.Errorf("Incorrect Decrypt() result: %s", result)
  }
}
