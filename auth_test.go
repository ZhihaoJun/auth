package auth

import (
	"testing"
	"bytes"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"encoding/hex"
	"crypto/sha256"
)

func TestAuthBytesEqual(t *testing.T) {
	a := []byte("aaa")
	b := []byte("aaa")
	if bytes.Equal(a, b) == false {
		t.Error("[TestAuthBytesEqual] equal failed")
	}
}

func TestPrivateKeyGeneration(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	bytes := x509.MarshalPKCS1PrivateKey(pk)
	hexStr := hex.EncodeToString(bytes)
	fmt.Println(hexStr)
	fmt.Println(len(hexStr))
}

func TestPrivateKeyEncrypt(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	publicKey := pk.Public().(*rsa.PublicKey)
	plainMsg := "Hello World"
	msg := []byte(plainMsg)
	label := []byte("test")
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, msg, label)
	if err != nil {
		t.Error(err)
	}

	encodedStr := hex.EncodeToString(encrypted)

	fmt.Println(encodedStr)
	fmt.Println(len(encodedStr))

	// decrypt
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pk, encrypted, label)
	if err != nil {
		t.Error(err)
	}
	if string(decrypted) != plainMsg {
		t.Error("[TestPrivateKeyEncrypt] decryption failed")
	}
}
