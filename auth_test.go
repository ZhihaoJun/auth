package auth

import (
	"testing"
	"bytes"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"encoding/hex"
)

func TestAuthBytesEqual(t *testing.T) {
	a := []byte("aaa")
	b := []byte("aaa")
	if bytes.Equal(a, b) == false {
		t.Error("[TestAuthBytesEqual] equal failed")
	}
}

func TestPrivateKeyGenerate(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	bytes := x509.MarshalPKCS1PrivateKey(pk)
	hexStr := hex.EncodeToString(bytes)
	fmt.Println(hexStr)
	fmt.Println(len(hexStr))
}
