package client

import (
	"testing"
	"github.com/zhihaojun/auth"
	"crypto/rsa"
	"crypto/rand"
	"time"
	"fmt"
	"encoding/json"
)

type tokenInfo struct {
	appID string
	timestamp int64
	encrypted []byte
	scope string
}

func newTokenInfo(appID string, timestamp int64, encrypted []byte, scope string) *tokenInfo {
	return &tokenInfo{
		appID,
		timestamp,
		encrypted,
		scope,
	}
}

func (i *tokenInfo) AppID() string {
	return i.appID
}

func (i *tokenInfo) ValidTime() time.Time {
	return time.Unix(i.timestamp, 0)
}

func (i *tokenInfo) Encrypted() []byte {
	return i.encrypted
}

func (i *tokenInfo) Scope() string {
	return i.scope
}

func TestClientGenerateToken(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	keyStore := auth.NewMemoryKeyStore()
	keyStore.Set("test_app_id", pk)

	label := []byte("test")
	authObj := auth.NewAuth(auth.NewDefaultDecryptor(label), auth.NewDefaultValidator(time.Second * 5, keyStore), keyStore)
	client := NewClient("test_app_id", label, pk.Public().(*rsa.PublicKey))

	token, err := client.GenerateToken("test")
	fmt.Println(len(token))
	fmt.Println(string(token))

	type out struct {
		AppID string `json:"appID"`
		ValidTime int64 `json:"validTime"`
		Scope string `json:"scope"`
		Encrypted []byte `json:"encrypted"`
	}
	info := out{}

	if err := json.Unmarshal(token, &info); err != nil {
		t.Error(err)
	}
	fmt.Printf("%v\n", info)
	tokenInfo := newTokenInfo(info.AppID, info.ValidTime, info.Encrypted, info.Scope)

	if err := authObj.IsCredentialValid(tokenInfo, []string{"test"}); err != nil {
		t.Error(err)
	}
}
