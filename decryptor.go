package auth

import (
	"time"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/rand"
	"encoding/json"
)

type DefaultDecryptor struct {
	label []byte
}

func NewDefaultDecryptor(label []byte) *DefaultDecryptor {
	return &DefaultDecryptor{
		label: label,
	}
}

func (dd *DefaultDecryptor) Decrypt(encrypted []byte, key *rsa.PrivateKey) (string, time.Time, string, error) {
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encrypted, dd.label)
	if err != nil {
		return "", time.Time{}, "", err
	}

	type u struct {
		AppID string `json:"appID"`
		Timestamp int64 `json:"validTime"`
		Scope string `json:"scope"`
	}
	res := u{}
	if err := json.Unmarshal(plain, &res); err != nil {
		return "", time.Time{}, "", err
	}

	validTime := time.Unix(res.Timestamp, 0)
	return res.AppID, validTime, res.Scope, nil
}
