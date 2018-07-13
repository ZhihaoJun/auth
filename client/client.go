package client

import (
	"time"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/rand"
	"encoding/json"
	"encoding/base64"
)

type Client struct {
	appID         string
	publicKey     *rsa.PublicKey
	validDuration time.Duration
	label         []byte
}

func NewClient(appID string, label []byte, publicKey *rsa.PublicKey) *Client {
	return &Client{
		appID:         appID,
		publicKey:     publicKey,
		validDuration: time.Second * 5,
		label: label,
	}
}

func (c *Client) GenerateToken(scope string) ([]byte, error) {
	type u struct {
		AppID string `json:"appID"`
		ValidTime int64 `json:"validTime"`
		Scope string `json:"scope"`
	}
	validTime := time.Now().Add(c.validDuration)
	info := u{
		AppID: c.appID,
		ValidTime: validTime.Unix(),
		Scope: scope,
	}

	msg, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.publicKey, msg, c.label)
	if err != nil {
		return nil, err
	}

	type out struct {
		AppID string `json:"appID"`
		ValidTime int64 `json:"validTime"`
		Scope string `json:"scope"`
		Encrypted []byte `json:"encrypted"`
	}
	o := out{
		AppID: c.appID,
		ValidTime: validTime.Unix(),
		Scope: scope,
		Encrypted: encrypted,
	}

	jsonEncoded, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}

	base64EncodedLen := base64.StdEncoding.EncodedLen(len(jsonEncoded))
	base64Encoded := make([]byte, base64EncodedLen)
	base64.StdEncoding.Encode(base64Encoded, jsonEncoded)
	return base64Encoded, nil
}

func (c *Client) GenerateTokenString(scope string) (string, error) {
	token, err := c.GenerateToken(scope)
	if err != nil {
		return "", nil
	}
	return string(token), nil
}
