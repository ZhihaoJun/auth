package auth

import (
	"time"
	"crypto/rsa"
)

type ICredentialInfo interface {
	AppID() string
	ValidTime() time.Time
	Encrypted() ([]byte, error)
	Scope() string
}

type IDecryptor interface {
	Decrypt(sign []byte, key *rsa.PrivateKey) (appID string, validTime time.Time, scope string, err error)
}

type IPrivateKeyStore interface {
	Get(appID string) (*rsa.PrivateKey, error)
}

type IInfoValidator interface {
	Validate(appID string, validTime time.Time, scope string, validScopes []string) (error)
}
