package auth

import (
	"time"
	"github.com/jmoiron/sqlx"
)

type Auth struct {
	decryptor  IDecryptor
	validator  IInfoValidator
	keyStore   IPrivateKeyStore
}

func NewAuth(decryptor IDecryptor, validator IInfoValidator, keyStore IPrivateKeyStore) *Auth {
	return &Auth{
		decryptor: decryptor,
		validator: validator,
		keyStore: keyStore,
	}
}

func NewDefaultAuth(label []byte, validDuration time.Duration, pgHost string, tableName string) (*Auth, error) {
	var keyStore IPrivateKeyStore
	db, err := sqlx.Connect("postgres", pgHost)
	if err != nil {
		return nil, err
	}
	keyStore, err = NewARCCacheKeyStore(NewPgKeyStore(db, tableName), 256)
	if err != nil {
		return nil, err
	}
	return &Auth{
		decryptor: NewDefaultDecryptor(label),
		validator: NewDefaultValidator(validDuration, keyStore),
		keyStore: keyStore,
	}, nil
}

func (a *Auth) IsCredentialValid(info ICredentialInfo, validScopes []string) (error) {
	appID := info.AppID()
	validTime := info.ValidTime()
	encrypted := info.Encrypted()
	scope := info.Scope()

	if err := a.validator.Validate(appID, validTime, scope, validScopes); err != nil {
		return err
	}

	key, err := a.keyStore.Get(appID)
	if err != nil {
		return err
	}

	decryptedAppID, decryptedValidTime, decryptedScope, err := a.decryptor.Decrypt(encrypted, key)
	if err != nil {
		return err
	}
	if decryptedAppID != appID {
		return NewDecryptInfoNotMatchError("appID", decryptedAppID)
	}
	if decryptedValidTime.Equal(decryptedValidTime) == false {
		return NewDecryptInfoNotMatchError("validTime", decryptedValidTime.Unix())
	}
	if decryptedScope != scope {
		return NewDecryptInfoNotMatchError("scope", decryptedScope)
	}
	return nil
}
