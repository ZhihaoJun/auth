package auth

import "time"

type DefaultValidator struct {
	validDuration time.Duration
	keyStore      IPrivateKeyStore
}

func NewDefaultValidator(validDuration time.Duration, keyStore IPrivateKeyStore) *DefaultValidator {
	return &DefaultValidator{
		validDuration: validDuration,
		keyStore: keyStore,
	}
}

func (dv *DefaultValidator) Validate(appID string, validTime time.Time, scope string, validScopes []string) (error) {
	// check valid scope
	isScopeValid := false
	for _, validScope := range validScopes {
		if validScope == scope {
			isScopeValid = true
		}
	}
	if isScopeValid == false {
		return NewValidationFailedError("scope", scope, "scope is invalid")
	}

	// check valid time
	if validTime.Before(time.Now().Add(dv.validDuration)) == false {
		return NewValidationFailedError("validTime", validTime, "validTime is invalid")
	}

	_, err := dv.keyStore.Get(appID)
	if _, ok := err.(*AppIDMissingError); ok {
		return NewValidationFailedError("appID", appID, "appID not exists")
	}
	if err != nil {
		return err
	}
	return nil
}
