package auth

import "fmt"

type AppIDMissingError struct {
	appID string
}

func NewAppIDMissingError(appID string) *AppIDMissingError {
	return &AppIDMissingError{
		appID,
	}
}

func (ame *AppIDMissingError) Error() string {
	return fmt.Sprintf("[AppIDMissingError] appID is not in record: %s", ame.appID)
}

type ValidationFailedError struct {
	field string
	dat interface{}
	msg string
}

func NewValidationFailedError(field string, dat interface{}, msg string) *ValidationFailedError {
	return &ValidationFailedError{
		field: field,
		dat: dat,
		msg: msg,
	}
}

func (vfe *ValidationFailedError) Error() string {
	return fmt.Sprintf("[ValidationFailedError] field:%s, dat:%v, msg:%s", vfe.field, vfe.dat, vfe.msg)
}

type DecryptInfoNotMatchError struct {
	field string
	dat interface{}
}

func NewDecryptInfoNotMatchError(field string, dat interface{}) *DecryptInfoNotMatchError {
	return &DecryptInfoNotMatchError{
		field: field,
		dat: dat,
	}
}

func (dinme *DecryptInfoNotMatchError) Error() string {
	return fmt.Sprintf("[DecryptInfoNotMatchError] %s not matched: %v", dinme.field, dinme.dat)
}
