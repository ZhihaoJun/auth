package middleware

import (
	"github.com/labstack/echo"
	"github.com/zhihaojun/auth"
	"encoding/base64"
	"net/http"
	"fmt"
	"encoding/json"
	"time"
	"encoding/hex"
)

type echoTokenInfo struct {
	AppIDField string `json:"appID"`
	TimestampField int64 `json:"validTime"`
	EncryptedField string `json:"encrypted"`
	ScopeField string `json:"scope"`
}

func (i *echoTokenInfo) AppID() string {
	return i.AppIDField
}

func (i *echoTokenInfo) ValidTime() time.Time {
	return time.Unix(i.TimestampField, 0)
}

func (i *echoTokenInfo) Encrypted() ([]byte, error) {
	return hex.DecodeString(i.EncryptedField)
}

func (i *echoTokenInfo) Scope() string {
	return i.ScopeField
}

func NewEchoMiddleware(auth *auth.Auth, headerName string, validScopes []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			token := ctx.Request().Header.Get(headerName)
			jsonStr, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				return ctx.JSON(http.StatusForbidden, map[string]interface{}{
					"error": "token:invalid",
					"msg": fmt.Sprintf("%s is not a valid base64 format", headerName),
				})
			}

			info := &echoTokenInfo{}
			if err := json.Unmarshal(jsonStr, &info); err != nil {
				return ctx.JSON(http.StatusForbidden, map[string]interface{}{
					"error": "token:invalid",
					"msg": fmt.Sprintf("%s is not a valid json format", headerName),
				})
			}

			if err := auth.IsCredentialValid(info, validScopes); err != nil {
				return ctx.JSON(http.StatusForbidden, map[string]interface{}{
					"error": "token:invalid",
					"msg": err.Error(),
				})
			}
			return next(ctx)
		}
	}
}
