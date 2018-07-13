package middleware

import (
	"github.com/labstack/echo"
	"github.com/zhihaojun/auth"
	"encoding/base64"
	"net/http"
	"fmt"
	"encoding/json"
	"time"
)

type echoTokenInfo struct {
	appID string
	timestamp int64
	encrypted []byte
	scope string
}

func newEchoTokenInfo(appID string, timestamp int64, encrypted []byte, scope string) *echoTokenInfo {
	return &echoTokenInfo{
		appID,
		timestamp,
		encrypted,
		scope,
	}
}

func (i *echoTokenInfo) AppID() string {
	return i.appID
}

func (i *echoTokenInfo) ValidTime() time.Time {
	return time.Unix(i.timestamp, 0)
}

func (i *echoTokenInfo) Encrypted() []byte {
	return i.encrypted
}

func (i *echoTokenInfo) Scope() string {
	return i.scope
}

func NewEchoMiddleware(auth *auth.Auth, header string, validScopes []string) echo.MiddlewareFunc {
	type u struct {
		AppID string `json:"appID"`
		Timestamp int64 `json:"validTime"`
		Encrypted []byte `json:"encrypted"`
		Scope string `json:"scope"`
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			token := ctx.Request().Header.Get(header)
			jsonStr, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				return ctx.JSON(http.StatusForbidden, map[string]interface{}{
					"error": "token:invalid",
					"msg": fmt.Sprintf("%s is not a valid base64 format", header),
				})
			}

			info := &u{}
			if err := json.Unmarshal(jsonStr, &info); err != nil {
				return ctx.JSON(http.StatusForbidden, map[string]interface{}{
					"error": "token:invalid",
					"msg": fmt.Sprintf("%s is not a valid json format", header),
				})
			}

			tokenInfo := newEchoTokenInfo(info.AppID, info.Timestamp, info.Encrypted, info.Scope)
			if err := auth.IsCredentialValid(tokenInfo, validScopes); err != nil {
				return ctx.JSON(http.StatusForbidden, map[string]interface{}{
					"error": "token:invalid",
					"msg": err.Error(),
				})
			}
			return next(ctx)
		}
	}
}
