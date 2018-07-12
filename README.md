# auth
a library like jwt auth, but simplified.

## Usage
main function entry is auth.Auth

shipped with default auth configuration
* rsa encryption
* appid and private key are stored in postgres
* appid and private retrival with ARC cache

or, Auth can be configured by injecting following interfaces
* IDecryptor
* IInfoValidator
* IPrivateKeyStore

in subpackage auth/middleware  
basic usage and validation middleware of echo framework can be construct with NewEchoMiddleware

``` Golang
label := []byte("label")
validDuration := time.Second * 60
psHost := "..." // pg connect string
tableName := "app_key"

auth, err := auth.NewDefaultAuth(label, validDuration, pgHost, tableName)
if err != nil {
    panic(err)
}
middleware := middleware.NewEchoMiddleware(auth, "X-Token", []string{"api"})

echo.Use(middleware)

echo.GET("/api/some", handler, middleware)
```
