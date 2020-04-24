# PgpDecryptServer
PGP decrypt Web server example written in go lang.

This example shows how to implement simple PGP decrypt Web server.  
It use HTTPS, session based auth log in. Registered user can upload PGP file, and then download PGP decrypted file.

Some items are empty intentionally, so you need to fill it up according to your credentials, e.g., below lists are need to be set correctly.  
  * ssl/server.crt
  * ssl/server.key
  * approvedUsers in main.go
  * privateKey in pgpDec.go
  * passphrase in pgpDec.go

You can run it as like below.
```bash
$ go run main.go pgpDec.go
```
Or you can build it as like below.
```bash
$ go build
```

If you want to use HTTP instead of HTTPS, you need to modify as like following.
```go
func main() {
    ...
    // router.RunTLS(":443", "./ssl/server.crt", "./ssl/server.key")
    router.Run(":8080")
}

func authLoginHandler(c *gin.Context) {
    ...
	session.Options(sessions.Options{
		MaxAge: 60 * 60,
		// Secure:   true,
		HttpOnly: true,
	})
    ...
}
```