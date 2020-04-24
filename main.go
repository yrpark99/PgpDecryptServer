package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	userkey      = "user"
	uploadPath   = "upload/"
	downloadPath = "download/"
)

var approvedUsers = map[string]string{
	"user1": "user1passwd",
	"user2": "user2passwd",
}

func main() {
	router := gin.New()
	cookie := sessions.NewCookieStore([]byte("secret"))
	router.Use(sessions.Sessions("my_session", cookie))

	auth := router.Group("/auth")
	auth.Use(authRequired)
	{
		auth.GET("/welcome", authWelcomeHandler)
		auth.GET("/decrypt_request", authDecryptRequestHandler)
		auth.POST("/upload", authUploadHandler)
		auth.GET("/download_ready", authDownloadReadyHandler)
		auth.POST("/download_decrypted", authDownloadDecryptedHandler)
		auth.POST("/logout", authLogoutHandler)
	}

	router.GET("/", homeHandler)
	router.GET("/login", loginHandler)
	router.POST("/auth_login", authLoginHandler)

	router.LoadHTMLGlob("templates/*")

	go checkPassedFiles()

	router.RunTLS(":443", "./ssl/server.crt", "./ssl/server.key")
}

func checkPassedFiles() {
	for {
		checkAndDeleteFiles(uploadPath)
		checkAndDeleteFiles(downloadPath)
		time.Sleep(10 * 60 * time.Second)
	}
}

func checkAndDeleteFiles(path string) {
	now := time.Now()
	files, _ := ioutil.ReadDir(path)
	for _, file := range files {
		fileName := path + file.Name()
		stat, err := os.Stat(fileName)
		if err != nil {
			continue
		}
		modTime := stat.ModTime()
		diff := now.Sub(modTime)
		if diff.Hours() > 24 {
			fmt.Println("Delete file '" + fileName + "'")
			os.Remove(fileName)
		}
	}
}

func homeHandler(c *gin.Context) {
	c.Redirect(http.StatusMovedPermanently, "/login")
}

func authRequired(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userkey)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Next()
}

func loginHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func authLoginHandler(c *gin.Context) {
	userName := c.PostForm("username")
	password := c.PostForm("password")

	if strings.Trim(userName, " ") == "" || strings.Trim(password, " ") == "" {
		c.JSON(http.StatusBadRequest, "Login is failed")
		return
	}

	val, exists := approvedUsers[userName]
	if !exists {
		c.String(http.StatusUnauthorized, "Login is failed")
		return
	}
	if password != val {
		c.String(http.StatusUnauthorized, "Login is failed")
		return
	}

	session := sessions.Default(c)
	session.Set(userkey, userName)
	session.Options(sessions.Options{
		MaxAge:   60 * 60,
		Secure:   true,
		HttpOnly: true,
	})
	if err := session.Save(); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save session")
		return
	}
	log.Println(userName + " is logged in")

	welcomeURI := "/auth/welcome?userid=" + userName
	c.Redirect(http.StatusMovedPermanently, welcomeURI)
}

func authWelcomeHandler(c *gin.Context) {
	userid := c.Query("userid")
	c.HTML(http.StatusOK, "welcome.html", gin.H{
		"userid": userid,
	})
}

func authDecryptRequestHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "request.html", nil)
}

func authUploadHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("Error: %s", err.Error()))
		return
	}

	fileName := filepath.Base(file.Filename)
	pos := strings.LastIndex(fileName, ".pgp")
	if pos < 0 {
		pos = strings.LastIndex(fileName, ".gpg")
		if pos < 0 {
			c.String(http.StatusBadRequest, "Error: Not a PGP file")
			return
		}
	}

	if err := c.SaveUploadedFile(file, uploadPath+fileName); err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
		return
	}

	err = pgpDecryptFile(uploadPath, fileName, downloadPath)
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("Fail to PGP decrypt"))
		return
	}

	downloadURI := "/auth/download_ready?filename=" + fileName[:pos]
	c.Redirect(http.StatusMovedPermanently, downloadURI)
}

func authDownloadReadyHandler(c *gin.Context) {
	fileName := c.Query("filename")
	c.HTML(http.StatusOK, "download_ready.html", gin.H{
		"filename": fileName,
	})
}

func authDownloadDecryptedHandler(c *gin.Context) {
	downloadFileName := downloadPath + c.PostForm("filename")
	var fileName string
	index := strings.LastIndex(downloadFileName, "/")
	fileName = downloadFileName[index+1:]
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+fileName)
	c.Header("Content-Type", "application/octet-stream")
	c.File(downloadFileName)
}

func authLogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userkey)
	if user == nil {
		c.String(http.StatusBadRequest, "Invalid session token")
		return
	}
	session.Delete(userkey)
	if err := session.Save(); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save session")
		return
	}

	userName := fmt.Sprintf("%v", user)
	log.Println(userName + " is logged out")

	c.Redirect(http.StatusMovedPermanently, "/login")
}
