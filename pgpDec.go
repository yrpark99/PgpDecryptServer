package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

const privateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----`

const passphrase = ""

func pgpDecryptFile(srcPath string, fileName string, dstPath string) error {
	pgpFile, err := os.Open(srcPath + fileName)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer pgpFile.Close()

	index := strings.LastIndex(fileName, ".pgp")
	if index < 0 {
		index = strings.LastIndex(fileName, ".gpg")
		if index < 0 {
			fmt.Println("Not a PGP file")
			return err
		}
	}
	decFileName := dstPath + fileName[:index]

	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
	if err != nil {
		fmt.Println(err)
		return err
	}

	decFile, err := os.Create(decFileName)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer decFile.Close()

	return pgpDecrypt(entityList, pgpFile, decFile)
}

func pgpDecrypt(entityList openpgp.EntityList, r io.Reader, w io.Writer) error {
	entity := entityList[0]

	passphraseByte := []byte(passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	md, err := openpgp.ReadMessage(r, entityList, nil, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		fmt.Println(err)
		return err
	}

	_, err = w.Write(bytes)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return err
}
