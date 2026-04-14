package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/stremovskyy/golaraauth"
)

type DBModel struct {
	ID        int64
	TokenID   string
	CreatedAt string
	UpdatedAt string
}

func main() {
	tokenString := os.Getenv("TOKEN_STRING")
	if tokenString == "" {
		fmt.Println("set TOKEN_STRING to a Laravel-issued JWT before running this example")
		return
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to resolve example directory")
	}
	keyDir := filepath.Join(filepath.Dir(currentFile), "keys")

	model := &DBModel{}

	dbConfig := golaraauth.DbConfig{
		HostName:       "127.0.0.1",
		Port:           "3306",
		Username:       "root",
		Password:       "password",
		DbName:         "database",
		TokensTable:    "personal_access_tokens",
		TokensTableCol: "token_id",
	}

	config := golaraauth.AuthConfig{
		DbConfig:      dbConfig,
		PublicKeyFile: filepath.Join(keyDir, "dev.rsa.pub"),
	}

	a := golaraauth.LaravelAuthenticator{}
	err := a.New(config)
	if err != nil {
		panic(err)
	}

	defer a.CloseDBConnection()

	b, err := a.VerifyTokenString(tokenString, model)
	if err != nil {
		panic(err)
	}

	println(b)
}
