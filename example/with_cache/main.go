package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/stremovskyy/cachemar"
	"github.com/stremovskyy/cachemar/drivers/memory"
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
	keyDir := filepath.Join(filepath.Dir(currentFile), "..", "with_keys", "keys")

	manager := cachemar.New()
	memoryCache := memory.NewWithConfig(memory.Config{MaxSize: 1000})
	manager.Register("memory", memoryCache)
	manager.SetCurrent("memory")
	defer func() { _ = manager.Close() }()

	config := golaraauth.AuthConfig{
		DbConfig: golaraauth.DbConfig{
			HostName:       "127.0.0.1",
			Port:           "3306",
			Username:       "root",
			Password:       "password",
			DbName:         "database",
			TokensTable:    "personal_access_tokens",
			TokensTableCol: "token_id",
		},
		PublicKeyFile: filepath.Join(keyDir, "dev.rsa.pub"),
		Cache:         manager.Current(),
	}

	authenticator := golaraauth.LaravelAuthenticator{}
	if err := authenticator.New(config); err != nil {
		panic(err)
	}
	defer authenticator.CloseDBConnection()

	model := &DBModel{}
	valid, err := authenticator.VerifyTokenString(tokenString, model)
	if err != nil {
		fmt.Printf("token verification failed: %v\n", err)
		return
	}

	fmt.Printf("token valid: %v\n", valid)
	if valid {
		fmt.Printf("token id: %s\n", model.TokenID)
	}

	if err := authenticator.ClearTokenFromCache(tokenString); err != nil {
		fmt.Printf("failed to clear token cache: %v\n", err)
	}
}
