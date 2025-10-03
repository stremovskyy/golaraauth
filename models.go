package golaraauth

import "github.com/stremovskyy/cachemar"

type AuthConfig struct {
	DbConfig       DbConfig
	PrivateKeyFile string
	PublicKeyFile  string
	PrivateKey     string
	PublicKey      string
	Cache          cachemar.Cacher // Optional cache instance
}

type DbConfig struct {
	HostName       string
	Port           string
	Username       string
	Password       string
	DbName         string
	TokensTable    string
	TokensTableCol string
}
