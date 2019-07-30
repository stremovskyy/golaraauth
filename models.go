package golaraauth

import (
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

type AuthConfig struct {
	DbConfig       DbConfig
	PrivateKeyFile string
	PublicKeyFile  string
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
