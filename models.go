package golaraauth

type AuthConfig struct {
	DbConfig       DbConfig
	PrivateKeyFile string
	PublicKeyFile  string
	PrivateKey     string
	PublicKey      string
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
