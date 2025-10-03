package golaraauth

type Authenticator interface {
	New(config AuthConfig) error
	setConnectionToDB(config DbConfig) error
	CloseDBConnection()
	setPrivateKeyFile(file string) error
	setPublicKeyFile(file string) error
	VerifyTokenString(tokenString string, dbModel interface{}) (bool, error)
	ClearTokenFromCache(tokenString string) error
	ClearAllTokenCache() error
}
