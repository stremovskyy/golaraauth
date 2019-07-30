package golaraauth

type Authenticator interface {
	New(config AuthConfig) error
	setConnectionToDB(config DbConfig) error
	setPrivateKeyFile(file string) error
	setPublicKeyFile(file string) error
	VerifyTokenString(tokenString string, dbModel interface{}) (bool, error)
}
