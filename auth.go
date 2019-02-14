package golaraauth

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"io/ioutil"
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

type LaravelAuthentificator interface {
	New(config AuthConfig) error
	setConnectionToDB(config DbConfig) error
	setPrivateKeyFile(file string) error
	setPublicKeyFile(file string) error
	VerifyTokenString(tokenString string, dbModel interface{}) (bool, interface{}, error)
}

type GoLaraAuth struct {
	db        *gorm.DB
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Token     *jwt.Token
	Config    AuthConfig
}

func (g *GoLaraAuth) New(config AuthConfig) error {
	g.Config = config
	if config.PrivateKeyFile != "" {
		err := g.setPrivateKeyFile(config.PrivateKeyFile)
		if err != nil {
			return err
		}
	}
	if config.PublicKeyFile != "" {
		err := g.setPublicKeyFile(config.PublicKeyFile)
		if err != nil {
			return err
		}
	}
	err := g.setConnectionToDB(config.DbConfig)
	if err != nil {
		return err
	}

	return nil
}

func (g *GoLaraAuth) setConnectionToDB(config DbConfig) error {
	var err error
	g.db, err = gorm.Open("mysql", config.Username+":"+config.Password+"@tcp("+config.HostName+":"+config.Port+")/"+config.DbName+"?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		return err
	}

	return nil
}

// SetPrivateKeyFile Sets private key file and puts rsa.private key into structure
func (g *GoLaraAuth) setPrivateKeyFile(file string) error {
	signBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	g.signKey = signKey
	return nil
}

// SetPrivateKeyFile Sets public key file and puts rsa.publicKey into structure
func (g *GoLaraAuth) setPublicKeyFile(file string) error {
	verifyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	g.verifyKey = verifyKey
	return nil
}

// VerifyTokenString verifies token string and puts Token object into structure
func (g *GoLaraAuth) VerifyTokenString(tokenString string, dbModel interface{}) (bool, interface{}, error) {
	var err error
	g.Token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return g.verifyKey, nil
	})
	if err != nil {
		return false, nil, err
	}

	if claims, ok := g.Token.Claims.(jwt.MapClaims); ok && g.Token.Valid {
		err := g.db.First(dbModel, g.Config.DbConfig.TokensTableCol+" = ?", claims["jti"]).Error
		if err != nil {
			return false, nil, err
		} else {
			return true, dbModel, nil
		}
	} else {
		return false, nil, err
	}
}
