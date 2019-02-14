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
	HostName   string
	Port       string
	Username   string
	Password   string
	DbName     string
	UsersTable string
}

type LaravelAuthentificator interface {
	New(config AuthConfig) error
	SetConnectionToDB(config DbConfig) error
	SetPrivateKeyFile(file string) error
	SetPublicKeyFile(file string) error
	VerifyTokenString(tokenString string) (bool, error)
}

type GoLaraAuth struct {
	db        *gorm.DB
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Token     *jwt.Token
}

func (g *GoLaraAuth) New(config AuthConfig) error {
	if config.PrivateKeyFile != "" {
		err := g.SetPrivateKeyFile(config.PrivateKeyFile)
		if err != nil {
			return err
		}
	}
	if config.PublicKeyFile != "" {
		err := g.SetPublicKeyFile(config.PublicKeyFile)
		if err != nil {
			return err
		}
	}
	err := g.SetConnectionToDB(config.DbConfig)
	if err != nil {
		return err
	}

	return nil
}

func (g *GoLaraAuth) SetConnectionToDB(config DbConfig) error {
	var err error
	g.db, err = gorm.Open("mysql", config.Username+":"+config.Password+"@tcp("+config.HostName+":"+config.Port+")/"+config.DbName+"?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		return err
	}

	return nil
}

// SetPrivateKeyFile Sets private key file and puts rsa.private key into structure
func (g *GoLaraAuth) SetPrivateKeyFile(file string) error {
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
func (g *GoLaraAuth) SetPublicKeyFile(file string) error {
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
func (g *GoLaraAuth) VerifyTokenString(tokenString string) (bool, error) {
	var err error
	g.Token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return g.verifyKey, nil
	})
	if err != nil {
		return false, err
	}

	if claims, ok := g.Token.Claims.(jwt.MapClaims); ok && g.Token.Valid {
		fmt.Println(claims["jti"], claims["aud"])
	} else {
		return false, err
	}

	return g.Token.Valid, nil
}
