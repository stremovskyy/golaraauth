package golaraauth

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type LaravelAuthenticator struct {
	db        *gorm.DB
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Token     *jwt.Token
	Config    AuthConfig
}

func (g *LaravelAuthenticator) CloseDBConnection() {
	if g.db != nil {
		db, err := g.db.DB()
		if err != nil {
			println(err.Error())
			return
		}

		err = db.Close()
		if err != nil {
			println(err.Error())
		}
	}
}

func (g *LaravelAuthenticator) New(config AuthConfig) error {
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

func getDBConnectionurl(config DbConfig) string {
	return config.Username + ":" + config.Password + "@tcp(" + config.HostName + ":" + config.Port + ")/" + config.DbName + "?charset=utf8&parseTime=True&loc=UTC"
}

func (g *LaravelAuthenticator) setConnectionToDB(config DbConfig) error {
	var err error

	g.db, err = gorm.Open(mysql.Open(getDBConnectionurl(config)))
	if err != nil {
		return err
	}

	return nil
}

// SetPrivateKeyFile Sets private key file and puts rsa.private key into structure
func (g *LaravelAuthenticator) setPrivateKeyFile(file string) error {
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
func (g *LaravelAuthenticator) setPublicKeyFile(file string) error {
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
func (g *LaravelAuthenticator) VerifyTokenString(tokenString string, dbModel interface{}) (bool, error) {
	var err error
	g.Token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return g.verifyKey, nil
	})
	if err != nil {
		return false, err
	}

	if claims, ok := g.Token.Claims.(jwt.MapClaims); ok && g.Token.Valid {
		err := g.db.Table(g.Config.DbConfig.TokensTable).First(dbModel, g.Config.DbConfig.TokensTableCol+" = ?", claims["jti"]).Error
		if err != nil {
			return false, err
		} else {
			return true, nil
		}
	} else {
		return false, err
	}
}
