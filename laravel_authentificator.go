package golaraauth

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/golang-jwt/jwt/v4"
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

	if config.PrivateKey != "" {
		err := g.setPrivateKey(config.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to set private key: %s", err.Error())
		}
	} else if config.PrivateKeyFile != "" {
		err := g.setPrivateKeyFile(config.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to set private key from file: %s", err.Error())
		}
	} else {
		return fmt.Errorf("no private key provided")
	}

	if config.PublicKey != "" {
		err := g.setPublicKey(config.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to set public key: %s", err.Error())
		}
	} else if config.PublicKeyFile != "" {
		err := g.setPublicKeyFile(config.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to set public key from file: %s", err.Error())
		}
	} else {
		return fmt.Errorf("no public key provided")
	}

	err := g.setConnectionToDB(config.DbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %s", err.Error())
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

// base64Decode decodes base64 string or returns original string if decoding fails
func base64Decode(s string) []byte {
	base64Decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte(s)
	}

	return base64Decoded
}

// setPrivateKey Sets private key and puts rsa.private key into structure
func (g *LaravelAuthenticator) setPrivateKey(key string) error {
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(base64Decode(key))
	if err != nil {
		return err
	}

	g.signKey = signKey
	return nil
}

// SetPrivateKeyFile Sets private key file and puts rsa.private key into structure
func (g *LaravelAuthenticator) setPrivateKeyFile(file string) error {
	signBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	return g.setPrivateKey(string(signBytes))
}

// setPublicKey Sets public key and puts rsa.publicKey into structure
func (g *LaravelAuthenticator) setPublicKey(key string) error {
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(base64Decode(key))
	if err != nil {
		return err
	}

	g.verifyKey = verifyKey
	return nil
}

// SetPrivateKeyFile Sets public key file and puts rsa.publicKey into structure
func (g *LaravelAuthenticator) setPublicKeyFile(file string) error {
	verifyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	return g.setPublicKey(string(verifyBytes))
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
