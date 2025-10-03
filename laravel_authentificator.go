package golaraauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stremovskyy/cachemar"
	"gorm.io/gorm/logger"
	"io/ioutil"
	"log"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type LaravelAuthenticator struct {
	db        *gorm.DB
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Config    AuthConfig
	cache     cachemar.Cacher
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
	g.cache = config.Cache // Set the cache instance

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

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Silent,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			Colorful:                  false,
		},
	)

	g.db, err = gorm.Open(mysql.Open(getDBConnectionurl(config)), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %s", err.Error())
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

// VerifyTokenString verifies the JWT string and ensures the token reference exists in storage
func (g *LaravelAuthenticator) VerifyTokenString(tokenString string, dbModel interface{}) (bool, error) {
	ctx := context.Background()

	// If cache is available, try to get the result from cache first
	if g.cache != nil {
		cacheKey := fmt.Sprintf("token_verification:%s", tokenString)
		var cachedResult bool
		if err := g.cache.Get(ctx, cacheKey, &cachedResult); err == nil {
			// Found in cache, return the cached result
			if cachedResult {
				// If token was valid in cache, we still need to populate dbModel from cache or DB
				modelCacheKey := fmt.Sprintf("token_model:%s", tokenString)
				if err := g.cache.Get(ctx, modelCacheKey, dbModel); err == nil {
					return true, nil
				}
				// If model not in cache but token was valid, fall through to DB lookup
			} else {
				// Token was invalid according to cache
				return false, fmt.Errorf("token is invalid (cached)")
			}
		}
		// Cache miss, continue with normal validation
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return g.verifyKey, nil
	})
	if err != nil {
		// Cache the invalid result if cache is available
		if g.cache != nil {
			cacheKey := fmt.Sprintf("token_verification:%s", tokenString)
			g.cache.Set(ctx, cacheKey, false, 5*time.Minute, []string{"token_verification"})
		}
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		err := g.db.Table(g.Config.DbConfig.TokensTable).First(dbModel, g.Config.DbConfig.TokensTableCol+" = ?", claims["jti"]).Error
		if err != nil {
			// Cache the invalid result if cache is available
			if g.cache != nil {
				cacheKey := fmt.Sprintf("token_verification:%s", tokenString)
				g.cache.Set(ctx, cacheKey, false, 5*time.Minute, []string{"token_verification"})
			}
			return false, err
		} else {
			// Cache both the validation result and the model if cache is available
			if g.cache != nil {
				cacheKey := fmt.Sprintf("token_verification:%s", tokenString)
				modelCacheKey := fmt.Sprintf("token_model:%s", tokenString)

				// Cache the validation result for 15 minutes
				g.cache.Set(ctx, cacheKey, true, 15*time.Minute, []string{"token_verification"})
				// Cache the model data for 15 minutes
				g.cache.Set(ctx, modelCacheKey, dbModel, 15*time.Minute, []string{"token_model"})
			}
			return true, nil
		}
	} else {
		// Cache the invalid result if cache is available
		if g.cache != nil {
			cacheKey := fmt.Sprintf("token_verification:%s", tokenString)
			g.cache.Set(ctx, cacheKey, false, 5*time.Minute, []string{"token_verification"})
		}
		return false, fmt.Errorf("invalid token claims")
	}
}

// ClearTokenFromCache removes token verification and model data from cache
func (g *LaravelAuthenticator) ClearTokenFromCache(tokenString string) error {
	if g.cache == nil {
		return nil // No cache configured, nothing to clear
	}

	ctx := context.Background()
	cacheKey := fmt.Sprintf("token_verification:%s", tokenString)
	modelCacheKey := fmt.Sprintf("token_model:%s", tokenString)

	// Remove both keys from cache
	g.cache.Remove(ctx, cacheKey)
	g.cache.Remove(ctx, modelCacheKey)

	return nil
}

// ClearAllTokenCache removes all cached token verification data
func (g *LaravelAuthenticator) ClearAllTokenCache() error {
	if g.cache == nil {
		return nil // No cache configured, nothing to clear
	}

	ctx := context.Background()

	// Remove all token verification and model caches
	err := g.cache.RemoveByTag(ctx, "token_verification")
	if err != nil {
		return err
	}

	return g.cache.RemoveByTag(ctx, "token_model")
}
