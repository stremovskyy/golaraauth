package golaraauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	driverMysql "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stremovskyy/cachemar"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type LaravelAuthenticator struct {
	db        *gorm.DB
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	Config    AuthConfig
	cache     cachemar.Cacher
}

const (
	cacheVerificationTag    = "token_verification"
	cacheModelTag           = "token_model"
	invalidTokenCacheTTL    = 5 * time.Minute
	defaultMySQLCharset     = "utf8mb4"
	invalidCachedTokenError = "token is invalid (cached)"
)

var sqlIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)?$`)

func (g *LaravelAuthenticator) CloseDBConnection() {
	if g.db != nil {
		db, err := g.db.DB()
		if err != nil {
			log.Printf("golaraauth: failed to access sql DB handle: %v", err)
			return
		}

		err = db.Close()
		if err != nil {
			log.Printf("golaraauth: failed to close DB connection: %v", err)
		}
	}
}

func (g *LaravelAuthenticator) New(config AuthConfig) error {
	g.Config = config
	g.cache = config.Cache // Set the cache instance

	if config.PrivateKey != "" {
		err := g.setPrivateKey(config.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to set private key: %w", err)
		}
	} else if config.PrivateKeyFile != "" {
		err := g.setPrivateKeyFile(config.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to set private key from file: %w", err)
		}
	}

	if config.PublicKey != "" {
		err := g.setPublicKey(config.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to set public key: %w", err)
		}
	} else if config.PublicKeyFile != "" {
		err := g.setPublicKeyFile(config.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to set public key from file: %w", err)
		}
	} else {
		return errors.New("no public key provided")
	}

	if !isSafeSQLIdentifier(config.DbConfig.TokensTable) {
		return fmt.Errorf("invalid tokens table name: %q", config.DbConfig.TokensTable)
	}
	if !isSafeSQLIdentifier(config.DbConfig.TokensTableCol) {
		return fmt.Errorf("invalid token column name: %q", config.DbConfig.TokensTableCol)
	}

	err := g.setConnectionToDB(config.DbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	return nil
}

func getDBConnectionURL(config DbConfig) string {
	mysqlConfig := driverMysql.NewConfig()
	mysqlConfig.User = config.Username
	mysqlConfig.Passwd = config.Password
	mysqlConfig.Net = "tcp"
	mysqlConfig.DBName = config.DbName
	mysqlConfig.ParseTime = true
	mysqlConfig.Loc = time.UTC
	mysqlConfig.Params = map[string]string{
		"charset": defaultMySQLCharset,
	}

	switch {
	case config.HostName != "" && config.Port != "":
		mysqlConfig.Addr = net.JoinHostPort(config.HostName, config.Port)
	case config.HostName != "":
		mysqlConfig.Addr = config.HostName
	}

	if config.Charset != "" {
		mysqlConfig.Params["charset"] = config.Charset
	}
	if config.TLSConfig != "" {
		mysqlConfig.TLSConfig = config.TLSConfig
	}
	if config.Timeout > 0 {
		mysqlConfig.Timeout = config.Timeout
	}
	if config.ReadTimeout > 0 {
		mysqlConfig.ReadTimeout = config.ReadTimeout
	}
	if config.WriteTimeout > 0 {
		mysqlConfig.WriteTimeout = config.WriteTimeout
	}
	for key, value := range config.Params {
		mysqlConfig.Params[key] = value
	}

	return mysqlConfig.FormatDSN()
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

	g.db, err = gorm.Open(mysql.Open(getDBConnectionURL(config)), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	return nil
}

// base64Decode decodes base64 string or returns original string if decoding fails
func base64Decode(s string) []byte {
	trimmed := strings.TrimSpace(s)
	base64Decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return []byte(trimmed)
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
	signBytes, err := os.ReadFile(filepath.Clean(file))
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
	verifyBytes, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return err
	}

	return g.setPublicKey(string(verifyBytes))
}

// VerifyTokenString verifies the JWT string and ensures the token reference exists in storage
func (g *LaravelAuthenticator) VerifyTokenString(tokenString string, dbModel interface{}) (bool, error) {
	ctx := context.Background()

	if dbModel == nil {
		return false, errors.New("dbModel must not be nil")
	}

	// Only negative verification results are trusted from cache.
	if g.cache != nil {
		cacheKey := tokenVerificationCacheKey(tokenString)
		var cachedResult bool
		if err := g.cache.Get(ctx, cacheKey, &cachedResult); err == nil && !cachedResult {
			return false, errors.New(invalidCachedTokenError)
		}
	}

	if g.verifyKey == nil {
		return false, errors.New("public key is not initialized")
	}

	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return g.verifyKey, nil
	})
	if err != nil {
		g.cacheInvalidToken(ctx, tokenString)
		return false, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		g.cacheInvalidToken(ctx, tokenString)
		return false, errors.New("invalid token claims")
	}

	jti, err := tokenJTI(claims)
	if err != nil {
		g.cacheInvalidToken(ctx, tokenString)
		return false, err
	}

	if g.db == nil {
		return false, errors.New("database connection is not initialized")
	}

	err = g.db.Table(g.Config.DbConfig.TokensTable).
		First(dbModel, g.Config.DbConfig.TokensTableCol+" = ?", jti).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, err
		}
		return false, err
	}

	return true, nil
}

// ClearTokenFromCache removes token verification and model data from cache
func (g *LaravelAuthenticator) ClearTokenFromCache(tokenString string) error {
	if g.cache == nil {
		return nil // No cache configured, nothing to clear
	}

	ctx := context.Background()
	cacheKey := tokenVerificationCacheKey(tokenString)
	modelCacheKey := tokenModelCacheKey(tokenString)

	// Remove both keys from cache
	return errors.Join(
		g.cache.Remove(ctx, cacheKey),
		g.cache.Remove(ctx, modelCacheKey),
	)
}

// ClearAllTokenCache removes all cached token verification data
func (g *LaravelAuthenticator) ClearAllTokenCache() error {
	if g.cache == nil {
		return nil // No cache configured, nothing to clear
	}

	ctx := context.Background()

	// Remove all token verification and model caches
	return errors.Join(
		g.cache.RemoveByTag(ctx, cacheVerificationTag),
		g.cache.RemoveByTag(ctx, cacheModelTag),
	)
}

func (g *LaravelAuthenticator) cacheInvalidToken(ctx context.Context, tokenString string) {
	if g.cache == nil {
		return
	}

	cacheKey := tokenVerificationCacheKey(tokenString)
	if err := g.cache.Set(ctx, cacheKey, false, invalidTokenCacheTTL, []string{cacheVerificationTag}); err != nil {
		log.Printf("golaraauth: failed to cache invalid token result: %v", err)
	}
}

func tokenJTI(claims jwt.MapClaims) (string, error) {
	rawJTI, ok := claims["jti"]
	if !ok {
		return "", errors.New("token is missing jti claim")
	}

	jti, ok := rawJTI.(string)
	if !ok || jti == "" {
		return "", errors.New("token jti claim must be a non-empty string")
	}

	return jti, nil
}

func tokenVerificationCacheKey(tokenString string) string {
	return fmt.Sprintf("%s:%s", cacheVerificationTag, tokenCacheDigest(tokenString))
}

func tokenModelCacheKey(tokenString string) string {
	return fmt.Sprintf("%s:%s", cacheModelTag, tokenCacheDigest(tokenString))
}

func tokenCacheDigest(tokenString string) string {
	sum := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(sum[:])
}

func isSafeSQLIdentifier(identifier string) bool {
	return sqlIdentifierPattern.MatchString(identifier)
}
