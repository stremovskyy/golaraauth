package golaraauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
	"testing"
	"time"

	driverMysql "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stremovskyy/cachemar"
	"github.com/stremovskyy/cachemar/drivers/memory"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type testTokenRecord struct {
	ID        uint   `gorm:"primaryKey"`
	TokenID   string `gorm:"column:token_id"`
	Subject   string `gorm:"column:subject"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func TestVerifyTokenStringAcceptsValidTokenBackedByDB(t *testing.T) {
	privateKey, publicKey := loadSampleKeyPair(t)
	db := newTestDB(t)
	record := testTokenRecord{TokenID: "valid-token-id", Subject: "user-1"}
	if err := db.Create(&record).Error; err != nil {
		t.Fatalf("failed to insert token record: %v", err)
	}

	auth := &LaravelAuthenticator{
		db:        db,
		verifyKey: publicKey,
		Config: AuthConfig{
			DbConfig: DbConfig{
				TokensTable:    "test_token_records",
				TokensTableCol: "token_id",
			},
		},
	}

	tokenString := signToken(t, privateKey, jwt.MapClaims{
		"jti": "valid-token-id",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	})

	var result testTokenRecord
	valid, err := auth.VerifyTokenString(tokenString, &result)
	if err != nil {
		t.Fatalf("VerifyTokenString returned unexpected error: %v", err)
	}
	if !valid {
		t.Fatalf("VerifyTokenString returned invalid for a valid token")
	}
	if result.TokenID != record.TokenID {
		t.Fatalf("expected token record %q, got %q", record.TokenID, result.TokenID)
	}
}

func TestVerifyTokenStringRejectsRevokedTokenEvenIfLegacyPositiveCacheExists(t *testing.T) {
	privateKey, publicKey := loadSampleKeyPair(t)
	manager := newMemoryCacheManager(t)
	auth := &LaravelAuthenticator{
		db:        newTestDB(t),
		verifyKey: publicKey,
		Config: AuthConfig{
			DbConfig: DbConfig{
				TokensTable:    "test_token_records",
				TokensTableCol: "token_id",
			},
			Cache: manager.Current(),
		},
		cache: manager.Current(),
	}

	tokenString := signToken(t, privateKey, jwt.MapClaims{
		"jti": "revoked-token-id",
		"sub": "user-2",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	})

	legacyModel := &testTokenRecord{TokenID: "revoked-token-id", Subject: "cached-user"}
	if err := manager.Current().Set(context.Background(), tokenVerificationCacheKey(tokenString), true, time.Minute, []string{cacheVerificationTag}); err != nil {
		t.Fatalf("failed to seed verification cache: %v", err)
	}
	if err := manager.Current().Set(context.Background(), tokenModelCacheKey(tokenString), legacyModel, time.Minute, []string{cacheModelTag}); err != nil {
		t.Fatalf("failed to seed model cache: %v", err)
	}

	var result testTokenRecord
	valid, err := auth.VerifyTokenString(tokenString, &result)
	if err == nil {
		t.Fatalf("expected an error for revoked token")
	}
	if valid {
		t.Fatalf("expected revoked token to be rejected even with cached positive result")
	}
	if result.TokenID != "" {
		t.Fatalf("expected model to stay empty on revoked token, got %+v", result)
	}
}

func TestVerifyTokenStringCachesOnlyInvalidJWTResults(t *testing.T) {
	manager := newMemoryCacheManager(t)
	auth := &LaravelAuthenticator{
		db:        newTestDB(t),
		verifyKey: loadSamplePublicKey(t),
		Config: AuthConfig{
			DbConfig: DbConfig{
				TokensTable:    "test_token_records",
				TokensTableCol: "token_id",
			},
			Cache: manager.Current(),
		},
		cache: manager.Current(),
	}

	var result testTokenRecord
	const malformedToken = "not-a-jwt"

	valid, err := auth.VerifyTokenString(malformedToken, &result)
	if err == nil {
		t.Fatalf("expected malformed token to fail")
	}
	if valid {
		t.Fatalf("expected malformed token to be invalid")
	}

	var cachedResult bool
	if err := manager.Current().Get(context.Background(), tokenVerificationCacheKey(malformedToken), &cachedResult); err != nil {
		t.Fatalf("expected malformed token result to be cached: %v", err)
	}
	if cachedResult {
		t.Fatalf("expected malformed token cache entry to be false")
	}

	var legacyCacheResult bool
	if err := manager.Current().Get(context.Background(), "token_verification:"+malformedToken, &legacyCacheResult); err == nil {
		t.Fatalf("raw token cache key should not exist anymore")
	}
}

func TestVerifyTokenStringRejectsWrongSignature(t *testing.T) {
	manager := newMemoryCacheManager(t)
	auth := &LaravelAuthenticator{
		db:        newTestDB(t),
		verifyKey: loadSamplePublicKey(t),
		Config: AuthConfig{
			DbConfig: DbConfig{
				TokensTable:    "test_token_records",
				TokensTableCol: "token_id",
			},
			Cache: manager.Current(),
		},
		cache: manager.Current(),
	}

	tokenString := signToken(t, generateDifferentPrivateKey(t), jwt.MapClaims{
		"jti": "wrong-signature-token",
		"sub": "user-3",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	})

	var result testTokenRecord
	valid, err := auth.VerifyTokenString(tokenString, &result)
	if err == nil {
		t.Fatalf("expected wrong-signature token to fail")
	}
	if valid {
		t.Fatalf("expected wrong-signature token to be invalid")
	}

	var cachedResult bool
	if err := manager.Current().Get(context.Background(), tokenVerificationCacheKey(tokenString), &cachedResult); err != nil {
		t.Fatalf("expected wrong-signature result to be cached: %v", err)
	}
	if cachedResult {
		t.Fatalf("expected wrong-signature token cache entry to be false")
	}
}

func TestClearTokenFromCacheUsesHashedKeys(t *testing.T) {
	manager := newMemoryCacheManager(t)
	auth := &LaravelAuthenticator{cache: manager.Current()}
	tokenString := "token-to-clear"

	if err := manager.Current().Set(context.Background(), tokenVerificationCacheKey(tokenString), false, time.Minute, []string{cacheVerificationTag}); err != nil {
		t.Fatalf("failed to seed verification cache: %v", err)
	}
	if err := manager.Current().Set(context.Background(), tokenModelCacheKey(tokenString), testTokenRecord{TokenID: "cached"}, time.Minute, []string{cacheModelTag}); err != nil {
		t.Fatalf("failed to seed model cache: %v", err)
	}

	if err := auth.ClearTokenFromCache(tokenString); err != nil {
		t.Fatalf("ClearTokenFromCache returned error: %v", err)
	}

	var cachedVerification bool
	if err := manager.Current().Get(context.Background(), tokenVerificationCacheKey(tokenString), &cachedVerification); err == nil {
		t.Fatalf("verification cache entry should have been removed")
	}

	var cachedModel testTokenRecord
	if err := manager.Current().Get(context.Background(), tokenModelCacheKey(tokenString), &cachedModel); err == nil {
		t.Fatalf("model cache entry should have been removed")
	}
}

func TestNewDoesNotRequirePrivateKey(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("example/with_keys/keys/dev.rsa.pub")
	if err != nil {
		t.Fatalf("failed to read sample public key: %v", err)
	}

	auth := &LaravelAuthenticator{}
	err = auth.New(AuthConfig{
		DbConfig: DbConfig{
			HostName:       "127.0.0.1",
			Port:           "65000",
			Username:       "user",
			Password:       "p@ss:w/or?d",
			DbName:         "db",
			TokensTable:    "test_token_records",
			TokensTableCol: "token_id",
		},
		PublicKey: string(publicKeyBytes),
	})
	if err == nil {
		t.Fatalf("expected database connection error")
	}
	if strings.Contains(err.Error(), "no private key provided") {
		t.Fatalf("private key should be optional, got error: %v", err)
	}
}

func TestNewRejectsUnsafeIdentifiersBeforeDBConnect(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("example/with_keys/keys/dev.rsa.pub")
	if err != nil {
		t.Fatalf("failed to read sample public key: %v", err)
	}

	auth := &LaravelAuthenticator{}
	err = auth.New(AuthConfig{
		DbConfig: DbConfig{
			HostName:       "127.0.0.1",
			Port:           "3306",
			Username:       "user",
			Password:       "password",
			DbName:         "db",
			TokensTable:    "tokens;DROP TABLE tokens",
			TokensTableCol: "token_id",
		},
		PublicKey: string(publicKeyBytes),
	})
	if err == nil {
		t.Fatalf("expected invalid identifier error")
	}
	if !strings.Contains(err.Error(), "invalid tokens table name") {
		t.Fatalf("expected invalid table name error, got: %v", err)
	}
}

func TestGetDBConnectionURLUsesEscapedDSNAndOptions(t *testing.T) {
	dsn := getDBConnectionURL(DbConfig{
		HostName:       "db.internal",
		Port:           "3307",
		Username:       "user",
		Password:       "p@ss:w/or?d",
		DbName:         "service",
		TokensTable:    "tokens",
		TokensTableCol: "token_id",
		TLSConfig:      "preferred",
		Charset:        "utf8mb4",
		Timeout:        3 * time.Second,
		ReadTimeout:    4 * time.Second,
		WriteTimeout:   5 * time.Second,
		Params: map[string]string{
			"interpolateParams": "true",
		},
	})

	cfg, err := driverMysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("generated DSN should be parseable: %v", err)
	}
	if cfg.Passwd != "p@ss:w/or?d" {
		t.Fatalf("expected password to round-trip, got %q", cfg.Passwd)
	}
	if cfg.Addr != "db.internal:3307" {
		t.Fatalf("expected addr db.internal:3307, got %q", cfg.Addr)
	}
	if cfg.TLSConfig != "preferred" {
		t.Fatalf("expected TLS config preferred, got %q", cfg.TLSConfig)
	}
	if cfg.Timeout != 3*time.Second || cfg.ReadTimeout != 4*time.Second || cfg.WriteTimeout != 5*time.Second {
		t.Fatalf("expected timeouts to be preserved, got timeout=%v read=%v write=%v", cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout)
	}
	if !strings.Contains(dsn, "charset=utf8mb4") || !strings.Contains(dsn, "interpolateParams=true") {
		t.Fatalf("expected generated DSN to contain custom params, got %q", dsn)
	}
}

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite DB: %v", err)
	}
	if err := db.AutoMigrate(&testTokenRecord{}); err != nil {
		t.Fatalf("failed to migrate sqlite schema: %v", err)
	}

	return db
}

func newMemoryCacheManager(t *testing.T) cachemar.Manager {
	t.Helper()

	manager := cachemar.New()
	memoryCache := memory.NewWithConfig(memory.Config{MaxSize: 128})
	manager.Register("memory", memoryCache)
	manager.SetCurrent("memory")

	t.Cleanup(func() {
		_ = manager.Close()
	})

	return manager
}

func loadSampleKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	privateKeyBytes, err := os.ReadFile("example/with_keys/keys/dev.rsa")
	if err != nil {
		t.Fatalf("failed to read sample private key: %v", err)
	}
	publicKeyBytes, err := os.ReadFile("example/with_keys/keys/dev.rsa.pub")
	if err != nil {
		t.Fatalf("failed to read sample public key: %v", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse sample private key: %v", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse sample public key: %v", err)
	}

	return privateKey, publicKey
}

func loadSamplePublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	_, publicKey := loadSampleKeyPair(t)
	return publicKey
}

func signToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

func generateDifferentPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return key
}
