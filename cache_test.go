package golaraauth

import (
	"testing"
	"time"

	"github.com/stremovskyy/cachemar"
	"github.com/stremovskyy/cachemar/drivers/memory"
)

func TestLaravelAuthenticator_CacheIntegration(t *testing.T) {
	// Create a cache manager with memory driver
	manager := cachemar.New()
	memoryCache := memory.NewWithConfig(memory.Config{MaxSize: 100})
	manager.Register("memory", memoryCache)
	manager.SetCurrent("memory")

	// Test cache connectivity
	if err := manager.Ping(); err != nil {
		t.Fatalf("Cache ping failed: %v", err)
	}

	// Create config with cache
	config := AuthConfig{
		Cache: manager.Current(),
	}

	// Create authenticator
	auth := &LaravelAuthenticator{}
	auth.Config = config
	auth.cache = config.Cache

	// Test cache methods
	tokenString := "test-token-123"

	// Test ClearTokenFromCache
	err := auth.ClearTokenFromCache(tokenString)
	if err != nil {
		t.Errorf("ClearTokenFromCache failed: %v", err)
	}

	// Test ClearAllTokenCache
	err = auth.ClearAllTokenCache()
	if err != nil {
		t.Errorf("ClearAllTokenCache failed: %v", err)
	}

	// Test that cache is properly assigned
	if auth.cache == nil {
		t.Error("Cache was not properly assigned to authenticator")
	}

	// Test cache operations
	ctx := manager.Current()
	err = ctx.Set(nil, "test-key", "test-value", time.Minute, []string{"test"})
	if err != nil {
		t.Errorf("Failed to set cache value: %v", err)
	}

	var value string
	err = ctx.Get(nil, "test-key", &value)
	if err != nil {
		t.Errorf("Failed to get cache value: %v", err)
	}

	if value != "test-value" {
		t.Errorf("Expected 'test-value', got '%s'", value)
	}

	// Clean up
	manager.Close()
}

func TestAuthConfigWithoutCache(t *testing.T) {
	// Test that authenticator works without cache (backward compatibility)
	config := AuthConfig{
		Cache: nil, // No cache provided
	}

	auth := &LaravelAuthenticator{}
	auth.Config = config
	auth.cache = config.Cache

	// Test cache methods with nil cache
	err := auth.ClearTokenFromCache("test-token")
	if err != nil {
		t.Errorf("ClearTokenFromCache should not fail with nil cache: %v", err)
	}

	err = auth.ClearAllTokenCache()
	if err != nil {
		t.Errorf("ClearAllTokenCache should not fail with nil cache: %v", err)
	}

	// Verify cache is nil
	if auth.cache != nil {
		t.Error("Cache should be nil when not provided in config")
	}
}
