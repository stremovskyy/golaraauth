package main

import (
	"fmt"
	"time"

	"github.com/stremovskyy/cachemar"
	"github.com/stremovskyy/cachemar/drivers/memory"
	"github.com/stremovskyy/golaraauth"
)

const tokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNTQxNTYxMGMwOWRmNzRmMjk4NGZlY2I1MmRiOWQ4NmI1MmRhMThmMGRjNzY1ZDM4OGQ3YzUwYzlkMmUzNGQ5ZTgwNzgzZGRkNjM1YjgxMGIiLCJpYXQiOjE2NTk2MDMxNTUuMDAzODk3LCJuYmYiOjE2NTk2MDMxNTUuMDAzODk5LCJleHAiOjE2OTExMzkxNTQuOTkyODk1LCJzdWIiOiI1Iiwic2NvcGVzIjpbXX0.bveK906BK-vZSRoDWEDuR7vf561ksYqeUK53AwmLuLJrnhuOfPuM82FEMiBcp_0gpatxUyJrJgGqmFTdCCtQmR-CIeX4RNTiHCUr7-AgE-qLC31x4RiTbo54yLxeXJzcO-kI6yA0hM-7mUV9JcmXqLwIXIJOOzQNms31YDU78EzEVc40veh3cxGLoK8YPWStYQk8kp8ic38U1u49d7-kQWm7ET2Qd-JzwHD9zsQnXA4ZZqD1tjvfQ2ew7xFMYYTuK26sXAnlgwzBOKyQCmtnPeWdyQ0PTiNYA6XXJiS1b67YrjR2xPQCv6K9hKQbOYypxhuBemcHLJjnClHFTAhMAWyilUMoi_lls_zlFRvob_1GMNLZlSPhxnGisM0u0Mhryrh199Br297pBoVoGyPntwDvRF64OTBD1zkjSxd6_nuhSaUN9VjjQlbn0IA5zc1t7kMhbLSPNSF19uIVfyVXQTfVV12kTp_3gVYx-xNe99roL3CuYExGzi0rNLxTv3O0XfoU-lSX3jbER2p4FHlpMkitLaptwpc2wfScNCT_Rzer8Sa1t4lO30INASV9veDuHN3dIDEOwP_LpRx0k6Bv0UcUr9ZWv_7kS9gXk8M1x4NZI6mT-TXDq9doijpt1MiN2zTfWkNVzuqiNqQH0euDHEr1ARCO5ULp49uvMgCw0tY"

const (
	privKey = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlKS1FJQkFBS0NBZ0VBeC9ocUVBQ2xxZm44OHhlTTFmWHpJa3FIcFU0UktCM1VLVG1Tbjd2UVRkUnoyT1BPClZrVGV6eWtkNUtXb3BzSzliR3RkR3J1all6enBWckFtWlBoM2c4emJFM3VzejQ5YUd2dGNUMWFraEVGUlF2ZXoKT0tIQlNaSDBTSXVZUlhsUVdMRDdLSWFsbXlSZTFvYzY1bzdlVG9URi81ZC9WUEpucE1BT25tZElhbkprdTljQQp3azlCVnJ5QllEVm0xR1NEazZsemxLN0hxRjRObDZXQ2sxWkhFa2ZtZ2VlTTZZYjYxRmtPSCtYdmxFNTRpV3JXCi9NMWR3QzhqR2oxMEtLZFFNbXl0Qm9Za3NhSjBIWDVNMXByMzJtSUZyR2FrczA1QVBXd1ladFRVb0tyRnFyMmIKZGk0QzROR0tjTEhzQzRQOTJ6NXhOOWsrOTlFQUZiZmFraE9ybG9MRHR4WjNaYzlpdDlrN2xGQUV5Y0dwM3dRWQpLTVlZbERPRjNBUmhMell4RGtiTTU4VWJGREVHTXJYSHF5bmwreGppaldHalN1aEx5UWNOSlYxWEQ4S1RiNXFUClVQY0U5UzhZbGNzcHV2aXhlQkdONTdkVThhNy9GdWZqSUlySTdMUWpna3RGNEtJTDRieERnMlF6RWF1VDAwQVgKV2lseW0zZGdxUzQ1RnkwR3pGZjdOdnFRaXNReGhwT285Tmw3LzhsWTBCNUVmbU44aGNoU1dKMTQvOHlEQzNraApZc2JoTHA1ZUp5TW12UVVtN0sreEVoTTFwNU91ZHBZcXB3dWFmN3ZhcFRoVUJDWjRGdklBNmZINmF1Q0xtWlArCjlKZ2JySjhNbVdTZ2V3b3czTVZyWmt2b1N3RzVWQjZScVVyRWc0S2hROUM5YVFUQUpNOW9vUUxxck9VQ0F3RUEKQVFLQ0FnQnRUaVV6a0JiOTNXN2R0ZDYreVl6WURxTXN3WXB4UWpUSlAvWWNwLzNKdlRxQnNLd0Z6ZWw0bFVJSQp6R0J1bnY0SnVIb1E5Y1h1cGNucUg2a3RBZi9hSkcwUHJrZWN3UUFBeGFzRWx4aWdUay9MNmplbDJnMGNXTktOCm9QaGY2VnI0eit6Smp5Z1FzSVhDZi9LN09oYmNGb2xnRjRCN2YzRVZ4Z0YzcG44WDZHV1ZvNFYvc1BESEo0MFUKZUx3M2xxV3hYaXVXZHg4ZHNpTjk0L09HODk4dlordmcwQi9mT20vN0NKN0c0dG5kV0ROYzhmQ0lDUDJZNG1zdQptYTdYMWZUcFN5d2M1OUJBNU1yUm9Fc0I5MzFKZXRFZEZwSXFqTGhpbXFhUDl3QXV2b29EdFZhMzk1aU5LUnlpClV5N3ljSGlma2ZjekR1WHpjZU80KzJGVy9iZUpPcmN3eXBtUnZFRWVhSEdzdGszUzhHVkhaUHZpQWNQcFU5SHgKZUlOcnlLSHpYcnF5SWZheDFEV0tpdEtaWEpxQVU5a2V4VlZYZnNjTk5MNFBGY0YrdnpmekZObWpBT05xZ3dnbwpGOXJsS01yVEhkOEJjZHRhWmdyVDN5a0VJeFR0dWIvQjVsL3R6QXlyREtpQ0lrcUpSZU1DZVBFbmJkMmZDaDBKCjF1Qi9NYWhncXVRQzZURjlQSnpKb3hpclpZK1NHUWluckNFZUcyQVJMR29BT3NYeW1aZ2djbGJDMjFJK3J5aTgKVUpEUjhRQzRERGN0QW1YTmhlL0RaQ1pHMUluVi9ydEowTWtPYmpXUElXUlVEcVRGcVF1Qy82dzRnWng1Tm9CSgpVVzMrekV2aHpuS0x0ZHNyWGd3T0w5VTlWdVVvTzhTWlNoYlBPVWRtUWE1eGFINUJWUUtDQVFFQTlvNzB5b3Y2CjZ1TzhOWTFhaXZFSEpkZ3UvbWxpbk5ZOVFvWjdjdEpndmVpRzY5OWczYXJYa056MFNkbTFsWlZjeWNUOHhycEwKc09QRFJmVzJmRnNsdVRTVHV0OTdJUFlWbmhtdlovejFhVWNrdWJEVWp0TUZMUEFNYVUzUFFLcC93bzh3T3ZsOQpzT1dhRXQ3aW95ZDRYRVh3TVZTQnlWSkVFKzdzdU83YStYcUlwM2pUa2Z1MTdpSlQ2WTZSS1FJNCtXbWVVbUlsCnAvdEJ5Y2lQd3hoYzdXOE1tdDZnMTFpSEdLTmFGbGZKR2swTEdBK0ZMc2d1VVM5OFkrQ3Bya1BMOXRVQ1lFbFkKNU9BTFZFU3IwYzVmSmczeERPQ3ZGVnBmUXVTQkFBWEcyajZRZ0N4WGkxeVpHNHpUelZIR0tYMjRRckU5V2V4YQpKc0tWYWVvSXBvd0Rnd0tDQVFFQXo2Qy8ycUo4MmpNSEplQ2doTXI1VTI3bVBTZzBBalp1N1JZdHh1WHdSME1QCjFGQkNzRHdpa0Y5VjVzMFQvZ21YbzV3STR6Tmwwa2FnMEtQTzNsbWVqWWM3cUFyWld3TFNabGxwMWR1aUZOSlQKVnBjMSs1M0J0Tkwyam5oZHNBUkhZTTZvYXYveEhlRzMxMVVTY2ZYTWZQbFEwVFM5VEZoY2lTQTU5ZzVJNkFJTAo2VDdrdCtpMExWWVlFdmpaT3F1SC9nN1k2NHNsZTdIaWZwNkJESlh6b21pT2pCejVWVElTQnZQSUlacGZ6amZ3CmxCVzlWU1dQd2d3ZEJVNUhFSzdyT0c2UGY1MXNPWFJWU1lOMmFPTG0zTCtzenAxb3ZGNUhKSmRLekNpSXBuZ2gKMGNaVnYwbnUvYWREMDBCRHhsMlc3T3U4c2hZKzdNNnRTN2hiamNuWmR3S0NBUUJ5RmlJVkd3S0c3OHZsNTd0dQpzU3JDaXk3cmorNE9ibCs0U2F3VHJGOFJZT2dWZXE1Q3c4dXRmMkFXVUFQaTdGTWNGZWQxT1R6TzVBVTJlUVR3CnMraFhzNGxzSGY3R2VMZjJDU0tOOXBIRUhpUlRQQXlPN2Z2bUdFbFY3S2dxM3ZueEYvcVVQMSsybS9kWUpnUXUKeEpPLzlxaTIyc2lYVkZhbDlwZFkxMFZCelQ0d2FBdFY4R2YxZ2JMY1RwakNwZ0dnL3d0QVNhUHMvNmtvYW9LRApIdUhaQjlxSVN0Mlg1NkhUZDdxMnZmWVRFblZBcytYSGlOOU50N0JTTXVHdy9qUUJ5ZnlvZXlnRDk5dW1LWVJyCnQ1ZDFiMXdMdm1lbGRNVEJtaVJLMDJGNUdSd2FBdXFiVk1TUDUvRVZmM0kzUHJJbFFnZ0dkUVFlRFVtLzBZZ2gKTUlackFvSUJBUUNwVDBwanZWRFdsZm5rTjFKdU54NHRuU2QvQTRPMXNqR3VnQUdBU2cwdjcwMi9NbHZQWHBwSQo1SlVtQ21HZExMRk5KM1pQMzUvT1l1M01kV2ZDQlk2M2xtbGRWTXQ5M2NVNDFQenErWmtvSllMei80WnowbWNkClQxTGpSdUFQSXM0WjhTdUJaWWgzZDVMMHMxakJPVkV4TUJWcEkvcWhnUVNraFhUK1l4T3NyYzZNdTA3RGNhMUwKc3dNYXBYWnUwMldvRk85cTFDTVN4VElQVXEybFY3bysyOGd5RllaMHBNbnloV1RUa2hGQ0ZuZkdLaHdrak9hMwp0QzBPSUpEdTE5VFVSY1FhcW9LUUwzOUUzVUQzc3QvVGJ6STVvajdBTEprVEM1UmcrMFREaXY3NUV5VGxRaUx6CkVTekwzWUhuQm5hR2FJMk5JM3JZbklqUVVGdklPYXR0QW9JQkFRQzcrMitLNmM1a0ZMRUtSa3l6YmRmeWNwcWQKZnova0Y1eDh5OGhNNm4wZzRtQTdzRUdITlRSdUp5b2dwWDArMVdOeTluQjljRUk4bXVtRENHTjNmTFZYM3FzRApVM1ZQaDE1aUpYWmNHRmp3dW0vK1htNlhJYW1mK21wQytUbm00V01INGY4TjhYR0ZIdEFjSDZOMzJEK2xkOURlCkVRWXBFK01OTkZzNEJzdWM0T0FXd2ZGaFhJR01vQmZaME0zN1BuT2xqSmFJVGlvS2l3MldkdXhTOUZEOWZNYVEKOW5FcWYyRVYvVDZna0t6SG9LUk9qL05iQWVkVjdWb1QyZVRqUlNia2pDUEpmVW9qRDRzWnkzTG0yWTc1cTlXRQp5aGRieTVRTDd3SVpxN1hkSnlJOExpcW1BbEJ1anl0bTlZeGc2YVpBblZyaXI0Y2xydW0vNGVpWkZRNjcKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0K"
	pubkey  = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUF4L2hxRUFDbHFmbjg4eGVNMWZYegpJa3FIcFU0UktCM1VLVG1Tbjd2UVRkUnoyT1BPVmtUZXp5a2Q1S1dvcHNLOWJHdGRHcnVqWXp6cFZyQW1aUGgzCmc4emJFM3VzejQ5YUd2dGNUMWFraEVGUlF2ZXpPS0hCU1pIMFNJdVlSWGxRV0xEN0tJYWxteVJlMW9jNjVvN2UKVG9URi81ZC9WUEpucE1BT25tZElhbkprdTljQXdrOUJWcnlCWURWbTFHU0RrNmx6bEs3SHFGNE5sNldDazFaSApFa2ZtZ2VlTTZZYjYxRmtPSCtYdmxFNTRpV3JXL00xZHdDOGpHajEwS0tkUU1teXRCb1lrc2FKMEhYNU0xcHIzCjJtSUZyR2FrczA1QVBXd1ladFRVb0tyRnFyMmJkaTRDNE5HS2NMSHNDNFA5Mno1eE45ays5OUVBRmJmYWtoT3IKbG9MRHR4WjNaYzlpdDlrN2xGQUV5Y0dwM3dRWUtNWVlsRE9GM0FSaEx6WXhEa2JNNThVYkZERUdNclhIcXlubAoreGppaldHalN1aEx5UWNOSlYxWEQ4S1RiNXFUVVBjRTlTOFlsY3NwdXZpeGVCR041N2RVOGE3L0Z1ZmpJSXJJCjdMUWpna3RGNEtJTDRieERnMlF6RWF1VDAwQVhXaWx5bTNkZ3FTNDVGeTBHekZmN052cVFpc1F4aHBPbzlObDcKLzhsWTBCNUVmbU44aGNoU1dKMTQvOHlEQzNraFlzYmhMcDVlSnlNbXZRVW03Syt4RWhNMXA1T3VkcFlxcHd1YQpmN3ZhcFRoVUJDWjRGdklBNmZINmF1Q0xtWlArOUpnYnJKOE1tV1NnZXdvdzNNVnJaa3ZvU3dHNVZCNlJxVXJFCmc0S2hROUM5YVFUQUpNOW9vUUxxck9VQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
)

type DBModel struct {
	ID        int64
	TokenID   string
	CreatedAt string
	UpdatedAt string
}

func main() {
	fmt.Println("=== Laravel Authenticator with Caching Example ===")
	fmt.Println()

	// Create a cache manager with memory driver
	manager := cachemar.New()

	// Create memory cache with LRU eviction (max 1000 items)
	memoryCache := memory.NewWithConfig(memory.Config{MaxSize: 1000})

	// Register the memory cache
	manager.Register("memory", memoryCache)
	manager.SetCurrent("memory")

	fmt.Println("✓ Cache manager initialized with memory driver")

	// Test cache connectivity
	if err := manager.Ping(); err != nil {
		fmt.Printf("✗ Cache ping failed: %v\n", err)
		return
	}
	fmt.Println("✓ Cache is available")
	fmt.Println()

	// Configure database
	dbConfig := golaraauth.DbConfig{
		HostName:       "127.0.0.1",
		Port:           "53306",
		Username:       "root",
		Password:       "123698741",
		DbName:         "123456",
		TokensTable:    "cab_tokens",
		TokensTableCol: "token_id",
	}

	// Configure authenticator with cache
	config := golaraauth.AuthConfig{
		DbConfig:   dbConfig,
		PrivateKey: privKey,
		PublicKey:  pubkey,
		Cache:      manager.Current(), // Pass the cache instance
	}

	// Initialize authenticator
	authenticator := golaraauth.LaravelAuthenticator{}
	err := authenticator.New(config)
	if err != nil {
		fmt.Printf("✗ Failed to initialize authenticator: %v\n", err)
		return
	}
	defer authenticator.CloseDBConnection()

	fmt.Println("✓ Laravel authenticator initialized with caching support")
	fmt.Println()

	// Demo: First verification (cache miss)
	fmt.Println("=== First Token Verification (Cache Miss) ===")
	model := &DBModel{}
	start := time.Now()

	valid, err := authenticator.VerifyTokenString(tokenString, model)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("✗ Token verification failed: %v\n", err)
	} else {
		fmt.Printf("✓ Token verification result: %v (took %v)\n", valid, elapsed)
		if valid {
			fmt.Printf("  Token ID: %s\n", model.TokenID)
		}
	}
	fmt.Println()

	// Demo: Second verification (cache hit)
	fmt.Println("=== Second Token Verification (Cache Hit) ===")
	model2 := &DBModel{}
	start = time.Now()

	valid2, err := authenticator.VerifyTokenString(tokenString, model2)
	elapsed = time.Since(start)

	if err != nil {
		fmt.Printf("✗ Token verification failed: %v\n", err)
	} else {
		fmt.Printf("✓ Token verification result: %v (took %v - should be faster!)\n", valid2, elapsed)
		if valid2 {
			fmt.Printf("  Token ID: %s\n", model2.TokenID)
		}
	}
	fmt.Println()

	// Demo: Cache management
	fmt.Println("=== Cache Management Demo ===")

	// Clear specific token from cache
	err = authenticator.ClearTokenFromCache(tokenString)
	if err != nil {
		fmt.Printf("✗ Failed to clear token from cache: %v\n", err)
	} else {
		fmt.Println("✓ Token cleared from cache")
	}

	// Verify again (should be cache miss again)
	fmt.Println("Third verification after cache clear (should be cache miss):")
	model3 := &DBModel{}
	start = time.Now()

	valid3, err := authenticator.VerifyTokenString(tokenString, model3)
	elapsed = time.Since(start)

	if err != nil {
		fmt.Printf("✗ Token verification failed: %v\n", err)
	} else {
		fmt.Printf("✓ Token verification result: %v (took %v)\n", valid3, elapsed)
	}
	fmt.Println()

	// Demo: Clear all token cache
	fmt.Println("=== Clear All Token Cache ===")
	err = authenticator.ClearAllTokenCache()
	if err != nil {
		fmt.Printf("✗ Failed to clear all token cache: %v\n", err)
	} else {
		fmt.Println("✓ All token cache cleared")
	}
	fmt.Println()

	// Demo: Performance comparison
	fmt.Println("=== Performance Comparison ===")
	fmt.Println("Running 100000 verifications to demonstrate caching benefits...")

	var withoutCacheTotal time.Duration
	var withCacheTotal time.Duration

	// First run - populate cache
	model4 := &DBModel{}
	authenticator.VerifyTokenString(tokenString, model4)

	// Measure with cache
	for i := 0; i < 100000; i++ {
		model := &DBModel{}
		start := time.Now()
		authenticator.VerifyTokenString(tokenString, model)
		withCacheTotal += time.Since(start)
	}

	// Clear cache and measure without cache
	authenticator.ClearAllTokenCache()
	for i := 0; i < 100000; i++ {
		model := &DBModel{}
		authenticator.ClearTokenFromCache(tokenString) // Clear before each verification
		start := time.Now()
		authenticator.VerifyTokenString(tokenString, model)
		withoutCacheTotal += time.Since(start)
	}

	fmt.Printf("Average time with cache: %v\n", withCacheTotal/100000)
	fmt.Printf("Average time without cache: %v\n", withoutCacheTotal/100000)

	if withoutCacheTotal > withCacheTotal {
		improvement := float64(withoutCacheTotal-withCacheTotal) / float64(withoutCacheTotal) * 100
		fmt.Printf("✓ Cache provides ~%.1f%% performance improvement!\n", improvement)
	}

	fmt.Println()
	fmt.Println("=== Summary ===")
	fmt.Println("✓ Caching is now integrated with the Laravel authenticator")
	fmt.Println("✓ Token verification results are cached for 15 minutes")
	fmt.Println("✓ Invalid tokens are cached for 5 minutes to prevent repeated DB queries")
	fmt.Println("✓ Cache can be cleared per token or entirely")
	fmt.Println("✓ Performance improvements are significant for repeated verifications")

	// Close cache connections
	manager.Close()
}
