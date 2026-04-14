# Golaraauth

`golaraauth` is a Go package for verifying Laravel-issued RSA JWTs and resolving the corresponding token record from a database table.

## What changed

The package keeps the existing public API, but the verification path is now stricter and safer:

- positive cache hits are no longer trusted as authorization decisions
- cache keys are derived from a token hash instead of the raw bearer token
- only a public key is required for verification
- MySQL DSNs are built with the driver config instead of string concatenation

That means existing callers can upgrade without changing method signatures or config shape, while avoiding stale cached authorization results.

## Features

- JWT verification with RSA public keys
- token lookup through GORM
- optional caching through [cachemar](https://github.com/stremovskyy/cachemar)
- hashed cache keys for token-related cache entries
- optional MySQL connection hardening with TLS and timeout settings

## Installation

```bash
go get github.com/stremovskyy/golaraauth
```

## Usage

### Basic usage

```go
package main

import "github.com/stremovskyy/golaraauth"

type DBModel struct {
    ID        int64
    TokenID   string
    CreatedAt string
    UpdatedAt string
}

func main() {
    model := &DBModel{}

    config := golaraauth.AuthConfig{
        DbConfig: golaraauth.DbConfig{
            HostName:       "127.0.0.1",
            Port:           "3306",
            Username:       "root",
            Password:       "password",
            DbName:         "database",
            TokensTable:    "personal_access_tokens",
            TokensTableCol: "token_id",
        },
        PublicKeyFile: "/path/to/oauth-public.key",
    }

    auth := golaraauth.LaravelAuthenticator{}
    if err := auth.New(config); err != nil {
        panic(err)
    }
    defer auth.CloseDBConnection()

    valid, err := auth.VerifyTokenString("jwt-token-here", model)
    if err != nil {
        panic(err)
    }

    println(valid)
}
```

### Usage with cache

Caching is optional. The public cache API is unchanged:

```go
package main

import (
    "github.com/stremovskyy/cachemar"
    "github.com/stremovskyy/cachemar/drivers/memory"
    "github.com/stremovskyy/golaraauth"
)

func main() {
    manager := cachemar.New()
    memoryCache := memory.NewWithConfig(memory.Config{MaxSize: 1000})
    manager.Register("memory", memoryCache)
    manager.SetCurrent("memory")

    config := golaraauth.AuthConfig{
        DbConfig: golaraauth.DbConfig{
            HostName:       "127.0.0.1",
            Port:           "3306",
            Username:       "root",
            Password:       "password",
            DbName:         "database",
            TokensTable:    "personal_access_tokens",
            TokensTableCol: "token_id",
        },
        PublicKeyFile: "/path/to/oauth-public.key",
        Cache:         manager.Current(),
    }

    authenticator := golaraauth.LaravelAuthenticator{}
    if err := authenticator.New(config); err != nil {
        panic(err)
    }
    defer authenticator.CloseDBConnection()

    _ = authenticator.ClearTokenFromCache("jwt-token-here")
    _ = authenticator.ClearAllTokenCache()
}
```

## Cache behavior

- invalid JWT verification results can be cached briefly
- raw bearer tokens are not used as cache keys
- successful authorization still requires a fresh database check

This keeps the cache API backward-compatible without trusting stale positive auth results after revocation or expiry.

## Configuration

### `AuthConfig`

| Field | Required | Description |
|---|---|---|
| `DbConfig` | Yes | Database configuration |
| `PublicKey` | Yes* | RSA public key in PEM or base64-encoded PEM form |
| `PublicKeyFile` | Yes* | Path to RSA public key file |
| `PrivateKey` | No | Accepted for backward compatibility; not required for verification |
| `PrivateKeyFile` | No | Accepted for backward compatibility; not required for verification |
| `Cache` | No | Optional `cachemar.Cacher` instance |

\* Provide either `PublicKey` or `PublicKeyFile`.

### `DbConfig`

| Field | Required | Description |
|---|---|---|
| `HostName` | Yes | Database host |
| `Port` | Yes | Database port |
| `Username` | Yes | Database username |
| `Password` | Yes | Database password |
| `DbName` | Yes | Database name |
| `TokensTable` | Yes | Token table name |
| `TokensTableCol` | Yes | Column used to match the JWT `jti` |
| `Charset` | No | MySQL charset, defaults to `utf8mb4` |
| `TLSConfig` | No | Registered MySQL TLS config name |
| `Timeout` | No | Dial timeout |
| `ReadTimeout` | No | Read timeout |
| `WriteTimeout` | No | Write timeout |
| `Params` | No | Additional MySQL DSN params |

## Upgrade notes

- no method signatures changed
- `Cache`, `ClearTokenFromCache`, and `ClearAllTokenCache` still exist
- private key fields are still accepted, but no longer required for verification
- if you relied on positive authorization being served from cache, that behavior is intentionally removed for security

## Examples

- `example/from_strings/` - public key from strings
- `example/with_keys/` - public key from files
- `example/with_cache/` - cache wiring with the same public API

## Verification

Run the local checks with:

```bash
go test ./...
go vet ./...
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
