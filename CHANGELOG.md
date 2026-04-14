# Changelog

## [1.0.1] - 2026-04-14

### Security

- stopped trusting cached positive verification results as authorization decisions
- switched token-related cache keys from raw bearer tokens to SHA-256 digests
- made the verification path require only the public key; private key fields remain accepted for backward compatibility
- validated configured table and column identifiers before using them in SQL

### Reliability

- rebuilt MySQL DSNs with the driver config, preserving credentials and optional timeout/TLS settings safely
- propagated cache eviction errors from `ClearTokenFromCache` and `ClearAllTokenCache`
- returned explicit errors for missing `jti`, missing `dbModel`, and uninitialized public key / DB connection states

### Testing

- replaced the external-MySQL test flow with isolated SQLite-backed tests
- added regression coverage for stale positive cache entries, wrong-signature tokens, hashed cache keys, and DSN generation

### Documentation

- updated README examples and upgrade notes to reflect the hardened cache semantics
