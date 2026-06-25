# Contributing to Yvonne KMS

Thank you for your interest in contributing to Yvonne! This document outlines the process and the strict security red lines that all contributions must follow.

## Security Red Lines (非协商安全红线)

Yvonne is a cryptographic system. Any PR that violates the following red lines will be **immediately rejected** without further discussion.

### ❌ Auto-Reject Violations

1. **Printing sensitive material**: Any use of `fmt.Printf`, `log.Printf`, `fmt.Println`, or similar to print plaintext keys, DEK material, Shamir shares, JWT tokens, or password/secret values.

2. **Bypassing SecureBuffer**: Passing plaintext key material as `[]byte` instead of `*memguard.SecureBuffer` in function signatures. Sensitive data MUST flow through `WithKey(func(key []byte) error { ... })` closures.

3. **Missing `clear()` + `KeepAlive()` pairing**: Any `clear(slice)` without a matching `runtime.KeepAlive(slice)` within 3 lines. The security check script (`scripts/security-check.sh`) enforces this — it must pass.

4. **Using `math/rand`**: Any use of `math/rand` for security-sensitive randomness. Use `memguard.GenerateSecureRandom()` exclusively.

5. **Breaking the 12 security checks**: Any PR that causes `scripts/security-check.sh` to fail. The checks are:
   - `clear()` + `KeepAlive()` pairing (anti-DCE)
   - No `[]byte` returning getters
   - No sensitive variable interpolation in errors/logs
   - CSPRNG enforcement (no `math/rand`)
   - Plaintext key params must be `*SecureBuffer`
   - `subtle.ConstantTimeCompare` for sensitive comparisons
   - `ProvideShare` wipes `collectedShares` after threshold
   - Shamir operations strictly in GF(2^8)
   - `Combine` returns `*SecureBuffer`
   - `MemoryStore.Delete` clears before delete (Crypto-Shredding)
   - API handler `io.ReadAll` results cleared (Payload Escaping)
   - Byte slice access guarded by length check (anti-panic)

6. **Weak cryptography**: Introducing RSA PKCS#1 v1.5, SHA-1, MD5, or non-P-256 ECDSA curves.

7. **JWT `alg: none`**: Any code path that accepts unsigned JWTs.

### ✅ Mandatory Practices

- All sensitive byte slices MUST be `*memguard.SecureBuffer`
- All `clear()` calls MUST have `runtime.KeepAlive()` within 3 lines
- All token comparisons MUST use `subtle.ConstantTimeCompare`
- All error messages MUST be obfuscated (no "token expired at XXX", just "Unauthorized")
- All new APIs MUST be covered by integration tests
- All PRs MUST pass `make ci` (vet + fmt + security + tests)

## Development Setup

```bash
# Clone
git clone https://github.com/zealot00/Yvonne.git
cd Yvonne

# Build
make build

# Run dev mode
./bin/yvonne dev

# Run full CI locally
make ci

# Run security checks
bash scripts/security-check.sh
```

## Pull Request Process

1. **Branch**: Create a feature branch from `main` (`git checkout -b feat/your-feature`)
2. **Code**: Write code following the security red lines above
3. **Tests**: Add tests for new functionality (integration tests in `_test.go` files with `//go:build integration` tag)
4. **Security**: Run `bash scripts/security-check.sh` — must show `[SECURITY CHECK] ALL PASSED`
5. **CI**: Run `make ci` — must show `=== CI Pipeline PASSED ===`
6. **Commit**: Use conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`)
7. **PR**: Open PR with description including:
   - What changed
   - Why (motivation)
   - Security implications (if any)
   - Test coverage (new tests added)

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `security`

Example:
```
feat(auth): add JWT authenticator with RS256 support

- NewJWTAuthenticator loads RSA public key at startup
- Algorithm confusion prevention via WithValidMethods
- Configurable role claim path (supports nested dot notation)
- 25 integration tests covering attack vectors

Closes #42
```

## Code Style

- `gofmt -s` (simplify mode) is mandatory
- `go vet` must pass
- Use descriptive variable names (no `a`, `b`, `x` for security-sensitive data)
- Comments on exported functions are mandatory
- Package-level comments must describe the security model

## Testing Guidelines

### Unit Tests

- Place in same package as code (`internal/auth/auth_test.go`)
- Table-driven tests preferred
- Must cover error paths, not just happy path

### Integration Tests

- Add `//go:build integration` tag
- Place in `_test.go` files
- Use `httptest.NewRecorder` for API tests
- Test both authorization (200) and rejection (401/403) paths

### Security Tests

- Test attack vectors: algorithm confusion, timing side-channels, alg:none
- Test boundary conditions: empty input, max length, concurrent access
- Run with `-race` flag: `go test -race ./...`

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      API Layer                           │
│  RequireAuth (RBAC) → AuditMiddleware → Sealed Check    │
├─────────────────────────────────────────────────────────┤
│                    Lifecycle Manager                     │
│  DEK State Machine + Cache + LISTEN/NOTIFY + Reaper     │
├─────────────────────────────────────────────────────────┤
│                     Seal State Machine                   │
│  Shamir │ Local PKI │ HSM (CryptoBackend) │ Emergency   │
├─────────────────────────────────────────────────────────┤
│              Crypto Engine (memguard-protected)          │
│  AES-256-GCM │ RSA-4096 PSS │ ECDSA P-256 │ Shamir      │
├─────────────────────────────────────────────────────────┤
│           Storage (KVStore abstraction)                  │
│  MemoryStore │ PostgresKVStore (tx + row lock + LISTEN) │
├─────────────────────────────────────────────────────────┤
│        Audit (Hash Chain + File Rotation + Syslog)      │
└─────────────────────────────────────────────────────────┘
```

## Questions?

- Security questions: See [SECURITY.md](SECURITY.md)
- General discussion: Open a GitHub Discussion
- Bugs: Open a GitHub Issue (non-security only)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
