# Changelog

All notable changes to Yvonne KMS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- TPM 2.0 hardware-bound CMK unseal (planned, `CryptoBackend` interface ready)
- PKCS#11 HSM integration (planned, interface defined in `internal/seal/hsm.go`)
- Kubernetes KMS v2 plugin (planned, gRPC over Unix socket)
- OpenAPI spec + SDK (Go/Java/Python)

## [0.2.0] - 2026-06-25

### Added
- **JWT RBAC Engine** (`internal/auth/jwt_authenticator.go`)
  - Supports RS256/384/512, ES256/384/512, HS256/384/512
  - Algorithm confusion prevention via `WithValidMethods`
  - Configurable role claim path (nested dot notation: `custom.role`)
  - Array role support (`roles: ["admin"]` → first element)
  - 25 integration tests covering attack vectors
- **PolicyStore interface** — generic role→Policy lookup
  - `MemoryPolicyStore` with `sync.RWMutex` (thread-safe)
  - `AppRoleAuthenticator` implements PolicyStore (dual-use with JWT)
- **Auto Key Rotation Daemon** (`internal/lifecycle/daemon.go`)
  - PostgreSQL Advisory Lock cluster leader election
  - Hourly scan for `NextRotationAt <= now` + `State=Active`
  - Audit: `Actor=SYSTEM_DAEMON`, `Action=AutoRotate`
  - Context-aware graceful shutdown (releases lock on SIGTERM)
  - 16 daemon tests
- **KeyMetadata rotation fields**: `RotationPeriodDays`, `NextRotationAt`
- **GDK (Generate Data Key)** API (`POST /api/v1/keys/{id}/generate-data-key`)
  - Client-side envelope encryption
  - Plaintext DEK cleared after HTTP response
- **BYOK (Bring Your Own Key)** (`internal/lifecycle/transit.go`)
  - Temporary RSA-4096 transit key with 10-min TTL
  - Burn-after-reading: private key wiped after single use
  - `POST /api/v1/keys/import` + `GET /api/v1/keys/transit-pub`
- **Shamir Cold Backup** (`internal/seal/backup.go`)
  - Split Wrapped CMK to N USB drive files
  - HMAC-SHA256 integrity per shard
  - `yvonne backup-split` + `yvonne backup-restore` CLI
- **Audit Log Query API** (`POST /api/v1/audit/query`)
  - Filter by time range, Actor, Action
  - Hash chain verification (`valid: true/false`)
- **RotationDaemon assembly** in bootstrap (Cluster mode)
- **AdvisoryLocker** (`internal/storage/pg_locker.go`) — `pg_try_advisory_lock`
- **ScanPrefix** interface for KVStore (reaper + daemon scanning)
- **TLS enforcement** in `main.go` — `ListenAndServeTLS` when `tls.enabled=true`
- **Dual-write audit logger assembly** — `NewDualWriteLogger` (File + Syslog)
- **`yvonne init` CLI command** — generate CMK + RSA encrypt + write to DB
- **`AuditModeConf`** config: `dir`/`filename`/`retention_days`/`syslog_enabled`/`syslog_tag`

### Changed
- **P0 fix: Cluster mode强制认证装配** — `authenticator == nil` → `panic("FATAL: Cluster mode requires a valid authenticator")`
- **P0 fix: 资源级越权拦截** — `/encrypt` `/decrypt` handlers now call `Policy.IsKeyAllowed(body.KeyID)` from context
- `RequireAuth` middleware injects full `Policy` into context (not just RoleID)
- `NewRotationDaemon` accepts `seal.Unsealer` instead of raw `*SecureBuffer` (MasterKeyRef closure)
- `CreateKey` signature: added `rotationPeriodDays` parameter
- `RotateKey` propagates `RotationPeriodDays` + recalculates `NextRotationAt`
- Audit query API locked down with `authAndSeal("AuditQuery")`
- Cluster mode TLS disabled → red WARNING + audit record
- `AppRoleAuthenticator.RegisterPolicy` clears old token on re-registration

### Security
- Fixed: Cluster mode accepted `nil` authenticator (bare exposure)
- Fixed: `/encrypt` `/decrypt` lacked body `KeyID` resource-level authorization
- Fixed: `/api/v1/audit/query` had no authentication
- Fixed: TLS config ignored in `main.go` (always `ListenAndServe`)
- Fixed: Audit logger hardcoded to `os.Stdout` (no file persistence)
- Fixed: RotationDaemon not assembled in bootstrap
- Fixed: `MemoryPolicyStore` race condition (added `sync.RWMutex`)
- Fixed: `RegisterPolicy` left old token valid after re-registration
- Fixed: `security-check.sh` false positive on struct field declarations
- Fixed: `security-check.sh` CHECK 7 false positive on `HSMUnsealer.ProvideShare`

## [0.1.0] - 2026-06-24

### Added
- **Core crypto engine** (`internal/crypto`)
  - AES-256-GCM envelope encryption
  - RSA-4096 PSS signing/verification
  - ECDSA P-256 signing/verification
  - Versioned self-routing ciphertext: `[uint32 version BE][nonce][ciphertext+tag]`
  - `EncryptVersioned` / `DecryptVersioned` (zero-copy optimization)
- **Seal state machine** (`internal/seal`)
  - Shamir GF(2^8) threshold splitting (irreducible polynomial 0x11b, generator 0x03)
  - `VaultState`: Sealed → Unsealed → Sealing
  - `ProvideShare`: incremental shard submission, auto-combine at threshold
  - `DirectUnseal`: Dev mode direct injection
  - `Seal` / `EmergencySeal`: re-seal / irreversible emergency seal
  - `MasterKeyRef`: closure-based master key access
  - Local PKI auto-unseal: RSA-4096 OAEP + burn-after-reading PEM
  - HSM bridge interface: `CryptoBackend` + `HSMUnsealer` + `MockHSMBackend`
  - `BackendRef`: HSM mode closure access (replaces `MasterKeyRef`)
- **Key lifecycle** (`internal/lifecycle`)
  - `CreateKey`: generate DEK + MasterKey encrypt + store
  - `CreateAsymmetricKey`: RSA/ECDSA private key → DER → SecureBuffer → encrypt
  - `RotateKey`: atomic rotation (transaction + row-level lock)
  - `ShredKey`: Crypto-Shredding (UPDATE NULL + DELETE)
  - `SoftDeleteKey` / `RestoreKey`: recycle bin with 90-day TTL
  - `GetActiveKey` / `GetKeyForDecrypt`: state machine enforcement
  - DEK local cache: `sync.RWMutex` map + LISTEN/NOTIFY cluster invalidation
  - Recycle bin auto-cleanup: `StartSoftDeleteReaper`, TTL 90 days
- **Storage layer** (`internal/storage`)
  - `KVStore` interface: Put/Get/Delete/WithTx
  - `RowLocker`: `GetForUpdate` (SELECT FOR UPDATE)
  - `PrefixScanner`: `ScanPrefix` (LIKE 'prefix%')
  - `MemoryStore`: in-memory + Crypto-Shredding
  - `PostgresKVStore`: pgxpool + transactions + row locks + prefix scan
  - `CacheInvalidationListener`: LISTEN/NOTIFY + reconnect cache clear
- **Audit engine** (`internal/audit`)
  - HMAC-SHA256 hash chain: `sig = HMAC(key, prevSig + payload)`
  - `PrevSignature` self-containment (independent verification)
  - Chain anchor persistence: `audit.chain` file
  - `FileRotator`: daily rotation, files 0600 / dirs 0700
  - 180-day retention cleanup
  - High-risk operations `file.Sync()`: Rotate/ShredKey/SysUnseal/EmergencySeal
  - Syslog async dual-write: channel (4096) + 100ms timeout
- **API layer** (`internal/api`)
  - `GET /api/v1/sys/health`, `POST /api/v1/sys/unseal`, `POST /api/v1/sys/panic`
  - `POST /api/v1/keys`, `POST /api/v1/keys/{id}/rotate`, `DELETE /api/v1/keys/{id}/shred`
  - `POST /api/v1/encrypt`, `POST /api/v1/decrypt`
  - `GET /metrics` (Prometheus)
  - `AuditMiddleware`: TraceID + forced audit log + Actor=RoleID
  - `RequireAuth`: Bearer Token + RBAC (Action + KeyID)
  - Payload Escaping: `io.ReadAll` results cleared
- **Auth** (`internal/auth`)
  - `AppRoleAuthenticator`: Token → Policy, `subtle.ConstantTimeCompare`
  - `Policy`: RoleID + AllowedKeys (wildcard) + AllowedActions
  - Default deny: no/invalid Token → 401
- **Web admin UI** (`internal/admin`)
  - Overview page + Seal/Unseal operations + progress indicator
  - Embedded SPA (index.html + app.js + style.css)
  - Security headers: CSP / X-Frame-Options
- **CLI** (`cmd/yvonne`)
  - `yvonne dev`: dev mode
  - `yvonne server --config`: production mode
  - `yvonne unseal-keygen --out`: RSA-4096 key pair
- **Bootstrap** (`internal/bootstrap`)
  - Dev/Cluster dependency injection
  - Graceful shutdown
- **12 security checks** (`scripts/security-check.sh`)
  - `clear()` + `KeepAlive()` pairing
  - No `[]byte` returning getters
  - No sensitive variable interpolation
  - CSPRNG enforcement
  - `*SecureBuffer` for key params
  - `subtle.ConstantTimeCompare`
  - `ProvideShare` wipes shares
  - Shamir GF(2^8)
  - `Combine` returns `*SecureBuffer`
  - Crypto-Shredding
  - Payload Escaping
  - Slice length checks

### Infrastructure
- GitHub Actions CI: lint + test + security + coverage + PostgreSQL integration
- Security scan: GoSec + govulncheck + TruffleHog
- Release workflow: cross-compile Linux/macOS × amd64/arm64
- `Makefile` with `build`/`ci`/`test`/`coverage`/`security-check` targets
- `.gitignore` with strict exclusion of `.pem`/`.key`/`.dat`/`master-key*`

### Documentation
- `README.md` (bilingual English/Chinese)
- `docs/deployment.md`: PostgreSQL + systemd + Docker + monitoring + backup
- `docs/coverage.md`: test coverage report
- `.github/CODE_REVIEW_GUIDELINES.md`: security review checklist

## Versioning Policy

- **0.x**: Pre-release. Breaking changes possible between minor versions.
- **1.0+**: Stable API. Semantic versioning strictly enforced.
  - MAJOR: incompatible API changes
  - MINOR: new features (backward compatible)
  - PATCH: bug fixes (backward compatible)

## Release Process

1. Update `CHANGELOG.md` with release date and changes
2. Tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
3. Push tag: `git push origin v0.2.0`
4. GitHub Actions `release.yml` auto-builds + creates GitHub Release
5. Verify binaries: `dist/yvonne-linux-amd64`, `dist/yvonne-darwin-arm64`
