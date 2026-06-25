# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | ✅ Security fixes  |
| 0.2.x   | ✅ Security fixes  |
| 0.1.x   | ❌ Pre-release     |

## Security Fixes by Version

### 0.3.0
- **SecureBuffer race condition**: `sync.RWMutex` added (WithKey=RLock, Wipe=Lock)
- **O(N) version scan**: `meta:latest:{keyID}` index (O(1) lookup + phantom read prevention)
- **JWT multi-role**: array role claims fully extracted (not just first element)
- **statusRecorder**: `http.Flusher`/`Hijacker`/`Pusher` passthrough restored
- **GDK memory escape**: `json.Marshal` output cleared after response
- **Graceful shutdown**: rootCancel before HTTP Shutdown (prevent in-flight panic)
- **EmergencySeal cache**: DEK cache cleared synchronously on seal

## Threat Model

### In Scope (防范范围)

Yvonne is designed to defend against the following threats:

| Threat | Defense |
|--------|---------|
| **Go GC memory escape** — plaintext keys left on heap after GC | `memguard.SecureBuffer` with `mlock` + `clear()` + `runtime.KeepAlive()` anti-DCE |
| **DCE optimization** — compiler removes `clear()` as dead code | Mandatory `runtime.KeepAlive()` pairing enforced by `scripts/security-check.sh` |
| **Audit log tampering** — silent modification or deletion of audit records | HMAC-SHA256 hash chain with `PrevSignature` self-containment; chain breaks on any modification |
| **Database concurrent rotation race** — high-concurrency key rotation corrupts data | `SELECT FOR UPDATE` row-level lock + `WithTx` atomic rotation |
| **Unauthorized microservice decryption** — token with `order-*` access decrypts `user-key` | Resource-level RBAC: `Policy.IsKeyAllowed(body.KeyID)` in `/encrypt` `/decrypt` handlers |
| **Algorithm confusion attack** — HMAC-signed JWT accepted by RSA-configured authenticator | `jwt.WithValidMethods` restricts to single configured algorithm; `alg:none` explicitly rejected |
| **Timing side-channel on token comparison** — attacker recovers token byte-by-byte | `crypto/subtle.ConstantTimeCompare` for all token comparisons |
| **Plaintext DEK in API response** — GDK returns plaintext that lingers in memory | `clear(rawDEK)` + `runtime.KeepAlive(rawDEK)` after `w.Write()` in handler |
| **Transit key reuse** — BYOK private key used multiple times | Burn-after-reading: `UnwrapWithTransitKey` wipes private key after single use |

### Out of Scope (非防范范围)

Yvonne does **NOT** defend against:

| Threat | Reason |
|--------|--------|
| **OS root-level memory dump** — attacker with root directly dumps `/proc/<pid>/mem` | Out of application-layer scope. Use HSM (TPM/PKCS#11) for hardware-bound keys. |
| **PostgreSQL physical destruction** — `DROP DATABASE` with no backup | Operational responsibility. Use `yvonne backup-split` for Shamir cold backup. |
| **Physical server destruction** — hardware damage, theft | Out of scope. Offsite backup + disaster recovery required. |
| **Compromised build toolchain** — Go compiler backdoor injects key exfiltration | Out of scope. Use reproducible builds + supply chain verification. |
| **Kernel-level keylogger** — eBPF or LKM intercepts syscalls | Out of scope. Hardened OS kernel required. |
| **Side-channel via power/EM analysis** — physical proximity attack | Out of scope. HSM with tamper-resistant hardware required. |

If your threat model includes any of the above, you MUST deploy Yvonne behind HSM-backed `CryptoBackend` and hardened infrastructure.

## Reporting a Vulnerability

### 🔒 Private Disclosure Required

**DO NOT open public GitHub Issues for security vulnerabilities.**

If you discover a security vulnerability in Yvonne:

1. **Email**: Send details to `security@yvonne-kms.example.com` (replace with actual address)
2. **Encrypt**: If possible, encrypt your report with our PGP key (fingerprint published separately)
3. **Include**:
   - Affected version (`yvonne --version` or git commit)
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

### Response Timeline

| Step | SLA |
|------|-----|
| Acknowledge receipt | 48 hours |
| Initial assessment | 7 days |
| Fix or mitigation | 30 days (severity-dependent) |
| Public disclosure (after fix) | 90 days or coordinated with reporter |

### Safe Harbor

Security research conducted in good faith on self-hosted instances you own is welcomed. Do not test against production deployments you do not own.

## Security Hardening Checklist

Before production deployment:

- [ ] TLS enabled (`server.tls.enabled: true`)
- [ ] Cluster mode with authenticator (AppRole or JWT)
- [ ] Resource-level RBAC enforced (wildcard `*` restricted to admin only)
- [ ] Dual-write audit logger (File + Syslog)
- [ ] Audit log directory `0700`, files `0600`
- [ ] Shamir shards distributed to different physical locations
- [ ] USB cold backup drives stored offsite
- [ ] PostgreSQL `sslmode=verify-full`
- [ ] PEM file permissions `0600`
- [ ] Systemd `ProtectSystem=strict`
- [ ] Firewall: only API port exposed, admin port loopback only
- [ ] `scripts/security-check.sh` passes (12 checks)
- [ ] RotationDaemon enabled with Advisory Lock
- [ ] Emergency Seal procedure documented and tested

## Cryptography Notice

Yvonne uses Go's standard library cryptographic implementations (`crypto/aes`, `crypto/rsa`, `crypto/ecdsa`, `crypto/sha256`, `crypto/hmac`). These are **NOT** FIPS 140-3 validated modules.

For FIPS-required scenarios, integrate a validated HSM via the `CryptoBackend` interface (`internal/seal/hsm.go`).

### Supported Algorithms

| Category | Algorithms |
|----------|-----------|
| Symmetric | AES-256-GCM |
| Asymmetric (signing) | RSA-4096 PSS, ECDSA P-256 |
| Key wrapping | RSA-4096 OAEP (SHA-256) |
| Hash | SHA-256 |
| HMAC | HMAC-SHA256 |
| JWT | RS256/384/512, ES256/384/512, HS256/384/512 |
| Secret sharing | Shamir over GF(2^8), polynomial 0x11b, generator 0x03 |

### Deprecated/Forbidden

- ❌ RSA PKCS#1 v1.5 padding
- ❌ ECDSA curves other than P-256
- ❌ MD5, SHA-1
- ❌ `math/rand` for security-sensitive randomness
- ❌ JWT `alg: none`
- ❌ `[]byte` returning getters for sensitive data
