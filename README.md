# 🧊 Yvonne KMS

Because paying a cloud vendor $500/month just to hold your secrets hostage is institutional extortion.

Yvonne is a production-grade, paranoia-driven Key Management System (KMS) written in Go. She is cold, unforgiving, and explicitly designed for teams who trust absolutely no one—especially not their infrastructure providers, their garbage collector, or themselves.

If you are tired of storing your database credentials as Base64 strings in a "secure" config map, or if your compliance auditor is breathing down your neck and you refuse to pay the "Cloud Mafia" tax, you've come to the right place.

## 💀 Why Yvonne?

Most enterprise KMS solutions are either bloated black boxes that cost more than your engineering team's combined salary, or they are "managed services" that require you to blindly trust that some hyperscaler isn't keeping a backdoor copy of your master key.

Yvonne was built from the ground up with **Absolute Zero Trust**. She doesn't trust the network, she doesn't trust the database, and she certainly doesn't trust Go's Garbage Collector.

## 🔪 Core Features (or: How We Treat Your Data)

### Alzheimer's for Secrets (Absolute Memory Guard)
Go's Garbage Collector is a snitch that leaves your plaintext keys wandering around the heap. Yvonne violently murders memory slices using `clear()` and pins them with `runtime.KeepAlive()` to defeat Dead Code Elimination (DCE). When a key is done being used, its memory is zeroed out instantly. Memory dumps will yield nothing but ghosts.

### Horcrux-Level Master Keys (Shamir's Secret Sharing)
The Master Key is never stored intact. It is shattered into 5 cryptographic shards across a Galois Field GF(2^8). Distribute them to your executives. If the server reboots, 3 of them must provide their shards to resurrect Yvonne. If they forget their shards, congratulations, your data is mathematically sealed forever.

### The Poor Man's Auto-Unseal (Local PKI)
Because paying the cloud provider just to automatically unseal your Kubernetes pods at 3 AM is a scam. Yvonne supports a zero-cost local RSA-4096 unseal mechanism. She reads the private key, decrypts the Master Key, and immediately performs a "Burn After Reading"—wiping the key from memory and physically deleting the PEM file from the disk.

### Digital Cremation (True Crypto-Shredding)
When you rotate or destroy a Data Encryption Key (DEK), we don't just set an `is_deleted = true` flag like a coward. Yvonne issues a pessimistic lock (`SELECT FOR UPDATE`), physically overwrites the ciphertext with NULL or zeros in PostgreSQL, and then deletes the row. It is gone. Don't ask for it back.

### The Alibi Engine (Immutable Audit Chains)
To satisfy the most bureaucratic of compliance auditors (GxP, SOC2), every action is written to a daily-rotated, HMAC-SHA256 hashed chain, dual-written asynchronously to Syslog. If anyone tampers with a single byte of the log file, the cryptographic chain breaks. You will always be able to mathematically prove exactly which microservice screwed up.

### Cold Storage Shamir Backup (USB Key Drives)
Yvonne can split the Wrapped Master Key into N Shamir shards and write each to a separate USB drive. Lose a drive? No problem. Lose all of them? See the disclaimer below.

### Emergency Seal (The Nuclear Option)
One API call (`POST /api/v1/sys/panic`) instantly wipes the Master Key from memory, clears all shard caches, and puts Yvonne into a deep freeze. She will refuse every request until someone physically kills the process and performs a cold restart with Shamir unseal. There is no "undo."

## ⚠️ Disclaimer: The "You're On Your Own" Guarantee

Cryptography is a loaded gun. Yvonne provides the safety mechanism, but if you point it at your foot and pull the trigger, she will not stop the bullet.

- **Lose the Shamir shards?** Your data is gone.
- **Delete the PostgreSQL database without a backup?** Your data is gone.
- **Trigger the Emergency Seal?** Yvonne will instantly wipe her memory and play dead until manually resurrected.

Yvonne does not forgive, and she does not have a "Forgot Password" link. Use in production at your own risk.

---

## 🚀 Getting Started

### Environment

- Go 1.21+
- PostgreSQL 14+ (Cluster mode)

### Build

```bash
make build
# or
go build -o bin/yvonne ./cmd/yvonne
```

### Dev Mode (30-second zero-config trial)

```bash
./bin/yvonne dev
```

Dev mode: in-memory storage, auto-generated Master Key, unsealed on start. Web UI at `http://127.0.0.1:8250`.

### Full Cluster Setup

```bash
# 1. Generate RSA-4096 key pair for auto-unseal
./bin/yvonne unseal-keygen --out /secure/unseal.pem

# 2. Initialize: generate CMK, encrypt with public key, write to DB
./bin/yvonne init --config config.json --pub-key /tmp/unseal_pub.pem

# 3. (Optional) Shamir cold backup to USB drives
./bin/yvonne backup-split --config config.json --out-dir /mnt/usb --total 5 --threshold 3

# 4. Start
./bin/yvonne server --config config.json
```

---

## CLI Commands

| Command | Description |
|---|---|
| `yvonne dev` | Dev mode (in-memory, auto-unseal, web UI) |
| `yvonne server --config <path>` | Production mode (PostgreSQL + Shamir/Local PKI) |
| `yvonne unseal-keygen --out <path>` | Generate RSA-4096 key pair for local_pki unseal |
| `yvonne init --config <path> --pub-key <path>` | Generate CMK + encrypt + write to DB |
| `yvonne backup-split --config <path> --out-dir <dir>` | Shamir split Wrapped CMK to USB drive files |
| `yvonne backup-restore --out <path> <share1> <share2> ...` | Restore Wrapped CMK from share files |

---

## API Reference

All APIs return JSON: `{"ok": bool, "data": ..., "error": ...}`.

### System

| Method | Path | Description | Sealed OK? |
|---|---|---|---|
| GET | `/api/v1/sys/health` | Health check | ✅ |
| POST | `/api/v1/sys/unseal` | Submit Shamir shard | ✅ |
| POST | `/api/v1/sys/panic` | Emergency seal (irreversible) | ✅ |

### Keys

| Method | Path | Description | Sealed OK? |
|---|---|---|---|
| POST | `/api/v1/keys` | Create key (AES/RSA/ECDSA) | ❌ 503 |
| POST | `/api/v1/keys/{id}/rotate` | Rotate key | ❌ 503 |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred (irreversible) | ❌ 503 |
| PATCH | `/api/v1/keys/{id}/soft-delete` | Soft delete (recycle bin) | ❌ 503 |
| POST | `/api/v1/keys/{id}/restore` | Restore from recycle bin | ❌ 503 |

### Crypto

| Method | Path | Description | Sealed OK? |
|---|---|---|---|
| POST | `/api/v1/encrypt` | Envelope encrypt | ❌ 503 |
| POST | `/api/v1/decrypt` | Envelope decrypt | ❌ 503 |

### Observability

| Method | Path | Description |
|---|---|---|
| GET | `/metrics` | Prometheus metrics |

### Ciphertext Format (Self-Routing)

```
[Version (uint32, 4 bytes, BigEndian)] [Nonce (12 bytes)] [Ciphertext + AuthTag]
```

Decrypt extracts the version from the first 4 bytes and routes to the correct DEK. No guessing.

### Key States

```
Active ──(Rotate)──→ Deactivated ──(SoftDelete)──→ SoftDeleted ──(TTL/Shred)──→ Destroyed
                          ↑                          │
                          └────────(Restore)─────────┘
```

- **Active**: Only state that can encrypt. Also decrypts.
- **Deactivated**: Historical version. Decrypt only.
- **SoftDeleted**: In recycle bin. Still decrypts. Restorable for 90 days.
- **Destroyed**: Physically shredded. Gone forever.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      API Layer                           │
│  RBAC Auth → Audit Middleware → Sealed Check → Handler  │
├─────────────────────────────────────────────────────────┤
│                    Lifecycle Manager                     │
│  DEK State Machine + Cache + LISTEN/NOTIFY + Reaper     │
├─────────────────────────────────────────────────────────┤
│                     Seal State Machine                   │
│  Shamir GF(2^8) │ Local PKI │ Emergency Seal            │
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

---

## Security (12 Automated Checks)

```bash
bash scripts/security-check.sh
```

| # | Check |
|---|---|
| 1 | `clear()` + `runtime.KeepAlive()` pairing (anti-DCE) |
| 2 | No `[]byte` returning getters (sensitive data via `WithKey` closure) |
| 3 | No sensitive variable interpolation in errors/logs |
| 4 | CSPRNG enforcement (no `math/rand`, no bypassing `GenerateSecureRandom`) |
| 5 | Plaintext key params must be `*memguard.SecureBuffer` |
| 6 | Sensitive comparisons use `subtle.ConstantTimeCompare` |
| 7 | `ProvideShare` wipes `collectedShares` after threshold |
| 8 | Shamir operations strictly in GF(2^8) |
| 9 | `Combine` returns `*memguard.SecureBuffer` |
| 10 | `MemoryStore.Delete` clears before delete (Crypto-Shredding) |
| 11 | API handler `io.ReadAll` results cleared (Payload Escaping) |
| 12 | Byte slice access guarded by length check (anti-panic) |

---

## CI/CD

| Workflow | Triggers | Jobs |
|---|---|---|
| `ci.yml` | push/PR to main | lint, test, security, coverage, PostgreSQL integration |
| `security.yml` | daily + manual | GoSec, govulncheck, TruffleHog secret scan |
| `release.yml` | tag `v*.*.*` | Cross-compile (linux/darwin × amd64/arm64) + GitHub Release |

---

## Project Structure

```
yvonne/
├── cmd/yvonne/              # CLI entry point
├── internal/
│   ├── memguard/            # SecureBuffer + CSPRNG
│   ├── crypto/              # AES-256-GCM + RSA/ECDSA + versioned ciphertext
│   ├── seal/                # Shamir + VaultState + Local PKI + Emergency Seal + Backup
│   ├── lifecycle/           # DEK lifecycle + cache + reaper
│   ├── storage/             # KVStore (Memory + Postgres + LISTEN/NOTIFY)
│   ├── audit/               # Hash chain + file rotation + syslog
│   ├── metrics/             # Prometheus
│   ├── api/                 # HTTP routes + middleware + handlers
│   ├── auth/                # RBAC (AppRole + Policy)
│   ├── admin/               # Web UI (embedded SPA)
│   ├── bootstrap/           # Dependency injection (Dev/Cluster)
│   └── config/              # Config loading + validation
├── .github/workflows/       # CI/CD
├── scripts/security-check.sh
└── Makefile
```

---

## Roadmap

- [ ] **TPM 2.0 support** — Hardware-bound CMK unseal via `go-tpm`, replacing or complementing Local PKI
- [ ] PKCS#11 HSM integration
- [ ] mTLS client certificate authentication
- [ ] Audit log tamper detection API (chain verification endpoint)

---

## License

Private. All rights reserved.
