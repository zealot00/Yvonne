# Yvonne KMS User Manual

> Version: v1.3.3 (LTS) | Last updated: 2026-07-01

Welcome to Yvonne KMS. This manual covers all features and capabilities of the product, organized from basic to advanced, suitable for both DevOps engineers getting started and architects needing deep customization.

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Use Cases](#2-use-cases)
3. [Installation & Build](#3-installation--build)
4. [Quick Start](#4-quick-start)
5. [Modes & Configuration](#5-modes--configuration)
6. [Key Management](#6-key-management)
7. [Cryptographic Operations](#7-cryptographic-operations)
8. [Authentication & Authorization](#8-authentication--authorization)
9. [Multi-Tenant Isolation](#9-multi-tenant-isolation)
10. [MFA & Quorum Approval](#10-mfa--quorum-approval)
11. [Audit Log](#11-audit-log)
12. [Observability](#12-observability)
13. [Web Console](#13-web-console)
14. [SDK Guide](#14-sdk-guide)
15. [Deployment](#15-deployment)
16. [GM (Chinese National Crypto) Compliance](#16-gm-chinese-national-crypto-compliance)
17. [HSM Integration](#17-hsm-integration)
18. [Troubleshooting](#18-troubleshooting)
19. [Appendix](#19-appendix)

---

## 1. Product Overview

Yvonne KMS is a self-hosted Key Management System providing envelope encryption, auditable key lifecycle, absolute memory discipline, and JWT-based RBAC.

### Three Core Promises

1. **Plaintext keys never leave the process.** Every secret is pinned in `memguard.SecureBuffer`, wiped with `clear()` + `runtime.KeepAlive()`. Not the network, not the database, not even Go's GC can leak them.

2. **Every key operation is provably auditable.** HMAC hash chain audit log with file rotation + async syslog dual-write. Tamper with one entry and the entire chain breaks loudly.

3. **You own full sovereignty.** Shamir-split master key, HSM-backed CMK, self-hosted end to end. No vendor lock-in, no cloud call-home.

### Applicable & Non-Applicable Scenarios

- **Applicable**: Internal key management for regulated industries (finance, healthcare, government); unified encryption service for microservices; AI Agent accessing KMS via MCP; GM compliance (SM2/SM3/SM4 full stack); enterprises needing HSM.
- **Not applicable**: Scenarios requiring FIPS 140-3 certification (Yvonne itself is not FIPS-validated; integrate a FIPS HSM); services directly exposed to the public internet (Yvonne is designed as an intranet service; expose via mTLS reverse proxy).

Detailed use cases and architecture examples: [Chapter 2 Use Cases](#2-use-cases).

---

## 2. Use Cases

This chapter illustrates how Yvonne fits different business scenarios through 7 typical cases, each with architecture highlights, key configuration, and code snippets.

### 2.1 Unified Encryption for Microservices

**Scenario**: An e-commerce platform has a dozen microservices (orders, payments, users, inventory), each needing to encrypt sensitive fields (phone, ID card, bank card). Goal: unified key management, unified audit, avoid each service implementing its own crypto.

**Architecture**:

```
Order service ─┐
Payment svc ───┤
User service ──┼──→ Yvonne KMS Cluster ──→ PostgreSQL
Inventory svc ─┘        │
                        ├─ Hash chain audit → Syslog → SIEM
                        └─ Prometheus metrics → Grafana
```

**Key design**:

1. One AppRole per service, least privilege (only `Encrypt` + `Decrypt`)
2. Keys named by business prefix: `order-*`, `payment-*`, `user-*`
3. Envelope encryption: KMS generates DEK, service encrypts bulk data locally

**Config**:

```json
{
  "auth": {
    "app_roles": [
      {
        "role_id": "order-service",
        "token": "order-secure-token",
        "allowed_keys": ["order-*"],
        "allowed_actions": ["encrypt", "decrypt", "generate-data-key"]
      },
      {
        "role_id": "payment-service",
        "token": "payment-secure-token",
        "allowed_keys": ["payment-*"],
        "allowed_actions": ["encrypt", "decrypt"]
      }
    ]
  }
}
```

**Server code (Go SDK)**:

```go
// Order service encrypts user phone
resp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
    KeyID:     "order-user-phone",
    Plaintext: []byte(user.Phone),
})
// Store resp.Ciphertext in order database
```

**Benefits**: Keys never touch services, full audit, permission isolation, auto-rotation.

---

### 2.2 Database Field-Level Encryption

**Scenario**: User table needs to encrypt ID card, phone, email at rest, but still query by phone.

**Solution**: Dual-field strategy — "envelope encryption + HMAC index".

**Schema**:

```sql
CREATE TABLE users (
    id           BIGSERIAL PRIMARY KEY,
    phone_enc    BYTEA,       -- Yvonne-encrypted ciphertext
    phone_hmac   VARCHAR(64), -- HMAC value (for query index)
    id_card_enc  BYTEA,
    email_enc    BYTEA
);
CREATE INDEX idx_phone_hmac ON users(phone_hmac);
```

**Write**:

```go
// 1. Encrypt phone
encResp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
    KeyID:     "user-phone",
    Plaintext: []byte(phone),
})

// 2. Generate HMAC (dedicated HMAC key, irreversible)
macResp, _ := client.GenerateMAC(ctx, &yvonne.MACRequest{
    KeyID: "user-phone-hmac",
    Data:  []byte(phone),
})

// 3. Store
db.Exec("INSERT INTO users (phone_enc, phone_hmac) VALUES ($1, $2)",
    encResp.Ciphertext, macResp.MAC)
```

**Query by phone**:

```go
// 1. HMAC the input phone
macResp, _ := client.GenerateMAC(ctx, &yvonne.MACRequest{
    KeyID: "user-phone-hmac",
    Data:  []byte(inputPhone),
})

// 2. Query by HMAC index (no full-table decrypt)
var user User
db.QueryRow("SELECT phone_enc FROM users WHERE phone_hmac = $1", macResp.MAC).Scan(&user.PhoneEnc)

// 3. Decrypt
decResp, _ := client.Decrypt(ctx, &yvonne.DecryptRequest{
    KeyID:      "user-phone",
    Ciphertext: user.PhoneEnc,
})
```

**Key point**: HMAC key and encryption key are separate; HMAC is irreversible but supports equality match; encryption key can decrypt.

---

### 2.3 AI Agent Key Access (MCP)

**Scenario**: AI Agents (Claude, GPT) need to access encrypted user data but cannot hold decryption keys directly. Agents should call KMS via a standardized protocol, with restrictions to decrypt only specific keys.

**Architecture**:

```
User ──→ AI Agent ──→ MCP Server ──→ Yvonne KMS
                       │
                       └─ Only exposes encrypt + restricted decrypt
```

**Config**:

```json
{
  "server": {
    "mcp": {
      "enabled": true,
      "bind_port": 8202
    }
  },
  "auth": {
    "app_roles": [
      {
        "role_id": "ai-agent",
        "token": "ai-agent-token",
        "allowed_keys": ["ai-readable-*"],
        "allowed_actions": ["encrypt", "decrypt"]
      }
    ]
  }
}
```

**Agent calls**: AI Agent invokes `yvonne.encrypt` / `yvonne.decrypt` tools via MCP protocol. KMS restricts Agent to `ai-readable-*` keys only; all operations fully audited.

**Benefits**: Agent holds no keys, operations auditable, permissions revocable, keys rotatable.

---

### 2.4 GM (Chinese National Crypto) Compliance

**Scenario**: Financial institution must satisfy GB/T 39786-2021 Level 2 requirements, using GM algorithms end to end, and pass cryptographic assessment.

**Config**:

```json
{
  "crypto": {
    "suite": "gmsm",
    "strict": true
  },
  "server": {
    "tls": {
      "enabled": true,
      "gm_enabled": true,
      "gm_sign_cert_file": "/etc/yvonne/certs/sm2-sign.pem",
      "gm_sign_key_file": "/etc/yvonne/certs/sm2-sign-key.pem",
      "gm_enc_cert_file": "/etc/yvonne/certs/sm2-enc.pem",
      "gm_enc_key_file": "/etc/yvonne/certs/sm2-enc-key.pem"
    }
  },
  "auth": {
    "jwt": {"signing_method": "SM2"}
  },
  "audit": {"dir": "/var/log/yvonne", "syslog_enabled": true}
}
```

**Compliance mapping** (excerpt; full 24 items: [docs/compliance/self-assessment-level2.md](../compliance/self-assessment-level2.md)):

| Level 2 Requirement | Yvonne Implementation |
|---|---|
| SM4 symmetric encryption | SM4-GCM envelope encryption |
| SM2 asymmetric signing | SM2 sign/verify API |
| SM3 hashing | HMAC-SM3 audit hash chain |
| GM TLS | RFC 8998 (SM2 dual certs + SM4/SM3) |
| Key lifecycle | Full create/rotate/soft-delete/shred |
| Audit integrity | HMAC hash chain + syslog dual-write |

**Build**: `go build -tags gmsm -o bin/yvonne-gmsm ./cmd/yvonne`

---

### 2.5 Kubernetes In-Cluster Key Service

**Scenario**: K8s Pods need to access KMS for encrypting sensitive configs, using ServiceAccount JWT for automatic auth without managing static tokens.

**Architecture**:

```
K8s Pod (SA: order-app) ──→ Yvonne KMS
   │                           │
   └─ Auto-mounted SA JWT      └─ K8s authenticator verifies SA JWT
                                  and maps to Policy
```

**KMS config**:

```json
{
  "auth": {
    "k8s": {
      "enabled": true,
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "audience": ["yvonne-kms"],
      "jwks_url": "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
      "role_mapping": {
        "default/order-app": {
          "role_id": "order-app",
          "allowed_keys": ["order-*"],
          "allowed_actions": ["encrypt", "decrypt"]
        }
      }
    }
  }
}
```

**In-Pod code**:

```go
// Auto-read SA JWT (K8s mounts to /var/run/secrets/kubernetes.io/serviceaccount/token)
saToken, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
client := yvonne.New("http://yvonne.kms-system.svc:8200", string(saToken))

resp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{
    KeyID:     "order-config",
    Plaintext: []byte(dbPassword),
})
```

**Benefits**: Zero token management, auto-auth on Pod restart, RBAC via K8s SA.

---

### 2.6 Multi-Tenant SaaS Platform

**Scenario**: SaaS platform serves multiple enterprise customers; each tenant's keys must be strictly isolated.

**Config**:

```json
{
  "multi_tenant": {"enabled": true},
  "auth": {
    "app_roles": [
      {
        "role_id": "tenant-a-admin",
        "token": "tenant-a-token",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"],
        "tenant_id": "tenant-a"
      },
      {
        "role_id": "tenant-b-admin",
        "token": "tenant-b-token",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"],
        "tenant_id": "tenant-b"
      }
    ]
  }
}
```

**Isolation mechanism**:

- Tenant A creates `order-key` → actually stored as `tenant-a:order-key`
- Tenant B creates `order-key` → stored as `tenant-b:order-key`
- Tenants cannot see each other's keys, even with the same KeyID
- Transparent to applications: client passes `order-key`, Yvonne auto-prefixes based on Token

**Benefits**: Single KMS cluster serves multiple tenants, isolation without app-layer changes, backward compatible (`enabled=false` = single-tenant behavior).

---

### 2.7 Two-Person Approval for High-Sensitivity Operations

**Scenario**: Destroy production key, emergency seal — these operations must require 2-person approval; no single person can execute.

**Flow**:

```
Operator A initiates ShredKey → Create Quorum ticket (required=2)
                                ↓
                             ticket pending
                                ↓
Operator B approves ────────────┘  (anti-self-approve: A cannot approve own ticket)
                                ↓
                             ticket approved
                                ↓
Operator A executes ShredKey with ticket ID
```

**Config**:

```json
{
  "mfa": {
    "enabled": true,
    "sensitive_operations": ["ShredKey", "EmergencySeal"]
  }
}
```

**Steps**:

```bash
# 1. Operator A initiates approval
curl -X POST http://kms:8200/api/v1/approvals \
  -H 'Authorization: Bearer operator-a-token' \
  -d '{"operation":"ShredKey","key_id":"prod-master-key","required":2,"ttl_hours":24}'
# Returns {"id":"ticket-123","status":"pending"}

# 2. Operator B approves (A cannot self-approve)
curl -X POST http://kms:8200/api/v1/approvals/approve \
  -H 'Authorization: Bearer operator-b-token' \
  -d '{"id":"ticket-123"}'

# 3. Operator A executes shred with MFA + ticket ID
curl -X DELETE http://kms:8200/api/v1/keys/prod-master-key/shred \
  -H 'Authorization: Bearer operator-a-token' \
  -H 'X-MFA-Code: 123456' \
  -H 'X-Approval-Ticket-ID: ticket-123'
```

**Benefits**: Prevents single-point mistakes, prevents insider malice, full audit trail, auto-expiry cleanup.

---

### 2.8 Use Case Selection Matrix

| Scenario | Recommended Mode | Key Features | Complexity |
|---|---|---|---|
| Microservice encryption | Cluster | AppRole + envelope | ★★☆ |
| Database field encryption | Cluster | Encrypt + HMAC index | ★★☆ |
| AI Agent access | Cluster | MCP + restricted Policy | ★★☆ |
| GM compliance | Cluster + gmsm | SM2/SM3/SM4 + RFC 8998 | ★★★ |
| K8s integration | Cluster | K8s SA auth | ★★☆ |
| Multi-tenant SaaS | Cluster | Multi-tenant isolation | ★★☆ |
| Two-person approval | Cluster | MFA + Quorum | ★★★ |

---

## 3. Installation & Build

### 3.1 Prerequisites

- Go 1.25.11 or later
- PostgreSQL 14+ (Cluster mode only)
- Optional: SoftHSM (HSM testing), Chrome (Web console E2E testing)

### 3.2 Build from Source

```bash
git clone https://github.com/zealot00/Yvonne.git
cd Yvonne
make build
```

Output: `bin/yvonne` (13MB single binary, no runtime deps).

### 3.3 GM Build

```bash
go build -tags gmsm -o bin/yvonne-gmsm ./cmd/yvonne
```

Includes SM2/SM3/SM4 full stack, JWT SM2 signing, RFC 8998 GM TLS.

### 3.4 HSM Build

```bash
go build -tags hsm -o bin/yvonne-hsm ./cmd/yvonne
```

Integrates HSM via PKCS#11 interface.

### 3.5 Docker

```bash
docker build -t yvonne-kms .
docker run -p 8200:8200 yvonne-kms dev
```

### 3.6 Verify Installation

```bash
./bin/yvonne --help
./bin/yvonne dev --demo   # 30s startup + auto-create demo keys
```

---

## 4. Quick Start

### 4.1 Dev Mode (Zero Config)

```bash
./bin/yvonne dev --demo
```

After startup:
- API on `127.0.0.1:8200`
- Web console on `127.0.0.1:8250`
- In-memory storage, auto-unseal, 3 demo keys created

### 4.2 First Encryption

```bash
# Encrypt
curl -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"demo-order-key","plaintext":"SGVsbG8gWXZvbm5lIQ=="}'
# Returns {"ok":true,"data":{"ciphertext":"AAAA...","version":1}}

# Decrypt
curl -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"demo-order-key","ciphertext":"AAAA..."}'
# Returns {"ok":true,"data":{"plaintext":"SGVsbG8gWXZvbm5lIQ==","version":1}}
```

> **Note**: `plaintext` is a Base64-encoded byte string, not raw text.

### 4.3 Open Web Console

Visit `http://127.0.0.1:8250` in browser — Dashboard, Keys, Crypto, Audit pages.

### 4.4 Three-Protocol Verification

```bash
# HTTP REST
curl http://127.0.0.1:8200/api/v1/sys/health | jq .

# gRPC (requires grpc enabled)
grpcurl -plaintext 127.0.0.1:8201 yvonne.v1.YvonneService/Health

# MCP (AI Agent, requires mcp enabled)
# Call yvonne.encrypt / yvonne.decrypt via MCP protocol
```

---

## 5. Modes & Configuration

### 5.1 Two Modes

| Mode | Use Case | Storage | Unseal | Auth |
|---|---|---|---|---|
| `dev` | Dev/test | Memory | Auto | None (optional) |
| `cluster` | Production | PostgreSQL | Shamir / PKI / HSM | AppRole / JWT / K8s SA |

### 5.2 Config File

JSON format, loaded via `--config`. Full example: `deploy/examples/config-gmsm.json`.

#### Minimal Dev

No config needed: `./bin/yvonne dev`.

#### Minimal Cluster

```json
{
  "mode": "cluster",
  "server": {
    "bind_addr": "0.0.0.0",
    "bind_port": 8200,
    "tls": {"enabled": true, "cert_file": "/etc/yvonne/cert.pem", "key_file": "/etc/yvonne/key.pem"}
  },
  "storage": {
    "type": "postgres",
    "dsn": "postgresql://yvonne:password@db.internal:5432/yvonne"
  },
  "unseal": {
    "type": "shamir",
    "total_shares": 5,
    "threshold": 3
  },
  "auth": {
    "app_roles": [
      {
        "role_id": "admin",
        "token": "REPLACE_WITH_SECURE_TOKEN",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"]
      }
    ]
  },
  "audit": {
    "dir": "/var/log/yvonne",
    "retention_days": 180
  },
  "logging": {"level": "info", "redact_secrets": true}
}
```

### 5.3 Config Reference

#### `server`

| Field | Type | Default | Description |
|---|---|---|---|
| `bind_addr` | string | `127.0.0.1` | Listen address |
| `bind_port` | int | `8200` | API port |
| `tls.enabled` | bool | `false` | Enable TLS |
| `tls.cert_file` | string | - | TLS cert |
| `tls.key_file` | string | - | TLS key |
| `tls.gm_enabled` | bool | `false` | GM TLS (RFC 8998) |
| `grpc.enabled` | bool | `false` | Enable gRPC |
| `grpc.bind_port` | int | `8201` | gRPC port |
| `admin.enabled` | bool | `true` | Enable Web console |
| `admin.bind_port` | int | `8250` | Console port |
| `mcp.enabled` | bool | `false` | Enable MCP (AI Agent) |

#### `storage`

| Field | Description |
|---|---|
| `type` | `memory` (Dev) or `postgres` (Cluster) |
| `dsn` | PostgreSQL connection string (with password) |

#### `unseal`

| `type` | Description | Required Fields |
|---|---|---|
| `auto` | Dev auto-unseal | - |
| `shamir` | Shamir threshold unseal | `total_shares`, `threshold` |
| `local_pki` | Local PKI auto-unseal | `pki_key_path` |
| `hsm` | HSM hardware unseal | `hsm_backend`, `hsm_key_id` |

#### `auth`

Three auth methods, combinable:

- **AppRole**: static Token + Policy (service-to-service)
- **JWT**: RS/ES/HS/SM2 algorithms (user identity)
- **K8s SA**: Kubernetes ServiceAccount JWT (in-cluster Pods)

#### `crypto`

| Field | Description |
|---|---|
| `suite` | `standard` (AES-256-GCM + SHA-256) or `gmsm` (SM4-GCM + SM3) |
| `strict` | `true` enforces SM2/SM3/SM4 only, disables AES/RSA/ECDSA |

### 5.4 Environment Variable Overrides

Config file can be overridden by env vars (priority: env > file):

| Env | Overrides |
|---|---|
| `YVONNE_MODE` | `mode` |
| `YVONNE_STORAGE_TYPE` | `storage.type` |
| `YVONNE_STORAGE_DSN` | `storage.dsn` |
| `YVONNE_UNSEAL_TYPE` | `unseal.type` |
| `YVONNE_UNSEAL_THRESHOLD` | `unseal.threshold` |

### 5.5 Hot Reload

Send `SIGHUP` to hot-reload some config (no restart):

```bash
kill -HUP <yvonne-pid>
```

Hot-reloadable: `logging`, `audit`, `observability`.
Cold (requires restart): `server`, `storage`, `unseal`, `auth`.

---

## 6. Key Management

Yvonne supports 5 key types covering symmetric, asymmetric, and GM.

### 6.1 Key Types

| Type | Algorithm | Use Case | Endpoint |
|---|---|---|---|
| AES | AES-256-GCM | Envelope encryption, HMAC | `POST /api/v1/keys` |
| SM4 | SM4-GCM | GM envelope encryption | `POST /api/v1/keys` (gmsm) |
| RSA | RSA-4096 | Sign/verify | `POST /api/v1/keys/asymmetric` |
| ECDSA | ECDSA-P256 | Sign/verify | `POST /api/v1/keys/asymmetric` |
| SM2 | SM2 | GM sign/verify | `POST /api/v1/keys/asymmetric` (gmsm) |

### 6.2 Key Lifecycle

```
CreateKey → Active → RotateKey → Active(v2) → SoftDelete → RecycleBin → Restore/Reaper
                                                          ↓
                                                      ShredKey (crypto-shred)
```

#### Create symmetric key

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"order-key","algorithm":"AES-256-GCM"}'
```

#### Create asymmetric key

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/asymmetric \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"signing-key","key_type":"rsa"}'
# Returns {"ok":true,"data":{"public_key":"...","version":1}}
```

`key_type`: `rsa` / `ecdsa` / `sm2`.

#### Rotate key

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/order-key/rotate
# Old ciphertext still decryptable (version self-routing)
```

#### Soft delete (to recycle bin)

```bash
curl -X PATCH http://127.0.0.1:8200/api/v1/keys/order-key/soft-delete \
  -H 'Content-Type: application/json' \
  -d '{"version": 1}'
```

After soft delete: can still decrypt historical ciphertext, cannot encrypt, auto-shred after 90 days.

#### Restore from recycle bin

```bash
curl -X POST http://127.0.0.1:8200/api/v1/keys/order-key/restore \
  -H 'Content-Type: application/json' \
  -d '{"version": 1}'
```

#### Crypto-shred (permanent destruction)

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/order-key/shred
# Permanent; all ciphertext becomes undecryptable
```

> **Warning**: Shred is irreversible. If MFA is configured, requires `X-MFA-Code` header.

### 6.3 BYOK (Bring Your Own Key)

Import externally generated DEKs securely, without plaintext transmission.

```bash
# 1. Get temporary RSA-4096 transit public key (burn-after-reading)
curl http://127.0.0.1:8200/api/v1/keys/transit-pub
# Returns {"transit_key_id":"...","public_key":"..."}

# 2. Client encrypts its DEK with transit public key

# 3. Import wrapped DEK
curl -X POST http://127.0.0.1:8200/api/v1/keys/import \
  -H 'Content-Type: application/json' \
  -d '{
    "key_id":"imported-key",
    "transit_key_id":"...",
    "wrapped_material":"..."
  }'
```

### 6.4 Auto Rotation

Cluster mode: PostgreSQL Advisory Lock elects leader, hourly scan for expired keys, auto-rotate, Actor=`SYSTEM_DAEMON`.

### 6.5 Cold Storage Backup

Shamir-split Wrapped CMK to N USB drives, each shard with HMAC integrity check. See `yvonne init --wrapped-out`.

---

## 7. Cryptographic Operations

### 7.1 Envelope Encryption

```bash
# Encrypt
curl -X POST http://127.0.0.1:8200/api/v1/encrypt \
  -d '{"key_id":"order-key","plaintext":"SGVsbG8="}'

# Decrypt (auto-routes to correct version)
curl -X POST http://127.0.0.1:8200/api/v1/decrypt \
  -d '{"key_id":"order-key","ciphertext":"AAAA..."}'
```

**Ciphertext format**: `[uint32 version BE][nonce][ciphertext+tag]` — decrypt auto-routes to the correct DEK version; client does not manage versions.

### 7.2 Generate Data Key (GDK)

Client-side envelope encryption; KMS never sees business plaintext.

```bash
# With plaintext DEK (local encrypt)
curl -X POST http://127.0.0.1:8200/api/v1/keys/order-key/generate-data-key
# Returns {"plaintext_dek":"...","ciphertext_dek":"..."}

# Ciphertext-only DEK (safer)
curl -X POST "http://127.0.0.1:8200/api/v1/keys/gdk-no-plaintext?key_id=order-key"
# Returns {"ciphertext_dek":"..."}
```

### 7.3 Sign & Verify

```bash
# Sign (RSA-PSS / ECDSA / SM2)
curl -X POST http://127.0.0.1:8200/api/v1/sign \
  -d '{"key_id":"signing-key","data":"c2lnbi1tZQ=="}'
# Returns {"signature":"...","version":1}

# Verify
curl -X POST http://127.0.0.1:8200/api/v1/verify \
  -d '{"key_id":"signing-key","data":"c2lnbi1tZQ==","signature":"..."}'
# Returns {"valid":true,"version":1}
```

### 7.4 HMAC

```bash
# Generate MAC
curl -X POST http://127.0.0.1:8200/api/v1/mac/generate \
  -d '{"key_id":"hmac-key","data":"bWFjLWRhdGE="}'
# Returns {"mac":"...","version":1}

# Verify MAC (constant-time comparison)
curl -X POST http://127.0.0.1:8200/api/v1/mac/verify \
  -d '{"key_id":"hmac-key","data":"bWFjLWRhdGE=","mac":"..."}'
# Returns {"valid":true,"version":1}
```

> HMAC supports symmetric keys only (AES/SM4).

### 7.5 ReEncrypt

Migrate ciphertext from one key/version to another without client-side decrypt.

```bash
curl -X POST http://127.0.0.1:8200/api/v1/re-encrypt \
  -d '{
    "source_key_id":"order-key",
    "dest_key_id":"order-key-v2",
    "ciphertext":"AAAA..."
  }'
```

### 7.6 Get Public Key

```bash
curl "http://127.0.0.1:8200/api/v1/keys/public-key?key_id=signing-key"
# Returns {"public_key":"...","version":1}
```

---

## 8. Authentication & Authorization

### 8.1 Auth Methods

#### AppRole (service-to-service)

Static Token, suitable for service-to-service:

```json
{
  "auth": {
    "app_roles": [
      {
        "role_id": "order-service",
        "token": "secure-random-token",
        "allowed_keys": ["order-*"],
        "allowed_actions": ["encrypt", "decrypt"]
      }
    ]
  }
}
```

Call with header:

```bash
curl -H "Authorization: Bearer secure-random-token" http://127.0.0.1:8200/api/v1/...
```

#### JWT (user identity)

Supports RS256/384/512, ES256/384/512, HS256/384/512, SM2 — with algorithm confusion prevention.

```json
{
  "auth": {
    "jwt": {
      "signing_method": "RS256",
      "verifying_key_path": "/etc/yvonne/keys/jwt-pub.pem",
      "issuer": "your-issuer",
      "audience": ["yvonne-clients"]
    }
  }
}
```

#### Kubernetes ServiceAccount

In-cluster Pods auto-auth with SA JWT:

```json
{
  "auth": {
    "k8s": {
      "enabled": true,
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "audience": ["yvonne-kms"],
      "jwks_url": "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
      "role_mapping": {
        "default/order-app": {
          "role_id": "order-app",
          "allowed_keys": ["order-*"],
          "allowed_actions": ["encrypt", "decrypt"]
        }
      }
    }
  }
}
```

### 8.2 RBAC Model

#### Policy fields

| Field | Description |
|---|---|
| `RoleID` | Role ID |
| `AllowedKeys` | Allowed keys (`*` wildcard + prefix match) |
| `AllowedActions` | Allowed actions (e.g. `Encrypt`, `Decrypt`, `Sign`, `*`) |
| `TenantID` | Tenant ID (v1.3.1, multi-tenant) |

#### Resource-level authorization

Each request validates body `key_id` against `AllowedKeys`; default deny.

```json
{
  "role_id": "order-service",
  "allowed_keys": ["order-*", "payment-*"],
  "allowed_actions": ["encrypt", "decrypt", "generate-data-key"]
}
```

### 8.3 mTLS Client Certificates

Beyond Token auth, Yvonne supports mTLS mutual cert auth. Configure `client_ca_file` in `server.tls`.

---

## 9. Multi-Tenant Isolation

v1.3.1 introduces multi-tenant isolation via keyID prefix scoping.

### 9.1 Enable Multi-Tenant

```json
{
  "multi_tenant": {"enabled": true}
}
```

### 9.2 Tenant ID Binding

Configure `tenant_id` in AppRole:

```json
{
  "auth": {
    "app_roles": [
      {
        "role_id": "tenant-a-app",
        "token": "...",
        "allowed_keys": ["*"],
        "allowed_actions": ["*"],
        "tenant_id": "tenant-a"
      }
    ]
  }
}
```

### 9.3 Isolation Mechanism

- Tenant A creates `order-key` → stored as `tenant-a:order-key`
- Tenant B creates `order-key` → stored as `tenant-b:order-key`
- Tenant A cannot access `tenant-b:order-key` and vice versa

### 9.4 Backward Compatibility

`multi_tenant.enabled=false` (default): behavior is identical to single-tenant. Existing `key_id` gets no prefix.

---

## 10. MFA & Quorum Approval

### 10.1 MFA TOTP

v1.3 introduces RFC 6238 TOTP for sensitive operation二次确认.

#### Enable MFA

```json
{
  "mfa": {
    "enabled": true,
    "issuer": "Yvonne KMS",
    "window_seconds": 30,
    "sensitive_operations": ["ShredKey", "EmergencySeal", "ExportKey", "SoftDeleteKey"]
  }
}
```

#### Setup MFA

```bash
curl -X POST http://127.0.0.1:8200/api/v1/auth/mfa/setup \
  -H 'Authorization: Bearer <token>' \
  -d '{"role_id":"admin"}'
# Returns {"secret":"...","uri":"otpauth://totp/..."}
```

Scan the QR code (from `uri`) with Google Authenticator / 1Password.

#### Verify & enable

```bash
curl -X POST http://127.0.0.1:8200/api/v1/auth/mfa/verify \
  -H 'Authorization: Bearer <token>' \
  -d '{"role_id":"admin","code":"123456"}'
```

#### Sensitive operation with MFA

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/order-key/shred \
  -H 'Authorization: Bearer <token>' \
  -H 'X-MFA-Code: 123456'
```

Tolerance ±30s, replay-protected.

### 10.2 Quorum Approval

K-of-N approval workflow for high-sensitivity operations.

#### Create approval ticket

```bash
curl -X POST http://127.0.0.1:8200/api/v1/approvals \
  -H 'Authorization: Bearer <token>' \
  -d '{
    "operation":"ShredKey",
    "key_id":"order-key",
    "required":2,
    "ttl_hours":24
  }'
# Returns {"id":"ticket-xxx","status":"pending"}
```

#### Query & approve

```bash
# List pending
curl http://127.0.0.1:8200/api/v1/approvals \
  -H 'Authorization: Bearer <token>'

# Approve
curl -X POST http://127.0.0.1:8200/api/v1/approvals/approve \
  -H 'Authorization: Bearer <token>' \
  -d '{"id":"ticket-xxx"}'

# Reject
curl -X POST http://127.0.0.1:8200/api/v1/approvals/reject \
  -H 'Authorization: Bearer <token>' \
  -d '{"id":"ticket-xxx"}'
```

#### State machine

```
pending → approved (reaches K votes)
       → rejected (any rejection)
       → expired (TTL expires)
```

Features: anti-self-approve (creator cannot approve own ticket), idempotent (duplicate approvals no-op), auto-expiry cleanup.

### 10.3 Execute with Approval

```bash
curl -X DELETE http://127.0.0.1:8200/api/v1/keys/order-key/shred \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Approval-Ticket-ID: ticket-xxx'
```

---

## 11. Audit Log

### 11.1 Hash Chain Audit

Each key operation generates an audit record; records are chained via HMAC-SHA256 (or HMAC-SM3):

```
entry_1.signature = HMAC(key, entry_1.payload || prev_signature)
entry_2.signature = HMAC(key, entry_2.payload || entry_1.signature)
...
```

Tamper with any record — all subsequent signatures fail verification.

### 11.2 Dual-Write Strategy

- **File rotation**: daily rotation, retain `retention_days` (default 180)
- **Syslog dual-write**: async to syslog (tag=`yvonne-kms`), for SIEM ingestion

### 11.3 Audit Record Fields

```json
{
  "trace_id": "uuid",
  "timestamp": "2026-07-01T09:00:00Z",
  "client_ip": "10.0.0.1",
  "actor": "admin",
  "resource": "order-key",
  "action": "Encrypt",
  "result": "success",
  "status": "ok"
}
```

### 11.4 Query Audit

```bash
curl -X POST http://127.0.0.1:8200/api/v1/audit/query \
  -H 'Authorization: Bearer <token-with-AuditQuery-action>' \
  -d '{"limit":100,"action":"Encrypt"}'
```

Requires `AuditQuery` permission.

### 11.5 Verify Chain Integrity

```bash
yvonne audit verify --dir /var/log/yvonne
```

---

## 12. Observability

### 12.1 OpenTelemetry Tracing

```json
{
  "observability": {
    "tracing": {
      "enabled": true,
      "endpoint": "otel-collector:4317",
      "service_name": "yvonne-kms"
    }
  }
}
```

- OTLP gRPC exporter
- otelhttp auto-instrumentation
- TraceID propagates to audit log

### 12.2 Prometheus Metrics

```bash
curl http://127.0.0.1:8200/metrics
```

Metrics: request count, latency quantiles, failure rate, key count, sealed state, etc.

> Dev mode: metrics restricted to loopback. Cluster mode: requires `Metrics` action permission.

### 12.3 Webhook Alerting

```json
{
  "observability": {
    "alerting": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/...",
      "high_risk_operations": ["ShredKey", "EmergencySeal", "QuorumReject"]
    }
  }
}
```

Auto-detects Slack / DingTalk / PagerDuty format; high-risk operations trigger alerts.

### 12.4 Hot Reload

```bash
kill -HUP <yvonne-pid>
```

Hot-reloads `logging`, `audit`, `observability` without restart.

---

## 13. Web Console

### 13.1 Access

Open `http://<admin-bind>:8250` in browser; enter Bearer Token to login.

### 13.2 Pages

| Page | Function |
|---|---|
| Dashboard | Key count, Vault state, Sealed state |
| Keys | Key list, refresh |
| Crypto | Online encrypt/decrypt test |
| Audit | Audit log view (requires audit query permission) |
| MFA & Quorum | MFA/Quorum management entry (API calls) |

### 13.3 Security Policy

- Strict CSP: `script-src 'self'` (no CDN, no inline scripts, no `unsafe-eval`)
- Pure native JS (no Vue/Tailwind frameworks)
- Static assets embedded via `go:embed`

### 13.4 Admin REST API

| Method | Path | Description |
|---|---|---|
| GET | `/admin/api/dashboard` | Dashboard data |
| GET | `/admin/api/keys` | Key list |
| POST | `/admin/api/crypto/encrypt` | Encrypt (proxies to V1Router) |
| POST | `/admin/api/crypto/decrypt` | Decrypt (proxies to V1Router) |
| GET | `/admin/api/audit?limit=N` | Audit log |

---

## 14. SDK Guide

Yvonne provides SDKs in 3 languages, all with built-in retry, circuit breaker, and trace_id propagation.

### 14.1 Go SDK

```go
package main

import (
    "context"
    "fmt"
    "time"
    "yvonne/sdk/go/yvonne"
)

func main() {
    client := yvonne.NewWithOpts(
        "http://127.0.0.1:8200",
        "your-token",
        yvonne.WithRetry(yvonne.RetryConfig{
            MaxRetries:     3,
            InitialBackoff: 100 * time.Millisecond,
        }),
        yvonne.WithCircuitBreaker(yvonne.CircuitBreaker{
            Threshold:    5,
            ResetTimeout: 60 * time.Second,
        }),
        yvonne.WithTraceIDHeader("X-Request-ID"),
    )

    resp, err := client.Encrypt(ctx, &yvonne.EncryptRequest{
        KeyID:     "order-key",
        Plaintext: []byte("hello"),
    })
    if err != nil {
        panic(err)
    }
    fmt.Println("ciphertext:", resp.Ciphertext)
}
```

### 14.2 Python SDK

```python
from yvonne import YvonneClient

client = YvonneClient(
    "http://127.0.0.1:8200",
    token="your-token",
    max_retries=3,
    retry_backoff=0.1,
    circuit_breaker_threshold=5,
    trace_id_header="X-Request-ID",
)

# Encrypt
resp = client.encrypt("order-key", b"hello")
print(resp["ciphertext"])

# Decrypt
dec = client.decrypt("order-key", resp["ciphertext"])
print(dec["plaintext"])
```

### 14.3 Java SDK

```java
import io.yvonne.kms.YvonneClient;
import io.yvonne.kms.RetryConfig;
import io.yvonne.kms.CircuitBreaker;
import java.time.Duration;

YvonneClient client = YvonneClient.builder()
    .baseUrl("http://127.0.0.1:8200")
    .token("your-token")
    .timeout(Duration.ofSeconds(30))
    .retry(RetryConfig.defaultConfig())
    .circuitBreaker(CircuitBreaker.defaultBreaker())
    .traceIdHeader("X-Request-ID")
    .build();

JsonObject enc = client.encrypt("order-key", "hello".getBytes());
String ciphertext = enc.getAsJsonObject("data").get("ciphertext").getAsString();
```

### 14.4 Common SDK Features

| Feature | Description |
|---|---|
| Retry | Exponential backoff + jitter; only retries idempotent/network errors |
| Circuit breaker | closed → open (N consecutive failures) → half-open (probe after reset) |
| trace_id | Auto-generates UUID injected into header for cross-service tracing |
| Timeout | Default 30s, configurable |

---

## 15. Deployment

### 15.1 Single Node

```bash
./bin/yvonne server --config /etc/yvonne/config.json
```

For small-scale testing or single-node production (with `local_pki` unseal).

### 15.2 Cluster

Recommended: 3-node cluster + PostgreSQL primary/replica:

```
Node 1 ─┐
Node 2 ─┼── PostgreSQL (primary + replica)
Node 3 ─┘
```

All nodes share one PostgreSQL; Advisory Lock elects leader for background tasks (e.g. auto-rotation).

### 15.3 Reverse Proxy + mTLS

Yvonne is designed as an intranet service; expose via Nginx/Envoy + mTLS in production:

```nginx
server {
    listen 443 ssl;
    server_name kms.internal;

    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;
    ssl_client_certificate /etc/nginx/client-ca.pem;
    ssl_verify_client on;

    location / {
        proxy_pass http://127.0.0.1:8200;
    }
}
```

### 15.4 Kubernetes

See [docs/deployment.md](../deployment.md). Recommended: StatefulSet + PVC for audit log persistence.

### 15.5 Rolling Upgrade

1. Roll one node
2. Verify `/api/v1/sys/health` returns unsealed
3. Continue other nodes

Upgrade guide: [docs/upgrade-guide.md](../upgrade-guide.md).

### 15.6 Backup & Recovery

- **CMK cold backup**: `yvonne init --wrapped-out /mnt/usb/cmk-backup.bin` + Shamir split
- **Audit log backup**: daily cron of `/var/log/yvonne/audit-*.log`
- **PostgreSQL backup**: standard PG backup strategy

---

## 16. GM (Chinese National Crypto) Compliance

### 16.1 Enable GM

Build with `-tags gmsm`, configure:

```json
{
  "crypto": {
    "suite": "gmsm",
    "strict": true
  }
}
```

### 16.2 GM Full Stack

| Layer | Algorithm |
|---|---|
| Envelope encryption | SM4-GCM |
| Hash chain audit | HMAC-SM3 |
| Asymmetric signing | SM2 |
| JWT signing | SM2 |
| TLS | RFC 8998 (SM2 dual certs + SM4/SM3) |

### 16.3 Strict Mode

`crypto.strict: true`:
- Disables AES/RSA/ECDSA
- Only SM2/SM3/SM4 allowed
- Suitable for GM Level 2+ compliance

### 16.4 Level 2 Assessment

See [docs/compliance/self-assessment-level2.md](../compliance/self-assessment-level2.md) — 24-item assessment.

---

## 17. HSM Integration

### 17.1 PKCS#11

```bash
go build -tags hsm -o bin/yvonne-hsm ./cmd/yvonne
```

Config:

```json
{
  "unseal": {
    "type": "hsm",
    "hsm_backend": "pkcs11",
    "hsm_key_id": "yvonne-cmk"
  }
}
```

CMK never leaves the HSM chip; all crypto operations happen inside HSM.

### 17.2 SoftHSM (Testing)

CI uses SoftHSM to simulate hardware HSM. See [docs/pkcs11-hsm.md](../pkcs11-hsm.md).

### 17.3 KEK Abstraction

Yvonne provides unified KEK abstraction (`softwareKEK` / `hsmKEK`); business code is unaware whether HSM is enabled.

---

## 18. Troubleshooting

### 18.1 Common Issues

#### Service fails to start

```
error: cluster mode requires storage.type='postgres'
```

→ Check config `mode` field, or use `dev` mode.

#### Vault is sealed

```
{"ok":false,"error":"kms is sealed"}
```

→ Submit Shamir shares to unseal:

```bash
curl -X POST http://127.0.0.1:8200/api/v1/sys/unseal \
  -d '{"shares":["base64-share-1","base64-share-2","base64-share-3"]}'
```

#### 401 authentication required

→ Check `Authorization: Bearer <token>` header.

#### 403 action not allowed

→ Check Policy `AllowedActions`. `*` is wildcard.

#### Web console blank

→ Check browser console. Likely CSP block or embed cache stale.

```bash
go clean -cache  # Clear Go build cache
go build -o bin/yvonne ./cmd/yvonne  # Rebuild
```

### 18.2 Log Locations

- Application log: stdout (JSON)
- Audit log: `audit.dir` directory
- Syslog: `/var/log/system.log` (macOS) or `/var/log/syslog` (Linux)

### 18.3 Health Check

```bash
curl http://127.0.0.1:8200/api/v1/sys/health | jq .
# {"ok":true,"data":{"sealed":false,"state":"unsealed","status":"alive"}}
```

### 18.4 Emergency Seal

If you suspect key compromise, immediately emergency seal:

```bash
curl -X POST http://127.0.0.1:8200/api/v1/sys/panic \
  -H 'Authorization: Bearer <admin-token>'
```

All keys wiped from memory; requires manual restart + Shamir unseal to recover.

### 18.5 Debug Mode

```bash
YVONNE_LOG_LEVEL=debug ./bin/yvonne dev
```

### 18.6 Getting Help

- GitHub Issues: https://github.com/zealot00/Yvonne/issues
- Docs: [docs/](../)

---

## 19. Appendix

### 19.1 API Endpoint Reference

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/sys/health` | Health check |
| POST | `/api/v1/sys/unseal` | Submit Shamir shares |
| POST | `/api/v1/sys/panic` | Emergency seal |
| POST | `/api/v1/keys` | Create symmetric key |
| POST | `/api/v1/keys/asymmetric` | Create asymmetric key |
| GET | `/api/v1/keys/transit-pub` | BYOK transit public key |
| POST | `/api/v1/keys/import` | BYOK import |
| POST | `/api/v1/keys/{id}/rotate` | Rotate |
| DELETE | `/api/v1/keys/{id}/shred` | Crypto-shred |
| PATCH | `/api/v1/keys/{id}/soft-delete` | Soft delete |
| POST | `/api/v1/keys/{id}/restore` | Restore |
| POST | `/api/v1/keys/{id}/generate-data-key` | GDK |
| POST | `/api/v1/keys/gdk-no-plaintext` | GDK (ciphertext only) |
| GET | `/api/v1/keys/public-key` | Get public key |
| POST | `/api/v1/encrypt` | Envelope encrypt |
| POST | `/api/v1/decrypt` | Envelope decrypt |
| POST | `/api/v1/sign` | Sign |
| POST | `/api/v1/verify` | Verify |
| POST | `/api/v1/mac/generate` | HMAC generate |
| POST | `/api/v1/mac/verify` | HMAC verify |
| POST | `/api/v1/re-encrypt` | Re-encrypt |
| POST | `/api/v1/auth/mfa/setup` | MFA setup |
| POST | `/api/v1/auth/mfa/verify` | MFA verify |
| POST | `/api/v1/auth/mfa/disable` | MFA disable |
| POST | `/api/v1/approvals` | Create approval |
| GET | `/api/v1/approvals` | List/query approvals |
| POST | `/api/v1/approvals/approve` | Approve |
| POST | `/api/v1/approvals/reject` | Reject |
| POST | `/api/v1/audit/query` | Query audit |
| GET | `/metrics` | Prometheus metrics |

### 19.2 Error Codes

| HTTP | Meaning | Description |
|---|---|---|
| 200 | Success | - |
| 400 | Bad request | Missing/invalid params |
| 401 | Unauthorized | Token missing or invalid |
| 403 | Forbidden | Action or KeyID not in Policy |
| 404 | Not found | Key does not exist |
| 429 | Rate limited | Exceeded rate limit |
| 500 | Internal error | Server exception |
| 503 | Unavailable | Sealed or EmergencySealed |

### 19.3 Security Checklist

Run after every code change:

```bash
bash scripts/security-check.sh  # 12 security checks
gosec ./...                      # 0 issues
govulncheck ./...                # 0 vulnerabilities
```

### 19.4 Release Gate

Run before every release:

```bash
python3 scripts/release_gate_e2e.py
# Must pass 37/37 (3 skipped in dev mode)
```

### 19.5 Related Documentation

- [Product Roadmap](../roadmap.md)
- [Deliverables](../deliverables.md)
- [GM Compliance Guide](../gmsm-compliance.md)
- [Level 2 Self-Assessment](../compliance/self-assessment-level2.md)
- [v1.3 Compliance Features](../v1.3-compliance.md)
- [Deployment Guide](../deployment.md)
- [Upgrade Guide](../upgrade-guide.md)
- [gRPC API Guide](../grpc-api.md)
- [MCP API Guide](../mcp-api.md)
- [PKCS#11 HSM Guide](../pkcs11-hsm.md)
- [AES→SM4 Migration](../aes-to-sm4-migration.md)
- [Security Policy](../../SECURITY.md)
- [Changelog](../../CHANGELOG.md)

### 19.6 License

Apache License 2.0. See [LICENSE](../../LICENSE).

### 19.7 Compliance Disclaimer

> This project has NOT passed FIPS 140-3 or PCI-DSS formal audit. For strongly regulated environments (finance, healthcare, government), complete third-party audit + FIPS HSM integration + compliance certification before production deployment.

---

> Feedback: [GitHub Issues](https://github.com/zealot00/Yvonne/issues)
