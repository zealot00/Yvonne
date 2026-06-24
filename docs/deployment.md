# Deployment Guide

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.21+ | Build only |
| PostgreSQL | 14+ | Cluster mode storage |
| Linux/macOS | any | Production: Linux recommended |
| TPM 2.0 | optional | Future hardware unseal (roadmap) |

## 2. Binary Build

```bash
# Local build
make build

# Cross-compile (CI release)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/yvonne-linux-amd64 ./cmd/yvonne
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/yvonne-linux-arm64 ./cmd/yvonne
```

## 3. PostgreSQL Setup

```bash
# Create database and user
sudo -u postgres psql <<'SQL'
CREATE USER yvonne WITH PASSWORD 'strong-password-here';
CREATE DATABASE yvonne OWNER yvonne;
GRANT ALL PRIVILEGES ON DATABASE yvonne TO yvonne;
SQL

# Yvonne auto-creates the schema (yvonne_kv_str table) on first startup.
```

### Connection String (DSN)

```
postgres://yvonne:<password>@<host>:5432/yvonne?sslmode=require
```

**Production**: always use `sslmode=require` or `sslmode=verify-full`.

## 4. Configuration

### Cluster mode config (`config.json`)

```json
{
  "mode": "cluster",
  "server": {
    "bind_addr": "0.0.0.0",
    "bind_port": 8200,
    "tls": {
      "enabled": true,
      "min_version": "TLS1.3",
      "cert_file": "/etc/yvonne/tls.crt",
      "key_file": "/etc/yvonne/tls.key"
    },
    "admin": {
      "enabled": true,
      "bind_addr": "127.0.0.1",
      "bind_port": 8250
    }
  },
  "storage": {
    "type": "postgres",
    "dsn": "postgres://yvonne:password@db.internal:5432/yvonne?sslmode=require"
  },
  "unseal": {
    "type": "local_pki",
    "pki_key_path": "/var/run/yvonne/unseal.pem"
  },
  "logging": {
    "level": "info",
    "format": "json",
    "output": "stdout",
    "redact_secrets": true
  }
}
```

### Unseal modes

| Mode | Config | Use case |
|---|---|---|
| `shamir` | `"type": "shamir", "total_shares": 5, "threshold": 3` | Manual unseal, highest security |
| `local_pki` | `"type": "local_pki", "pki_key_path": "/path/unseal.pem"` | Auto-unseal, zero-cost |

## 5. Initialization (first-time setup)

```bash
# Step 1: Generate RSA-4096 key pair
./bin/yvonne unseal-keygen --out /var/run/yvonne/unseal.pem
# Private key → /var/run/yvonne/unseal.pem (0600)
# Public key → stdout (save to file for init)

# Step 2: Initialize CMK in database
./bin/yvonne init --config config.json --pub-key /tmp/unseal_pub.pem
# Generates 32-byte CMK → RSA-OAEP encrypt → writes to DB

# Step 3: (Optional) Shamir cold backup to USB drives
./bin/yvonne backup-split --config config.json --out-dir /mnt/usb --total 5 --threshold 3
# Writes backup-001.dat ... backup-005.dat, distribute to 5 USB drives
```

## 6. Start

```bash
./bin/yvonne server --config config.json
```

- API listens on `:8200`
- Admin Web UI on `127.0.0.1:8250`
- Metrics on `:8200/metrics`

## 7. Systemd Service

```ini
# /etc/systemd/system/yvonne.service
[Unit]
Description=Yvonne KMS
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=yvonne
Group=yvonne
ExecStart=/usr/local/bin/yvonne server --config /etc/yvonne/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/yvonne /var/run/yvonne
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now yvonne
```

## 8. Docker Deployment

```dockerfile
# Dockerfile
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /yvonne ./cmd/yvonne

FROM gcr.io/distroless/static
COPY --from=builder /yvonne /yvonne
ENTRYPOINT ["/yvonne"]
```

```bash
docker build -t yvonne .

docker run -d \
  --name yvonne \
  -p 8200:8200 \
  -p 8250:8250 \
  -v /etc/yvonne:/etc/yvonne:ro \
  -v /var/log/yvonne:/var/log/yvonne \
  yvonne server --config /etc/yvonne/config.json
```

## 9. PostgreSQL LISTEN/NOTIFY (multi-node cache sync)

Yvonne uses Postgres `LISTEN/NOTIFY` for cluster-wide cache invalidation. When any node rotates or shreds a key, all other nodes receive a notification and invalidate their local DEK cache.

- Channel: `yvonne_cache_invalidation`
- Payload: `KeyID`
- Auto-reconnect: on connection loss, entire cache is cleared (prevents stale data)

No configuration needed — this is automatic when using `PostgresKVStore`.

## 10. Audit Log

### File rotation

- Path: `/var/log/yvonne/audit.log` (configurable)
- Permissions: file `0600`, directory `0700`
- Daily rotation: `audit.log` → `audit-YYYYMMDD.log`
- Retention: 180 days (auto-prune)
- High-risk actions (`Rotate`, `ShredKey`, `EmergencySeal`): `file.Sync()` forced

### Syslog dual-write

- Facility: `LOG_AUTHPRIV|LOG_INFO`
- Tag: `yvonne-kms`
- Async via buffered channel (4096 capacity)
- Non-blocking: if syslogd is slow/down, logs are dropped (never blocks API)

### Hash chain

- Each log entry: `Signature = HMAC-SHA256(AuditKey, prevSignature + payload)`
- Chain anchor: `SHA256(AuditKey)`, persisted to `/var/log/yvonne/audit.chain`
- Each envelope contains `PrevSignature` for independent verification
- Restart recovery: anchor file restored on startup, chain continues

## 11. Emergency Seal

```bash
# Trigger immediate deep freeze
curl -X POST http://127.0.0.1:8200/api/v1/sys/panic \
  -H "Content-Type: application/json" \
  -d '{"admin_token":"<admin-token>","confirm":true}'
```

After emergency seal:
- Master Key wiped from memory
- All API requests return 503
- Process must be killed and cold-restarted
- Shamir unseal required to resume

## 12. Monitoring

### Prometheus metrics

| Metric | Type | Description |
|---|---|---|
| `yvonne_api_request_duration_seconds` | histogram | API latency (P99) |
| `yvonne_decrypt_failures_total` | counter | Decrypt failures (spike = tamper attempt) |
| `yvonne_encrypt_failures_total` | counter | Encrypt failures |
| `yvonne_api_requests_total{action}` | counter | Requests by action |
| `go_goroutines` | gauge | Goroutine count |
| `go_memstats_alloc_bytes` | gauge | Heap allocation |

### Grafana P99 query

```promql
histogram_quantile(0.99, rate(yvonne_api_request_duration_seconds_bucket[5m]))
```

### Alerting recommendations

| Alert | Condition | Severity |
|---|---|---|
| KMS sealed | `yvonne_sealed == 1` | Critical |
| Decrypt failures spike | `rate(yvonne_decrypt_failures_total[5m]) > 1` | High |
| Emergency sealed | `yvonne_emergency_sealed == 1` | Critical |
| Audit syslog drops | `yvonne_syslog_dropped_total` increasing | Medium |

## 13. Backup & Recovery

### Regular backup

- **PostgreSQL**: `pg_dump yvonne` (contains Wrapped CMK + DEK metadata)
- **Shamir USB drives**: `yvonne backup-split` (cold storage)

### Disaster recovery

```bash
# 1. Restore PostgreSQL from backup
pg_restore -d yvonne yvonne_backup.dump

# 2. (If DB lost) Restore Wrapped CMK from USB drives
./bin/yvonne backup-restore --out /tmp/wrapped-cmk.bin \
  /mnt/usb1/backup-001.dat /mnt/usb2/backup-002.dat /mnt/usb3/backup-003.dat

# 3. (If unseal.pem lost) Restore from physical safe
cp /secure/offsite/unseal.pem /var/run/yvonne/unseal.pem

# 4. Start Yvonne
./bin/yvonne server --config config.json
```

## 14. Security Hardening Checklist

- [ ] TLS enabled (`tls.enabled: true`, min TLS 1.3)
- [ ] `logging.redact_secrets: true`
- [ ] Admin UI bound to `127.0.0.1` only
- [ ] PostgreSQL `sslmode=verify-full`
- [ ] PEM file permissions `0600`, owned by `yvonne` user
- [ ] Audit log directory `0700`, owned by `yvonne` user
- [ ] Systemd `ProtectSystem=strict`
- [ ] Firewall: only API port (8200) exposed, admin port (8250) local only
- [ ] Shamir shards distributed to different physical locations
- [ ] USB cold backup drives stored offsite
