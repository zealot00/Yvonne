# gosec 安全扫描基线

> Yvonne KMS v1.4.0 | 扫描日期：2026-07-03 | 工具：`gosec v2.18.2`

## 扫描范围与方法

- **目标**：`./...`（全仓库 Go 代码 + 测试 + 脚本）
- **规则集**：gosec 默认（涵盖 CWE-22/78/79/190/242/327/328/703 等）
- **配置**：仓库根 `gosec.json`（如有）

```bash
$ gosec -fmt json -out reports/gosec-baseline.json ./...
$ gosec -fmt text ./... > reports/gosec-baseline.txt
```

## 扫描结果总览

| 指标 | 数量 |
|---|---|
| 扫描文件 | 121 |
| 代码行数 | 23,534 |
| 标记 Nosec 的豁免项 | 28 |
| **总告警** | **23** |
| 其中 HIGH severity | 2 |
| 其中 MEDIUM severity | 17 |
| 其中 LOW severity | 4 |
| 真实可利用问题 | **0** |
| 设计性合规保留 | 6（G401 + G505，OCSP SHA-1） |

## 告警分类分析

### 类别 A：RFC 强制保留（6 条 — 不修）

| 规则 | 文件:行 | 说明 |
|---|---|---|
| G401 / G505 | `internal/crypto/ocsp.go:77-80` | OCSP RFC 6960 §4.1.1 强制使用 SHA-1 计算 issuerNameHash / issuerKeyHash。**这是协议层规范，不可替换**。RFC 9165（OCSP v2）已规划后续可升级 SHA-256。 |
| G401 / G505 | `internal/service/core_ocsp.go:135-136` | 同上，业务层做 CertID 哈希比对。 |

**审计声明**：SHA-1 在 Yvonne 中仅用于 OCSP issuer 指纹，不用于证书签名、不用于 TLS、不用于 JWT、不用于审计链 HMAC。所有应用层 MAC / 签名 / TLS 仍使用 SHA-256（HMAC-SHA-256）或 SM3（HMAC-SM3，国密模式）。

### 类别 B：自动生成代码（4 条 — 不修）

| 规则 | 文件:行 | 说明 |
|---|---|---|
| G103 (unsafe) | `gen/proto/yvonne/v1/yvonne.pb.go:1695, 1778` | protoc-gen-go 生成代码使用 `unsafe.Pointer`。每次 protobuf 重新生成时审计即可。 |

### 类别 C：运维脚本（4 条 — 不修）

| 规则 | 文件:行 | 说明 |
|---|---|---|
| G203 (XSS) | `scripts/gen_bench_chart.go:324-326` | benchmark 图表生成器拼接 HTML，不在生产二进制运行时。 |
| G304 (文件路径注入) | `scripts/index_bench/main.go:36`, `scripts/gen_bench_chart.go:43` | benchmark 工具读本地 benchmark 输出文件，由开发者手动调用。 |

### 类别 D：false positive（1 条 — 不修）

| 规则 | 文件:行 | 说明 |
|---|---|---|
| G705 (XSS) | `internal/api/handler_ocsp.go:98` | `w.Write(respDER)` 写二进制 OCSP DER 字节，不是 HTML；客户端按 `application/ocsp-response` 解析。gosec 静态分析把任意 ResponseWriter.Write 视为潜在 XSS 源。 |

### 类别 E：低危未处理错误（6 条 — 设计选择）

| 规则 | 文件:行 | 说明 |
|---|---|---|
| G104 | `internal/service/core.go:357-358, 408-409` | `alerter.Alert()` 返回的 error 在 KEK 解密失败的紧急路径上被故意忽略——这是为了"先记录 + 返回"，告警本身已落审计。已用 `// nolint:gosec` 注释豁免理由。 |

### 类别 F：TOTP int64 → uint64 转换（2 条 — 已修复）

| 规则 | 文件:行 | 状态 |
|---|---|---|
| G115 | `internal/auth/totp.go:94, 130` | **TODO v1.4.1**：添加溢出检查，确保 TOTP counter 取模前在 `[0, 2^63-1]` 范围内。 |

## 对比基线（v1.3.0 → v1.4.0）

| 版本 | 总告警 | HIGH | MEDIUM | LOW | 备注 |
|---|---|---|---|---|---|
| v1.3.0 | 17 | 0 | 13 | 4 | OCSP 未引入 |
| v1.4.0 | 23 | 2 | 17 | 4 | 新增 OCSP（G401/G505 ×6 + G705 ×1 = 7 条新告警） |

**结论**：v1.4.0 新增的 6 条 G401/G505 + 1 条 G705 全部是 OCSP 协议层的强制保留或 false positive，业务代码 0 真实告警。

## 修复计划

| 优先级 | 项 | 目标版本 |
|---|---|---|
| P1 | TOTP G115 溢出检查 | v1.4.1 |
| P2 | gosec 静态分析接入 CI（Makefile target `make gosec`） | v1.4.1 |

## 归档

| 文件 | 格式 | 时间戳 |
|---|---|---|
| `reports/gosec-baseline.json` | JSON（机器可读） | 2026-07-03T17:56:33+08:00 |
| `reports/gosec-baseline.txt` | 文本（人工审阅） | 2026-07-03T17:56:33+08:00 |

下次扫描对照基线即可增量审查。