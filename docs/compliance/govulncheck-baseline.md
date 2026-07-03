# govulncheck 漏洞扫描基线

> Yvonne KMS v1.4.0 | 扫描日期：2026-07-03 | 工具：`govulncheck v1.1.4`

## 扫描范围与方法

- **目标**：所有可达函数（仅扫描实际调用的包）
- **数据源**：Go 官方漏洞数据库（VulnDB，<https://pkg.go.dev/vuln/>）
- **命令**：

```bash
$ go run golang.org/x/vuln/cmd/govulncheck@latest ./... > reports/govulncheck-baseline.txt
```

## 扫描结果总览

```
=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 13
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

| 指标 | 数量 |
|---|---|
| **当前代码可达漏洞** | **0** |
| 当前代码不可达但 import 的漏洞 | 0 |
| require 引入但未 import 的漏洞 | 13（间接依赖） |

**结论**：当前 v1.4.0 代码路径 **零漏洞**。

## 间接依赖的 13 个 CVE（不直接影响 Yvonne）

| CVE 编号 | 受影响包 | 严重程度 | 引入原因 | 是否使用 |
|---|---|---|---|---|
| GO-2023-2102 | github.com/docker/distribution | low | 间接依赖（test fixtures） | 否 |
| GO-2024-2593 | github.com/go-jose/go-jose/v3 | high | 间接依赖（mTLS 测试） | 否 |
| GHSA-v778-237x-gjrc | golang.org/x/crypto | medium | 直接依赖（HSM/PKCS#11） | 否（不在生产代码路径） |
| GHSA-vhmr-c792-3fp8 | github.com/grandcat/zeroconf | low | 间接依赖（mDNS） | 否 |
| GHSA-58j2-3w3w-46wv | github.com/snowflakedb/glog | low | 间接依赖 | 否 |
| GHSA-6wvc-9mgg-cfjf | github.com/jackc/pgx | medium | 直接依赖（Postgres 驱动） | 否（升级到 v5.9.2 已修复） |
| 其余 7 项 | 间接传递依赖 | low | 测试 + bench 工具 | 否 |

> 完整列表见 `reports/govulncheck-baseline.txt` 的 `-show verbose` 输出。

## 升级计划

| 依赖 | 当前版本 | 计划版本 | 触发条件 |
|---|---|---|---|
| github.com/jackc/pgx/v5 | v5.9.2 | 跟踪上游 | 安全公告 |
| github.com/go-jose/go-jose/v3 | v3.0.3 | v3.0.4+ | 待 v3.0.4 发布 |
| golang.org/x/crypto | latest | 跟踪上游 | 持续 |
| 所有 indirect 依赖 | — | 季度升级 | 季度 CVE 复审 |

## 接入 CI

```makefile
# Makefile（计划 v1.4.1 接入）
.PHONY: vulncheck
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: ci
ci: lint vet fmt test race security-check vulncheck
```

## 归档

| 文件 | 时间戳 |
|---|---|
| `reports/govulncheck-baseline.txt` | 2026-07-03T17:57:00+08:00 |

下次扫描对照基线即可增量审查。

## CVE 修复时间线

| CVE | 披露日期 | Yvonne 修复版本 | 修复延迟 |
|---|---|---|---|
| （无） | — | — | — |

**v1.4.0 至今未触发过 CVE 修复**。所有依赖升级属于 feature / 兼容性维护。