# Code review guidelines for Yvonne KMS

## 安全红线 Checklist

每个 PR 合并前必须通过以下检查：

### 自动化检查（CI 强制）

- [ ] `go vet ./...` 通过
- [ ] `gofmt -l .` 无输出
- [ ] `go test ./... -race` 全部通过
- [ ] `bash scripts/security-check.sh` 11 项全 PASS
- [ ] PostgreSQL 集成测试通过（`-tags=integration`）
- [ ] GoSec 静态分析无中危以上告警
- [ ] govulncheck 无已知漏洞

### 人工 Code Review 要点

#### 密码学安全
- [ ] 无 `math/rand` import
- [ ] 随机数全部通过 `memguard.GenerateSecureRandom` 获取
- [ ] 敏感数据比较用 `subtle.ConstantTimeCompare`，非 `==`/`!=`
- [ ] `clear()` 后紧跟 `runtime.KeepAlive()`
- [ ] 明文密钥参数类型为 `*memguard.SecureBuffer`，非 `[]byte`

#### 内存安全
- [ ] `io.ReadAll(req.Body)` 结果在 handler 内 `clear()` + `KeepAlive()`
- [ ] `SecureBuffer` 用完 `Wipe()`
- [ ] 临时明文切片有 `defer clear` 兜底
- [ ] `MemoryStore.Delete` 先 `clear(value)` 后 `delete(map, key)`

#### API 安全
- [ ] Sealed 状态返回 503
- [ ] 认证中间件覆盖所有业务路由
- [ ] 审计日志不含明文/密文/Token
- [ ] 越权返回 403 并记录审计日志
- [ ] HTTP body 读后立即清理（Payload Escaping Control）

#### 并发安全
- [ ] 共享状态用 `sync.RWMutex` 保护
- [ ] 后台 goroutine 绑定 `context.Context`
- [ ] 事务内用 `SELECT FOR UPDATE` 行级锁
- [ ] 无 goroutine 泄露（优雅停机时退出）

#### 合规
- [ ] 审计日志含 HMAC-SHA256 签名
- [ ] 日志脱敏（DSN 密码替换为 `xxxxx`）
- [ ] `logging.redact_secrets` 强制为 `true`（Cluster 模式）
- [ ] Crypto-Shredding 执行 UPDATE NULL + DELETE 两步
