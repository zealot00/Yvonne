# Yvonne KMS 渗透测试报告模板

> 测试对象：Yvonne KMS v1.4.0
> 测试标准：PTES（Penetration Testing Execution Standard）+ OWASP API Security Top 10
> 测试模式：cluster + dev
> 测试日期：YYYY-MM-DD（执行时填充）
> 报告版本：v1.0-template

---

## 0. 报告信息

| 项 | 值 |
|---|---|
| 客户名称 | ____________________ |
| 测试目标 | Yvonne KMS v1.4.0（YYYY-MM-DD 时版本） |
| 测试模式 | ☐ dev ☐ cluster ☐ mock |
| 测试窗口 | ____年__月__日 - ____年__月__日 |
| 测试方法 | ☐ 黑盒 ☐ 灰盒 ☐ 白盒 |
| 渗透测试员 | ____________________（姓名 + 资质证书号） |
| 复核人 | ____________________ |
| 报告日期 | ____年__月__日 |

## 0.1 测试范围

| 范围类型 | 详情 |
|---|---|
| 应用地址 | https://yvonne.example.com:8200 / 8250 |
| API 端点 | /v1, /v1.2, /api/v1, /admin |
| 测试账户 | 提供低权限测试账号 + MFA token |
| 排除项 | ☐ 拒绝服务攻击 ☐ 社会工程 ☐ 第三方依赖深度测试 |
| 工具许可 | ☐ Burp Suite Pro ☐ OWASP ZAP ☐ Nmap ☐ 自研脚本 |

## 0.2 风险评级标准

| 等级 | CVSS v3.1 范围 | 描述 |
|---|---|---|
| 严重 (Critical) | 9.0 - 10.0 | 直接获取密钥或主密钥 |
| 高 (High) | 7.0 - 8.9 | 绕过认证或获得解密能力 |
| 中 (Medium) | 4.0 - 6.9 | 信息泄露、权限提升 |
| 低 (Low) | 0.1 - 3.9 | 轻微信息泄露、可疑行为 |
| 信息 (Info) | 0.0 | 不构成安全风险 |

---

## 1. 测试摘要

| 类别 | 总用例 | 严重 | 高 | 中 | 低 | 通过 |
|---|---|---|---|---|---|---|
| 1. 认证与会话 | 12 | | | | | |
| 2. 授权与访问控制 | 16 | | | | | |
| 3. 输入验证 | 14 | | | | | |
| 4. 加密与密钥管理 | 12 | | | | | |
| 5. 业务逻辑 | 10 | | | | | |
| 6. 错误处理与日志 | 8 | | | | | |
| 7. 配置与部署 | 12 | | | | | |
| 8. 客户端与 API | 10 | | | | | |
| **合计** | **94** | | | | | |

测试结论（执行时填充）：

☐ **通过**（无 Critical / High 漏洞）
☐ **有条件通过**（存在 Medium，但有 30 天整改计划）
☐ **不通过**（存在 Critical / High 漏洞，必须立即修复）

---

## 2. 详细测试用例

### 2.1 认证与会话（12 用例）

#### TC-AUTH-01：暴力破解登录

- **目标**：`POST /v1/auth/approle/login`
- **方法**：使用 Burp Intruder，10 万条密码字典
- **预期行为**：5 次失败后 IP 锁 15 分钟；所有失败尝试记录审计
- **通过标准**：
  - 锁定机制生效
  - 没有审计记录泄露（如 actor 包含尝试的用户名但不在审计链）
- **风险等级**：高（无锁定 → 严重）
- **测试结果**：☐ 通过 ☐ 失败（详见 §漏洞清单）

#### TC-AUTH-02：JWT Token 弱签名

- **目标**：伪造 HMAC-SHA256 JWT
- **方法**：尝试用 `none` alg 伪造 + 字典爆破
- **预期行为**：拒绝 `alg=none`；签名验证拒绝任何不匹配 token
- **通过标准**：
  - `none` 攻击 100% 拒绝
  - 错误签名 100% 拒绝（401 Unauthorized）
- **风险等级**：严重（伪造可能 → 严重）
- **测试结果**：

#### TC-AUTH-03：JWT Token 过期检查

- **目标**：`exp` claim 验证
- **方法**：构造过期 token（修改 `exp` 到 1 年前）
- **预期行为**：拒绝 + 401
- **通过标准**：100% 拒绝过期 token
- **风险等级**：高
- **测试结果**：

#### TC-AUTH-04：会话固定（Session Fixation）

- **目标**：登录前后 session ID 是否被强制重置
- **方法**：登录前获得 session ID，登录后验证是否变更
- **预期行为**：JWT 模式无 session，但验证 token 是否原 token 仍然有效
- **通过标准**：登录前后 token 不同
- **风险等级**：中
- **测试结果**：

#### TC-AUTH-05：MFA 绕过

- **目标**：敏感操作（ShredKey / EmergencySeal）
- **方法**：
  1. 登录带 Bearer Token，尝试触发敏感操作不带 MFA
  2. 使用 Burp 修改 X-MFA 头伪造 MFA 通过
- **预期行为**：无 MFA → 拒绝 + 触发 audit alert
- **通过标准**：100% 拒绝无 MFA 敏感操作
- **风险等级**：严重
- **测试结果**：

#### TC-AUTH-06：客户端证书 mTLS 绕过

- **目标**：`/admin` 端点
- **方法**：使用合法客户端证书尝试访问其他用户资源
- **预期行为**：证书 subject CN 必须匹配 AppRole
- **通过标准**：越权访问 100% 拒绝
- **风险等级**：高
- **测试结果**：

#### TC-AUTH-07：密码重置功能

- **Yvonne 实现**：N/A（KMS 不暴露密码重置接口）
- **测试方法**：尝试访问 `/v1/auth/password/reset`
- **预期行为**：404 Not Found
- **测试结果**：

#### TC-AUTH-08：访问令牌复用

- **目标**：Revoke Token 后验证不可复用
- **方法**：获得 token → POST /v1/auth/token/revoke-self → 重用旧 token
- **预期行为**：403 Token Invalid
- **通过标准**：100% 拒绝已撤销 token
- **风险等级**：高
- **测试结果**：

#### TC-AUTH-09：Token TTL 长时复用

- **目标**：1 小时后 token 失效
- **方法**：登录获得 token，1 小时 1 分后重用
- **预期行为**：403 Token Expired
- **测试结果**：

#### TC-AUTH-10：JWT claim 篡改

- **目标**：篡改 `sub` claim 从 user-A 到 admin
- **方法**：使用 Burp 修改 claim 重新签名（无密钥应该失败）
- **预期行为**：签名验证失败
- **风险等级**：严重
- **测试结果**：

#### TC-AUTH-11：TLS 客户端认证降级

- **目标**：是否强制 mTLS 在 cluster 模式
- **方法**：尝试仅用 IP 白名单（无客户端证书）访问
- **预期行为**：必须客户端证书，否则 401
- **测试结果**：

#### TC-AUTH-12：MFA 重放攻击

- **目标**：TOTP 重放（窗口外）
- **方法**：使用合法 TOTP 提交，等待 90 秒（窗口外）后重用
- **预期行为**：TOTP 验证默认 ±30s 窗口
- **测试结果**：

### 2.2 授权与访问控制（16 用例）

#### TC-AZ-01：水平越权（不同 AppRole）

- **目标**：用户 A 读取用户 B 的密钥
- **方法**：用 A token 访问 `/v1/transit/keys/b-key`
- **预期行为**：403 Forbidden（即使路径存在）
- **风险等级**：严重
- **测试结果**：

#### TC-AZ-02：垂直越权（AppRole 提权）

- **目标**：低权限角色访问 admin 路径
- **方法**：用 read-only token 访问 `/admin/api/crypto/*`
- **预期行为**：403
- **测试结果**：

#### TC-AZ-03：路径穿透

- **目标**：`/v1/transit/keys/../keys/admin-key`
- **方法**：尝试 `..` 注入路径
- **预期行为**：标准化路径 + 403
- **测试结果**：

#### TC-AZ-04：HTTP 方法绕过

- **目标**：GET / PUT / DELETE vs 允许 POST
- **方法**：OPTIONS / PUT 探测
- **预期行为**：405 Method Not Allowed
- **测试结果**：

#### TC-AZ-05：协议层覆盖（Header 注入）

- **目标**：通过 X-Forwarded-For 伪造 IP
- **方法**：设置 `X-Forwarded-For: 10.0.0.1`（白名单 IP）
- **预期行为**：使用 proxy protocol 而非 header 信任
- **测试结果**：

#### TC-AZ-06：参数覆盖

- **目标**：通过 query 参数覆盖路径
- **方法**：`POST /v1/transit/keys/foo?role=admin`
- **预期行为**：query 参数不影响角色判定
- **测试结果**：

#### TC-AZ-07：未授权端点列举

- **目标**：`/v1/sys/seal-status` 等
- **方法**：gobuster/dirb 扫描
- **预期行为**：仅 401（未登录）/ 403（无权限）/ 404（不存在）
- **测试结果**：

#### TC-AZ-08：跨租户隔离（multi-tenant）

- **Yvonne 实现**：N/A（KMS 不支持多租户）
- **测试方法**：尝试访问不同 namespace
- **测试结果**：

#### TC-AZ-09：Root Token 滥用

- **目标**：测试 root token 是否有过度权限
- **方法**：用 root 执行一切操作
- **预期行为**：root 可执行一切，但需要审计 + MFA（敏感操作）
- **测试结果**：

#### TC-AZ-10：撤销 token 后立即失效

- **目标**：实时撤销
- **方法**：revoke → 1 秒后重用
- **预期行为**：立即失效
- **测试结果**：

#### TC-AZ-11：访问审计（不可绕过）

- **目标**：所有访问应该产生审计
- **方法**：通过合法 token 访问 100 次
- **预期行为**：100 条审计记录
- **测试结果**：

#### TC-AZ-12：审计权限隔离

- **目标**：admin 不能读审计员资源
- **方法**：用 admin token 访问 audit-read 路径
- **预期行为**：403
- **测试结果**：

#### TC-AZ-13：AppRole policy 边界

- **目标**：测试越界访问
- **方法**：访问未在 allowed_paths 中的路径
- **预期行为**：403
- **测试结果**：

#### TC-AZ-14：AppRole token TTL 校验

- **目标**：测试 TTL 是否强制
- **方法**：构造一个 TTL 异常的 token
- **测试结果**：

#### TC-AZ-15：IDOR（Insecure Direct Object Reference）

- **目标**：直接访问别人的密钥 ID
- **测试结果**：

#### TC-AZ-16：批量操作越权

- **目标**：批量 encrypt 包含越权 key
- **方法**：`POST /v1/transit/encrypt/{key}` 加密越权 key 名
- **测试结果**：

### 2.3 输入验证（14 用例）

#### TC-IV-01：JSON 注入

- **目标**：JSON payload 中注入额外字段
- **方法**：`{"key_id": "valid", "admin": true}`
- **预期行为**：忽略额外字段或拒绝
- **测试结果**：

#### TC-IV-02：超长输入 DoS

- **目标**：1 MB plaintext 提交
- **方法**：发送 1 GB JSON 一次
- **预期行为**：超过 payload 大小限制立即 413
- **配置**：`http.max_bytes_reader` 默认 1 MB
- **测试结果**：

#### TC-IV-03：ReDoS（正则表达式 DoS）

- **目标**：使用 ReDoS 正则的字段
- **方法**：提交特殊模式字符串
- **预期行为**：无 ReDoS 漏洞
- **测试结果**：

#### TC-IV-04：SQL 注入

- **目标**：`key_id` 或 `actor` 字段
- **方法**：classic SQLi payload `' OR '1'='1`
- **预期行为**：参数化查询，无注入
- **测试结果**：

#### TC-IV-05：NoSQL 注入

- **目标**：JSON 字段
- **方法**：`{"$ne": null}`
- **预期行为**：拒绝意外类型
- **测试结果**：

#### TC-IV-06：XSS（如果前端）

- **目标**：Audit 日志显示 XSS payload
- **方法**：在 key 名称中包含 `<script>` 字符串
- **预期行为**：HTML 转义显示
- **测试结果**：

#### TC-IV-07：命令注入

- **目标**：`actor` 或 `trace_id` 字段
- **方法**：`actor = "user; cat /etc/passwd"`
- **预期行为**：被识别为字符串，无 shell 解析
- **测试结果**：

#### TC-IV-08：路径遍历

- **目标**：备份文件路径参数
- **方法**：`file=../../etc/shadow`
- **预期行为**：限制在 `/var/backups/yvonne/*` 内
- **测试结果**：

#### TC-IV-09：SSRF（Server-Side Request Forgery）

- **Yvonne 实现**：N/A（KMS 不会主动 fetch 外部 URL）
- **测试结果**：

#### TC-IV-10：XML 注入（如果输入含 XML）

- **Yvonne 实现**：JSON only，无 XML 输入
- **测试结果**：

#### TC-IV-11：整数溢出

- **目标**：金额 / 计数 / 长度字段
- **方法**：传 `MaxInt64 + 1`
- **预期行为**：拒绝 + 400
- **测试结果**：

#### TC-IV-12：Unicode 标准化绕过

- **目标**：用 Unicode 字符尝试绕过路径
- **方法**：登录名 `ADMIN`（使用 Unicode 同形字符）
- **预期行为**：Unicode 标准化
- **测试结果**：

#### TC-IV-13：HTTP Request Smuggling

- **目标**：CL-TE 走私
- **方法**：构造 CL/TE 双编码
- **预期行为**：Go net/http 安全（无漏洞）
- **测试结果**：

#### TC-IV-14：HTTP/2 协议降级

- **目标**：尝试降级到 HTTP/1.1 走私
- **方法**：通过 alpn 切换
- **预期行为**：TLS 握手固定 ALPN
- **测试结果**：

### 2.4 加密与密钥管理（12 用例）

#### TC-CR-01：未授权密钥读取

- **目标**：尝试读取别人的私钥
- **方法**：访问 `/v1/transit/export` 应返回 405 / 403
- **预期行为**：私钥不可导出（仅签名/解密接口）
- **风险等级**：严重
- **测试结果**：

#### TC-CR-02：明文密钥泄露

- **目标**：备份文件 / 数据库 dump
- **方法**：dump PG 数据库
- **预期行为**：所有 key 字段都是 wrapped_blob 加密形式
- **测试结果**：

#### TC-CR-03：弱随机数

- **目标**：密钥生成 / nonce 生成
- **方法**：生成 1000 个 nonce 看分布
- **预期行为**：通过 NIST 子集检测
- **测试结果**：

#### TC-CR-04：密钥派生参数硬编码

- **目标**：HMAC-SHA256 key 是否硬编码
- **方法**：代码搜索 + 运行时 memory dump
- **预期行为**：所有 key 来自 SecureBuffer
- **测试结果**：

#### TC-CR-05：算法降级

- **目标**：强制使用 AES-128 而非 AES-256
- **方法**：配置层 + API 层双重检查
- **测试结果**：

#### TC-CR-06：弱 RSA 密钥

- **目标**：测试是否允许 1024 位 RSA
- **方法**：`POST /v1/transit/keys/foo` 带 `bits=1024`
- **预期行为**：拒绝小于 2048 位的 RSA
- **测试结果**：

#### TC-CR-07：弱 SM2 曲线

- **目标**：测试是否允许自定义椭圆曲线
- **方法**：尝试修改曲线参数
- **预期行为**：固定 GM/T 0009 标准曲线
- **测试结果**：

#### TC-CR-08：哈希碰撞攻击

- **目标**：SM3 / SHA-256
- **方法**：构造 SM3 碰撞对
- **预期行为**：使用成熟实现（gmsm / Go stdlib），无已知攻击
- **测试结果**：

#### TC-CR-09：侧信道（时序攻击）

- **目标**：HMAC 比较是否时序安全
- **方法**：使用 `subtle.ConstantTimeCompare`
- **测试结果**：

#### TC-CR-10：密钥重用（nonce reuse）

- **目标**：GCM nonce
- **方法**：100 万次加密看 nonce 重复率
- **预期行为**：0% 重复
- **测试结果**：

#### TC-CR-11：证书 CRL / OCSP 篡改

- **目标**：CRL 签名验证
- **方法**：尝试添加伪造撤销条目到 CRL
- **预期行为**：CA 签名验证失败
- **测试结果**：

#### TC-CR-12：PKCS#11 HSM 密钥导出

- **目标**：尝试从未配置 CKA_EXTRACTABLE 的密钥导出
- **方法**：通过 PKCS#11 接口调用 `C_GetAttributeValue` 读取私钥
- **预期行为**：CKR_ATTRIBUTE_SENSITIVE 错误
- **测试结果**：

### 2.5 业务逻辑（10 用例）

#### TC-BL-01：密钥轮转绕过

- **目标**：轮转后用旧版本加密是否被允许
- **方法**：轮转后用最小版本号仍能加密
- **预期行为**：策略可配置，但默认不允许
- **测试结果**：

#### TC-BL-02：ShredKey 后数据可恢复

- **目标**：销毁后是否能解密历史密文
- **方法**：备份 wrapped_blob，ShredKey，尝试解密
- **预期行为**：不可解密（除非其他 unwrap 路径）
- **测试结果**：

#### TC-BL-03：金额限制绕过

- **N/A**：KMS 不涉及金融交易
- **测试结果**：

#### TC-BL-04：资源耗尽（API rate limit）

- **目标**：1000 并发请求
- **方法**：loadrunner / ab 工具
- **预期行为**：触发限流 429
- **配置**：`v1.4.0` 引入限流
- **测试结果**：

#### TC-BL-05：时间相关攻击

- **目标**：TOTP 30 秒窗口
- **方法**：尝试在窗口边界外提交
- **预期行为**：TOTP 严格
- **测试结果**：

#### TC-BL-06：状态机绕过

- **目标**：Emergency Seal 触发后能否读取数据
- **方法**：seal 后尝试 decrypt
- **预期行为**：seal 后所有密钥操作禁止
- **测试结果**：

#### TC-BL-07：审计 ID 冲突

- **目标**：构造相同的 chain_seq
- **方法**：并发写入 1000 条审计
- **预期行为**：串行化，无重复
- **测试结果**：

#### TC-BL-08：备份恢复后密钥一致性

- **目标**：恢复后用历史 wrapped_blob 能解包吗
- **方法**：备份 → restore → 尝试解包
- **预期行为**：成功（恢复无损）
- **测试结果**：

#### TC-BL-09：管理员误操作（撤销自己的 token）

- **目标**：admin 撤销自己权限后能否恢复
- **方法**：撤销 + 看看是否能用新 token
- **预期行为**：unseal key 可重新初始化
- **测试结果**：

#### TC-BL-10：时钟偏移对 TOTP 的影响

- **目标**：服务器时钟 ±90s 偏移下 TOTP 是否仍有效
- **测试结果**：

### 2.6 错误处理与日志（8 用例）

#### TC-ER-01：错误信息泄露栈跟踪

- **目标**：故意触发 panic
- **方法**：构造非法输入
- **预期行为**：返回通用 500 + trace_id，不含栈
- **测试结果**：

#### TC-ER-02：错误信息泄露密钥

- **目标**：错误的错误处理
- **方法**：构造可触发异常的请求，看错误 message
- **预期行为**：所有错误输出已经 redact
- **测试结果**：

#### TC-ER-03：错误信息泄露内部 IP

- **目标**：泄露 PG IP / 内部地址
- **测试结果**：

#### TC-ER-04：审计日志含敏感信息

- **目标**：审计不应该含 plaintext / key_material
- **方法**：grep audit.log
- **预期行为**：白名单字段
- **测试结果**：

#### TC-ER-05：Debug 日志在生产启用

- **目标**：生产环境 debug 模式
- **方法**：配置 `level: debug` 启动
- **预期行为**：dev 模式允许，cluster 模式默认 info
- **测试结果**：

#### TC-ER-06：审计日志可篡改

- **目标**：文件系统权限
- **方法**：尝试以非 root 写入 audit.log
- **预期行为**：拒绝或写入失败
- **测试结果**：

#### TC-ER-07：HMAC 链断裂告警

- **目标**：篡改后是否告警
- **方法**：篡改一行 audit.log，运行 audit-verify
- **预期行为**：返回码 1 + 输出断点位置
- **测试结果**：

#### TC-ER-08：审计日志保留期

- **目标**：保留期可配置
- **方法**：检查旧日志是否按 retention_days 清理
- **测试结果**：

### 2.7 配置与部署（12 用例）

#### TC-CF-01：默认凭据

- **目标**：默认 root token / 默认密码
- **方法**：尝试默认 token `root`
- **预期行为**：init 时生成 256 位 random token
- **测试结果**：

#### TC-CF-02：TLS 版本

- **目标**：是否禁用 TLS 1.0 / 1.1
- **方法**：使用 sslscan / nmap --script ssl-enum-ciphers
- **预期行为**：仅 TLS 1.2 / 1.3
- **测试结果**：

#### TC-CF-03：弱密码套件

- **目标**：是否禁用 CBC / RC4 / 3DES
- **方法**：sslscan
- **预期行为**：AEAD 优先（GCM / ChaCha20-Poly1305）
- **测试结果**：

#### TC-CF-04：HSTS 设置

- **目标**：Strict-Transport-Security header
- **方法**：curl -I
- **预期行为**：`max-age=31536000; includeSubDomains`
- **测试结果**：

#### TC-CF-05：CSP 设置

- **目标**：Content-Security-Policy
- **方法**：浏览器开发者工具
- **预期行为**：限制 inline / eval
- **测试结果**：

#### TC-CF-06：X-Frame-Options

- **目标**：clickjacking 防护
- **测试结果**：

#### TC-CF-07：X-Content-Type-Options

- **目标**：MIME 嗅探防护
- **预期行为**：`nosniff`
- **测试结果**：

#### TC-CF-08：Cookie 安全属性

- **目标**：HttpOnly + Secure + SameSite
- **测试结果**：

#### TC-CF-09：CORS 配置

- **目标**：跨域访问控制
- **方法**：Origin: https://evil.com
- **预期行为**：仅允许白名单 origin
- **测试结果**：

#### TC-CF-10：管理端点暴露

- **目标**：`/admin` 端点的可达性
- **预期行为**：仅 mTLS + 内部 IP 允许
- **测试结果**：

#### TC-CF-11：默认 deny 规则

- **目标**：新创建的 AppRole 默认最小权限
- **测试结果**：

#### TC-CF-12：环境变量泄漏

- **目标**：进程环境是否含密码
- **方法**：Linux /proc/<pid>/environ
- **预期行为**：敏感值不在环境变量
- **测试结果**：

### 2.8 客户端与 API（10 用例）

#### TC-API-01：HTTP 状态码合规

- **目标**：所有端点返回正确状态码
- **测试结果**：

#### TC-API-02：API 版本控制

- **目标**：`/v1` vs `/v2` 路径隔离
- **测试结果**：

#### TC-API-03：错误响应格式一致性

- **目标**：所有错误使用统一 envelope
- **测试结果**：

#### TC-API-04：OpenAPI 规范一致性

- **工具**：Stoplight / Spectral
- **测试结果**：

#### TC-API-05：CORS 预检 (Preflight)

- **目标**：OPTIONS 请求
- **测试结果**：

#### TC-API-06：HTTP/2 支持

- **目标**：alpn h2
- **测试结果**：

#### TC-API-07：流式响应

- **目标**：长轮询或 SSE
- **测试结果**：

#### TC-API-08：压缩支持（gzip / brotli）

- **测试结果**：

#### TC-API-09：API 限流

- **目标**：X-RateLimit-* headers
- **测试结果**：

#### TC-API-10：API 文档一致性

- **目标**：实现 vs 文档
- **测试结果**：

---

## 3. 漏洞清单（执行时填充）

| ID | 名称 | 类别 | CVSS | 风险等级 | 状态 |
|---|---|---|---|---|---|
| VULN-001 | （待发现） | | | | |

### 3.1 漏洞 VULN-XXX 详情

（每个发现的漏洞记录如下）

#### 概述

- **标题**：
- **CVSS v3.1 评分**：`base 9.0, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **风险等级**：严重
- **影响范围**：所有 cluster 模式部署
- **首次发现**：YYYY-MM-DD
- **披露时间表**：
  - YYYY-MM-DD：发现
  - YYYY-MM-DD：内部通知
  - YYYY-MM-DD：厂商修复
  - YYYY-MM-DD：公开披露

#### 技术描述

详细描述漏洞的实现原理，包括请求/响应样例。

#### 复现步骤

```bash
# 步骤 1
curl -X POST https://yvonne.example.com:8200/v1/auth/approle/login \
  -d '{"role_id":"e2e-role","secret_id":"..."}' \
  -H "Content-Type: application/json"

# 步骤 2：构造恶意 token...

# 步骤 3：提交恶意 token...
```

#### 截图

（执行测试时附图）

#### 修复建议

代码层面的修复建议，包含 file:line 引用。

#### 厂商响应

（厂商在收到报告后的反馈）

---

## 4. 改进建议（执行时填充）

按优先级列出，便于跟踪：

| 优先级 | 建议项 | 影响面 | 推荐路径 |
|---|---|---|---|
| P0 | 立即修复 Critical | | |
| P1 | 30 天内修复 High | | |
| P2 | 90 天内改进 Medium | | |
| P3 | 未来版本改进 Low | | |

---

## 5. 工具配置

### 5.1 Nmap

```bash
nmap -p- -sV --script=ssl-enum-ciphers,http-enum yvonne.example.com
```

### 5.2 Burp Suite Pro

- Scope：cluster.example.com:8200-8250
- Plugins：Autorize, Logger++, JSON Beautifier

### 5.3 testssl.sh

```bash
./testssl.sh --vulnerable --severity high yvonne.example.com:8200
```

### 5.4 OWASP ZAP

- Spider + Active Scan 启用
- 配置：xpowered-by, content-type-options header 检测

### 5.5 自研审计链验证脚本

```bash
./bin/yvonne audit-verify --dir /var/log/yvonne/
```

---

## 6. 测试人员资质

| 测试员 | 资质证书 | 证书号 | 有效期 |
|---|---|---|---|
| | | | |

---

## 7. 客户确认

| 角色 | 签字 | 日期 |
|---|---|---|
| 渗透测试负责人 | | |
| 安全复核 | | |
| Yvonne 技术负责人 | | |

---

## 附录 A：测试环境配置

```json
{
  "target_version": "v1.4.0",
  "deployment_mode": "cluster",
  "test_account": "pentest-reader",
  "test_account_role": "audit-read-only",
  "test_window_hours": 16
}
```

## 附录 B：通信密钥协商记录

（测试开始前的密钥交换 + 测试结束后的清除）

## 附录 C：完整请求日志

（测试期间所有原始 HTTP 请求，作为证据）

## 附录 D：测试数据合法性声明

测试全程使用合法测试账号，未尝试破解主密钥以外的任何数据。所有测试数据为随机生成，未使用真实客户数据。

---

**模板结束**

使用说明：
1. 复制本模板到具体测试项目目录
2. 替换所有占位符为实际值
3. 详细记录每个 TC 的执行步骤
4. 保留所有工具的原始输出
5. 测试完成后 7 个工作日内输出完整报告
