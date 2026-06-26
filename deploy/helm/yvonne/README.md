# Yvonne KMS Helm Chart

`helm install yvonne deploy/helm/yvonne` 一键部署 Yvonne KMS 到 Kubernetes。

## 快速开始

### Dev 模式（零配置）

```bash
helm install yvonne deploy/helm/yvonne \
  -f deploy/helm/yvonne/values-dev.yaml
```

### Cluster 模式（生产）

```bash
# 创建命名空间
kubectl create namespace yvonne

# 部署（含 PostgreSQL 子 chart）
helm install yvonne deploy/helm/yvonne \
  -f deploy/helm/yvonne/values-cluster.yaml \
  -n yvonne \
  --set config.server.admin.admin_token="$ADMIN_TOKEN" \
  --set config.storage.dsn="postgres://yvonne:$PG_PASS@yvonne-postgresql:5432/yvonne?sslmode=require"

# Unseal 仪式（Shamir）
kubectl exec -it yvonne-0 -n yvonne -- yvonne unseal-keygen --out /tmp/unseal.pem
# 分发分片后...
kubectl exec -it yvonne-0 -n yvonne -- curl -X POST http://localhost:8400/api/v1/sys/unseal -d '{"shares":[...]}'
```

### 自定义配置

```bash
# 覆盖副本数
helm install yvonne deploy/helm/yvonne --set replicaCount=5

# 覆盖镜像
helm install yvonne deploy/helm/yvonne \
  --set image.repository=my-registry/yvonne \
  --set image.tag=v0.4.0

# 启用 MCP
helm install yvonne deploy/helm/yvonne \
  --set config.server.mcp.enabled=true \
  --set config.server.mcp.token="$MCP_TOKEN" \
  --set config.server.mcp.allowed_keys='{ai-key}'
```

## 验证部署

```bash
# Pod 状态
kubectl get pods -l app.kubernetes.io/name=yvonne

# Service
kubectl get svc -l app.kubernetes.io/name=yvonne

# 健康检查
kubectl port-forward svc/yvonne 8400:8400
curl http://localhost:8400/api/v1/sys/health
# {"state":"unsealed","emergency_sealed":false}

# gRPC 测试
grpcurl -plaintext localhost:8251 yvonne.v1.YvonneService/Health
```

## 架构

```
┌─────────────────────────────────────────────────┐
│ Kubernetes Cluster                               │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ yvonne-0 │  │ yvonne-1 │  │ yvonne-2 │      │
│  │ HTTP/API │  │ HTTP/API │  │ HTTP/API │      │
│  │ gRPC     │  │ gRPC     │  │ gRPC     │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │              │              │            │
│       └──────────────┴──────────────┘            │
│                      │                            │
│              ┌───────┴───────┐                   │
│              │  PostgreSQL   │                   │
│              │ (选主+共享态)  │                   │
│              └───────────────┘                   │
└─────────────────────────────────────────────────┘
```

- **StatefulSet**：多副本，Pod 间无状态（状态全在 PG）
- **选主**：`pg_advisory_lock` 确保只有一个 Pod 执行轮转
- **缓存失效**：`LISTEN/NOTIFY` 跨 Pod 同步
- **探针**：`/api/v1/sys/health`（liveness + readiness）
- **优雅停机**：SIGTERM → HTTP/gRPC/MCP 顺序 Shutdown

## 配置覆盖

### 环境变量

```bash
helm install yvonne deploy/helm/yvonne \
  --set env.YVONNE_STORAGE_DSN="postgres://..."
```

### Secret 注入

```yaml
# values.yaml
envFromSecret:
  adminToken:
    name: my-existing-secret
    key: admin-token
```

### TLS

```bash
# 创建 TLS Secret
kubectl create secret tls yvonne-tls \
  --cert=server.crt --key=server.key

# 部署时挂载
helm install yvonne deploy/helm/yvonne \
  --set config.server.tls.enabled=true
```

## 升级

```bash
helm upgrade yvonne deploy/helm/yvonne \
  -f deploy/helm/yvonne/values-cluster.yaml \
  --set image.tag=0.5.0
```

> 滚动更新：StatefulSet 逐个 Pod 滚动，`terminationGracePeriodSeconds=30` 确保优雅停机。

## 卸载

```bash
helm uninstall yvonne
# PVC 需手动清理
kubectl delete pvc -l app.kubernetes.io/name=yvonne
```
