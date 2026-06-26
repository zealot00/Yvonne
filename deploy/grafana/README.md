# Yvonne KMS Grafana Dashboard

## 导入

1. 打开 Grafana → Dashboards → Import
2. 上传 `deploy/grafana/yvonne-dashboard.json`
3. 选择 Prometheus 数据源
4. 点击 Import

## Prometheus 抓取配置

```yaml
# prometheus.yml
scrape_configs:
  - job_name: "yvonne"
    static_configs:
      - targets: ["yvonne:8400"]
    metrics_path: "/metrics"
```

## Dashboard 面板

| 面板 | 指标 | 说明 |
|---|---|---|
| API Request Rate | `rate(yvonne_api_requests_total[1m])` | 按方法/路径/状态码分组的请求速率 |
| API Latency (p99/p50) | `histogram_quantile` | 请求延迟百分位 |
| Error Rate (4xx/5xx) | `rate(yvonne_api_requests_total{status=~"4..|5.."})` | 错误请求速率 |
| Vault State | `yvonne_vault_sealed` | 封印状态（0=unsealed, 1=sealed） |
| Active DEK Count | `yvonne_keys_total{state="active"}` | 活跃密钥数量 |
| Go Memory | `go_memstats_alloc_bytes` | Go 内存分配 |
| Go Goroutines | `go_goroutines` | Goroutine 数量 |

## 告警规则（建议）

```yaml
groups:
  - name: yvonne
    rules:
      - alert: YvonneVaultSealed
        expr: yvonne_vault_sealed == 1
        for: 1m
        annotations:
          summary: "Yvonne vault is sealed"

      - alert: YvonneHighErrorRate
        expr: rate(yvonne_api_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "Yvonne 5xx error rate > 0.1/s"

      - alert: YvonneHighLatency
        expr: histogram_quantile(0.99, rate(yvonne_api_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        annotations:
          summary: "Yvonne p99 latency > 1s"
```
