# Yvonne KMS systemd 部署指南

## 安装

```bash
# 1. 下载二进制
curl -L -o /usr/local/bin/yvonne https://github.com/zealot00/Yvonne/releases/latest/download/yvonne-linux-amd64
chmod +x /usr/local/bin/yvonne

# 2. 创建用户和目录
useradd -r -s /sbin/nologin yvonne
mkdir -p /etc/yvonne /var/lib/yvonne /var/log/yvonne
chown yvonne:yvonne /var/lib/yvonne /var/log/yvonne

# 3. 创建配置文件
cat > /etc/yvonne/config.json << 'EOF'
{
  "mode": "cluster",
  "server": {
    "bind_addr": "127.0.0.1",
    "bind_port": 8400,
    "tls": { "enabled": false }
  },
  "storage": { "type": "postgres" },
  "unseal": { "type": "shamir", "total_shares": 5, "threshold": 3 },
  "logging": { "redact_secrets": true, "level": "info" }
}
EOF
chmod 600 /etc/yvonne/config.json

# 4. 安装 systemd 服务
cp deploy/systemd/yvonne.service /etc/systemd/system/
systemctl daemon-reload

# 5. 设置环境变量（DSN 不写入配置文件）
# 编辑 /etc/systemd/system/yvonne.service 修改 Environment 行
# 或创建 override：
systemctl edit yvonne
# 在编辑器中添加：
# [Service]
# Environment="YVONNE_STORAGE_DSN=postgresql://..."
# Environment="YVONNE_SERVER_ADMIN_ADMIN_TOKEN=your-token"

# 6. 启动
systemctl enable yvonne
systemctl start yvonne

# 7. 查看状态
systemctl status yvonne
journalctl -u yvonne -f
```

## 管理

```bash
# 启动/停止/重启
systemctl start yvonne
systemctl stop yvonne
systemctl restart yvonne

# 查看日志
journalctl -u yvonne --since "1 hour ago"

# 健康检查
curl http://127.0.0.1:8400/api/v1/sys/health

# Unseal（需 Shamir 分片）
curl -X POST http://127.0.0.1:8400/api/v1/sys/unseal \
  -d '{"shares":["<share1>"]}'
```

## 安全加固

- `UMask=0077`：文件权限仅 owner 可读
- `ProtectSystem=strict`：文件系统只读（除指定路径）
- `PrivateTmp=true`：独立 /tmp
- `NoNewPrivileges=true`：禁止提权
- DSN 通过环境变量注入，不落盘
