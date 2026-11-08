# syntax=docker/dockerfile:1

# ─── Stage 1: Build ───
FROM golang:1.25-alpine AS builder

WORKDIR /src

# 预下载依赖，利用 Docker 层缓存加速后续构建
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 编译静态二进制：
#   - CGO_ENABLED=0: 纯静态链接，适配 distroless
#   - -tags gmsm,timetzdata: 内置国密算法套件 (SM2/SM3/SM4) 与 IANA 时区数据库（防精简镜像缺 tzdata panic）
RUN CGO_ENABLED=0 go build \
    -tags "gmsm,timetzdata" \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/yvonne \
    ./cmd/yvonne

# 准备运行期可写目录（供 nonroot 用户挂载/写入审计日志与数据）
RUN mkdir -p /out/var/log/yvonne /out/var/run/yvonne /out/etc/yvonne

# ─── Stage 2: Runtime (Distroless Non-Root) ───
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/yvonne /yvonne
COPY --from=builder --chown=nonroot:nonroot /out/var/log/yvonne /var/log/yvonne
COPY --from=builder --chown=nonroot:nonroot /out/var/run/yvonne /var/run/yvonne
COPY --from=builder --chown=nonroot:nonroot /out/etc/yvonne /etc/yvonne

USER nonroot:nonroot

# 8200: HTTP API | 8250: Admin Web UI | 8251: gRPC | 8252: MCP HTTP
EXPOSE 8200 8250 8251 8252

ENTRYPOINT ["/yvonne"]
CMD ["dev", "--addr", "0.0.0.0"]
