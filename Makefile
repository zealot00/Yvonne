# Yvonne KMS - Makefile

GO        := go
GOFLAGS   := -trimpath -buildvcs=false
BINARY    := bin/yvonne
PKG       := ./...

.PHONY: all build run test test-integration vet fmt clean tidy coverage security-check ci proto

all: tidy build

proto:
	@export PATH=$$PATH:$$(go env GOPATH)/bin; \
	protoc \
	  --proto_path=proto \
	  --go_out=gen/proto --go_opt=paths=source_relative \
	  --go-grpc_out=gen/proto --go-grpc_opt=paths=source_relative \
	  proto/yvonne/v1/yvonne.proto

build:
	$(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/yvonne

run:
	$(GO) run ./cmd/yvonne

test:
	$(GO) test -race -count=1 $(PKG)

test-integration:
	$(GO) test -race -count=1 -tags=integration -timeout 120s ./internal/api/ ./internal/storage/

vet:
	$(GO) vet $(PKG)

fmt:
	gofmt -s -w .

fmt-check:
	@if [ -n "$$(gofmt -l .)" ]; then echo "unformatted files:"; gofmt -l .; exit 1; fi

tidy:
	$(GO) mod tidy

# 11 项安全红线自检。
security-check:
	bash scripts/security-check.sh

# 生成覆盖率报告（合并单元测试 + 集成测试）。
coverage:
	@echo "Running unit tests with coverage..."
	$(GO) test -race -count=1 -coverprofile=/tmp/cover_core.out ./internal/memguard/ ./internal/crypto/ ./internal/lifecycle/ ./internal/seal/ ./internal/audit/ ./internal/metrics/
	@echo "Running integration tests with coverage..."
	$(GO) test -race -count=1 -tags=integration -coverprofile=/tmp/cover_api.out ./internal/api/
	@echo "Merging coverage profiles..."
	@echo "mode: set" > /tmp/cover_merged.out
	@grep -v "^mode:" /tmp/cover_core.out >> /tmp/cover_merged.out
	@grep -v "^mode:" /tmp/cover_api.out >> /tmp/cover_merged.out
	$(GO) tool cover -html=/tmp/cover_merged.out -o coverage.html
	@echo ""
	@echo "=== Coverage Summary ==="
	@$(GO) tool cover -func=/tmp/cover_merged.out | tail -1
	@echo ""
	@echo "HTML report: coverage.html"

# 本地模拟 CI 完整流水线。
ci: vet fmt-check security-check test
	@echo ""
	@echo "=== CI Pipeline PASSED ==="

clean:
	rm -rf bin/ dist/ coverage.txt coverage.html
