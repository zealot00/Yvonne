// Package memguard 提供 Yvonne 最底层的安全内存基础设施：CSPRNG 熵源与
// 敏感数据容器 SecureBuffer。
//
// 本包是整个 KMS 的信任根，不得依赖项目内任何其他包。
package memguard

import (
	"crypto/rand"
	"fmt"
	"runtime"
)

// GenerateSecureRandom 从操作系统底层 CSPRNG（crypto/rand）读取 size 字节。
//
// 红线：
//   - 绝对禁止使用 math/rand；本函数是全项目唯一的随机数入口。
//   - crypto/rand.Read 失败时绝不降级、绝不静默忽略，直接返回 error。
//     调用方必须将其视为致命错误（在系统启动/封印流程中应直接 panic 或拒绝 Unseal）。
//   - 失败路径上也要清空已分配的缓冲，避免半填充的"随机数"被误用。
func GenerateSecureRandom(size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("memguard: invalid negative size %d", size)
	}
	buf := make([]byte, size)
	if size == 0 {
		return buf, nil
	}
	if _, err := rand.Read(buf); err != nil {
		// 熵源不可用是致命的：清空已分配缓冲，绝不返回半填充数据。
		clear(buf)
		runtime.KeepAlive(buf) // 防 DCE：确保 clear 不被编译器优化掉
		return nil, fmt.Errorf("memguard: crypto/rand.Read failed (CSPRNG unavailable): %w", err)
	}
	return buf, nil
}
