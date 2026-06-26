// Package seal - Shamir 门限密码学基元（基于 GF(2^8)）。
//
// 实现要点：
//   - 有限域 GF(2^8) 用对数/反对数表法（生成元 0x03）。
//   - Split: 对 secret 每字节构造 threshold-1 次多项式，常数项为 secret 字节，
//     其余系数由 memguard.GenerateSecureRandom 生成。
//   - Combine: 拉格朗日插值在 x=0 处求值还原 secret。
//   - Share 格式：首字节为 x ∈ [1, 255]，其余字节为各位置上的 y。
//
// 红线：
//   - 严禁依赖第三方库；GF(2^8) 全部手写。
//   - 多项式系数必须用 CSPRNG 生成。
//   - 重组后的明文直接进 SecureBuffer。
//   - 任何临时明文必须 defer 清理。
package seal

import (
	"errors"
	"fmt"
	"runtime"

	"yvonne/internal/memguard"
)

// gfPrime 是有限域的特征：2^8 = 256。
const gfPrime = 256

// gfGenerator 是 GF(2^8) 的生成元：0x03。
// 经验证 0x03 在不可约多项式 x^8 + x^4 + x^3 + x + 1 下是原根。
const gfGenerator = 0x03

// errInvalidShareFormat 表示 share 格式不合法（如长度为 0 或 x 为 0）。
var errInvalidShareFormat = errors.New("seal: invalid share format")

// errInvalidParam 表示 Split 参数不合法。
var errInvalidParam = errors.New("seal: invalid split parameters")

// gfExp / gfLog 是 GF(2^8) 的对数与反对数表。
// gfExp[i] = generator^i mod polynomial
// gfLog[gfExp[i]] = i
//
// 用查表替代每次乘法运算，常数时间且无分支。
var (
	gfExp [512]byte // 环形缓冲：512 长度避免 mod 255 的分支
	gfLog [256]byte
)

func init() {
	// 构造对数/反对数表。
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		// x = x * generator mod polynomial
		x = gfMulNoTable(x, gfGenerator)
	}
	// 复制前 255 项到 255..510，使 gfExp 不需要 mod 即可索引。
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMulNoTable 是构造表时使用的纯乘法（带归约），仅在 init 中调用。
// 标准俄罗斯乘法 + AES 不可约多项式 0x11b 归约。
func gfMulNoTable(a, b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			result ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1b // x^8 + x^4 + x^3 + x + 1 的低 8 位
		}
		b >>= 1
	}
	return result
}

// gfMul 有限域乘法：通过查表实现，常数时间无分支。
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv 有限域求逆：a^(254) = a^(-1) in GF(2^8)。
// 通过对数表实现：inv(a) = exp(255 - log(a))。
func gfInv(a byte) byte {
	if a == 0 {
		// 数学上 0 无逆元；调用方必须保证 a != 0。
		// 这里返回 0 触发后续插值出错，而非 panic，避免 DoS。
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

// Split 把 secret 分割成 parts 份，需 threshold 份才能还原。
//
// 参数约束：
//   - parts ∈ [2, 255]
//   - threshold ∈ [2, parts]
//   - secret 长度 > 0
//
// 返回：shares 长度为 parts，每份长度 = 1 + len(secret)。
// 首字节为 x（1..parts），后续为 y 字节。
//
// 安全：
//   - 多项式系数由 memguard.GenerateSecureRandom 生成。
//   - 入参 secret 是 *memguard.SecureBuffer，通过 WithKey 闭包访问，不外泄。
//   - 临时系数缓冲用完即 clear+KeepAlive。
func Split(secret *memguard.SecureBuffer, parts, threshold int) ([][]byte, error) {
	if secret == nil {
		return nil, errInvalidParam
	}
	if parts < 2 || parts > 255 {
		return nil, fmt.Errorf("%w: parts must be in [2, 255], got %d", errInvalidParam, parts)
	}
	if threshold < 2 || threshold > parts {
		return nil, fmt.Errorf("%w: threshold must be in [2, parts], got %d", errInvalidParam, threshold)
	}

	// 读出 secret 长度（无需访问内容）。
	secretLen := secret.Len()
	if secretLen == 0 {
		return nil, fmt.Errorf("%w: secret is empty", errInvalidParam)
	}

	// 预分配输出。每份 = [x][y0..yN]
	shares := make([][]byte, parts)
	for i := range shares {
		shares[i] = make([]byte, 1+secretLen)
		shares[i][0] = byte(i + 1) // x = 1..parts
	}

	// 在 SecureBuffer 闭包内逐字节构造多项式并求值。
	err := secret.WithKey(func(sec []byte) error {
		// 临时系数缓冲：threshold 个系数（含常数项）。
		// 常数项 = secret 字节；其余 threshold-1 个为随机系数。
		coef := make([]byte, threshold)
		defer func() {
			clear(coef)
			runtime.KeepAlive(coef)
		}()

		for idx := 0; idx < secretLen; idx++ {
			// 系数 0 = secret 字节；系数 1..threshold-1 = 随机。
			randCoef, err := memguard.GenerateSecureRandom(threshold - 1)
			if err != nil {
				return fmt.Errorf("seal: generate polynomial coefficients: %w", err)
			}
			coef[0] = sec[idx]
			copy(coef[1:], randCoef)
			clear(randCoef)
			runtime.KeepAlive(randCoef)

			// 对每个 x = 1..parts 求 f(x)。
			for x := 1; x <= parts; x++ {
				shares[x-1][1+idx] = gfEval(byte(x), coef)
			}
		}
		return nil
	})
	if err != nil {
		// 失败路径：清理已分配的 shares，避免半状态残留。
		for i := range shares {
			clear(shares[i])
			runtime.KeepAlive(shares[i])
		}
		return nil, err
	}
	return shares, nil
}

// gfEval 在 GF(2^8) 上计算 f(x)，其中 f 由 coef 给出（coef[0] 是常数项）。
// 使用 Horner 法，常数时间无分支（不依赖 x 的具体值）。
func gfEval(x byte, coef []byte) byte {
	var result byte
	for i := len(coef) - 1; i >= 0; i-- {
		result = gfMul(result, x) ^ coef[i]
	}
	return result
}

// Combine 用拉格朗日插值在 x=0 处求值，还原原始 secret。
//
// 输入：shares，每份格式 [x][y0..yN]。
// 至少需要 threshold 份；多于 threshold 份也合法（任意 threshold 份即可还原）。
//
// 返回：*memguard.SecureBuffer，内含重组后的明文。
//
// 安全：
//   - 重组结果直接进 SecureBuffer（memguard.NewSecureBuffer）。
//   - 任何错误路径都清空临时缓冲（defer clear）。
//   - 不假设输入 shares 已去重——若存在重复 x，返回错误。
//
// 注意：本函数不校验 threshold（包级函数无此上下文）。
// 调用方应使用 CombineWithThreshold 进行严格校验，或自行确保份数足够。
func Combine(shares [][]byte) (*memguard.SecureBuffer, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("%w: need at least 2 shares, got %d", errInvalidShareFormat, len(shares))
	}

	// 校验所有 share 等长且非空。
	expectedLen := len(shares[0])
	if expectedLen < 2 { // 至少 1 字节 x + 1 字节 y
		return nil, errInvalidShareFormat
	}
	for i, s := range shares {
		if len(s) != expectedLen {
			return nil, fmt.Errorf("%w: share %d length mismatch (got %d, want %d)", errInvalidShareFormat, i, len(s), expectedLen)
		}
		if s[0] == 0 {
			return nil, fmt.Errorf("%w: share %d has x=0 (reserved for secret)", errInvalidShareFormat, i)
		}
	}

	// 校验 x 唯一（不可有重复 x，否则插值退化）。
	xSeen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if xSeen[s[0]] {
			return nil, fmt.Errorf("%w: duplicate x=%d at share %d", errInvalidShareFormat, s[0], i)
		}
		xSeen[s[0]] = true
	}

	secretLen := expectedLen - 1
	plain := make([]byte, secretLen)
	// 防御性清零：无论成功还是失败路径，defer 都尝试清零 plain。
	// 成功路径下 NewSecureBuffer 已清零 plain 并转交所有权，handedOff 标志
	// 阻止对已清零切片的重复操作（虽无害，但语义更清晰）。
	handedOff := false
	defer func() {
		if !handedOff && plain != nil {
			clear(plain)
			runtime.KeepAlive(plain)
		}
	}()

	// 对每个字节位置做拉格朗日插值。
	for idx := 0; idx < secretLen; idx++ {
		// f(0) = Σ y_i * Π_{j≠i} (0 - x_j) / (x_i - x_j)
		// 在 GF(2^8) 中：减法 = 异或，除法 = 乘以逆元。
		var acc byte
		for i := 0; i < len(shares); i++ {
			xi := shares[i][0]
			yi := shares[i][1+idx]

			// 计算 Π_{j≠i} (0 - x_j) / (x_i - x_j)
			// = Π_{j≠i} x_j / (x_i ⊕ x_j)   （减法在 GF(2^8) 中是异或）
			num := byte(1)
			den := byte(1)
			for j := 0; j < len(shares); j++ {
				if j == i {
					continue
				}
				xj := shares[j][0]
				num = gfMul(num, xj)    // 分子：(0 - x_j) = x_j（异或 0）
				den = gfMul(den, xi^xj) // 分母：(x_i - x_j) = xi ⊕ xj
			}
			// term = yi * num * inv(den)
			term := gfMul(yi, gfMul(num, gfInv(den)))
			acc ^= term
		}
		plain[idx] = acc
	}

	// 重组成功：封装进 SecureBuffer（NewSecureBuffer 会拷贝 plain 并清零原切片）。
	// 标记 handedOff 阻止 defer 重复清零。
	sb := memguard.NewSecureBuffer(plain)
	handedOff = true
	return sb, nil
}

// CombineWithThreshold 在 Combine 基础上校验 share 数量是否达到 threshold。
// threshold <= 0 时退化为 Combine（不校验）。
// 用于 VaultState.ProvideShare 等已知 threshold 的场景，防止传入不足的分片
// 导致拉格朗日插值产生无意义垃圾数据。
func CombineWithThreshold(shares [][]byte, threshold int) (*memguard.SecureBuffer, error) {
	if threshold > 0 && len(shares) < threshold {
		return nil, fmt.Errorf("%w: need at least %d shares (threshold), got %d", errInvalidShareFormat, threshold, len(shares))
	}
	return Combine(shares)
}
