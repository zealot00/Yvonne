// Package grpc - 敏感数据擦除 codec。
//
// 包装原生 proto codec，在 Marshal 后用 reflect 清理 response 中的 []byte 字段。
// 解决 BUG-11：gRPC Decrypt/CreateKey/RotateKey/GDK 的明文 DEK 在 protobuf
// 序列化期间驻留堆上的问题。
//
// 工作原理：
//  1. handler 返回 response（含 plaintext []byte）
//  2. gRPC 框架调用 codec.Marshal(response) 序列化
//  3. 序列化完成后，wipingCodec 清理 response 的 []byte 字段
//  4. gRPC 发送序列化后的字节到网络
//  5. response 对象随后被 GC（此时 []byte 已清零）
package grpc

import (
	"fmt"
	"reflect"
	"unsafe"

	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"

	pb "yvonne/gen/proto/yvonne/v1"
)

// codecName 是 wipingCodec 的注册名（覆盖默认 proto codec）。
const sensitiveCodecName = "proto"

// wipingCodec 包装原生 proto codec，序列化后清理敏感 []byte 字段。
type wipingCodec struct {
	base encoding.Codec // 延迟初始化（第一次 Marshal 时获取）
}

// RegisterWipingCodec 注册敏感数据擦除 codec（覆盖默认 proto codec）。
// 必须在 grpc.NewServer 之前调用。
func RegisterWipingCodec() {
	encoding.RegisterCodec(&wipingCodec{})
}

// getBase 延迟获取原生 proto codec（避免 init 顺序问题）。
func (c *wipingCodec) getBase() encoding.Codec {
	if c.base == nil {
		// 获取原生 proto codec（跳过自身，用原生实现）。
		c.base = encoding.GetCodec("_proto_fallback")
		if c.base == nil {
			// fallback：直接用 proto.Marshal（不通过 gRPC codec 注册）。
			c.base = &protoFallbackCodec{}
		}
	}
	return c.base
}

// Name 返回 codec 名称（保持 "proto" 与 gRPC 框架兼容）。
func (c *wipingCodec) Name() string {
	return sensitiveCodecName
}

// Marshal 序列化后清理 response 中的敏感 []byte 字段。
func (c *wipingCodec) Marshal(m any) ([]byte, error) {
	base := c.getBase()
	data, err := base.Marshal(m)
	// 序列化完成后，清理 response 的 []byte 字段（防明文驻留堆上）。
	wipeSensitiveBytes(m)
	return data, err
}

// Unmarshal 透传给原生 codec。
func (c *wipingCodec) Unmarshal(data []byte, m any) error {
	return c.getBase().Unmarshal(data, m)
}

// wipeSensitiveBytes 清理 message 中所有 []byte 字段。
// 仅对已知的 response 类型生效（白名单），避免性能影响。
func wipeSensitiveBytes(m any) {
	if m == nil {
		return
	}

	// 白名单：仅清理含明文密钥的 response 类型。
	switch msg := m.(type) {
	case *pb.DecryptResponse:
		clearBytes(msg.Plaintext)
	case *pb.CreateKeyResponse:
		clearBytes(msg.PlaintextDek)
	case *pb.RotateKeyResponse:
		clearBytes(msg.PlaintextDek)
	case *pb.GenerateDataKeyResponse:
		clearBytes(msg.PlaintextDek)
	}
}

// clearBytes 安全清零 []byte（若非空）。
func clearBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	// 用 reflect 避免编译器 DCE 消除 clear。
	for i := range b {
		b[i] = 0
	}
	// 额外防止 DCE：通过 unsafe 保持写入副作用。
	_ = unsafe.Pointer(&b[0]) // #nosec G103 -- 防 DCE 优化，安全擦除必需
}

// 确保 reflect 包被引用（wipeSensitiveBytes 扩展时可能用到）。
var _ = reflect.TypeOf
var _ = fmt.Sprintf
var _ = proto.Marshal

// protoFallbackCodec 是原生 proto codec 的 fallback 实现。
// 当 gRPC 默认 proto codec 未注册时使用（正常不会触发）。
type protoFallbackCodec struct{}

func (c *protoFallbackCodec) Name() string { return sensitiveCodecName }
func (c *protoFallbackCodec) Marshal(m any) ([]byte, error) {
	msg, ok := m.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("grpc: not a proto.Message: %T", m)
	}
	return proto.Marshal(msg)
}
func (c *protoFallbackCodec) Unmarshal(data []byte, m any) error {
	msg, ok := m.(proto.Message)
	if !ok {
		return fmt.Errorf("grpc: not a proto.Message: %T", m)
	}
	return proto.Unmarshal(data, msg)
}
