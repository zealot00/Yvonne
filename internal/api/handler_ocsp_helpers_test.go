// OCSP handler 测试共享 helper。
package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

// rsaGenKeyTest 生成 2048 位 RSA 密钥（测试用）。
func rsaGenKeyTest() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// encodeRSAPubPEMTest 把 RSA 公钥序列化为 PEM。
func encodeRSAPubPEMTest(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// base64URLEncode 把 bytes 编码为 URL-safe base64（带 padding，RFC 6960 兼容）。
func base64URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// jsonMarshal 是 encoding/json.Marshal 的薄包装。
func jsonMarshal(v interface{}) ([]byte, error) { return json.Marshal(v) }

// jsonUnmarshal 是 encoding/json.Unmarshal 的薄包装。
func jsonUnmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }
