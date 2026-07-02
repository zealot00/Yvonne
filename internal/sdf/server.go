// Package sdf — SDF HTTP 服务（把 Device 暴露为 HTTP API）。
//
// 端点：
//
//	POST /api/v1/sdf/device/info     — 设备信息
//	POST /api/v1/sdf/random          — 生成随机数
//	POST /api/v1/sdf/sm2/generate    — 生成 SM2 密钥对
//	POST /api/v1/sdf/sm2/sign        — SM2 签名
//	POST /api/v1/sdf/sm2/verify      — SM2 验签
//	POST /api/v1/sdf/sm2/encrypt     — SM2 加密
//	POST /api/v1/sdf/sm2/decrypt     — SM2 解密
//	POST /api/v1/sdf/sm3/hash        — SM3 哈希
//	POST /api/v1/sdf/sm4/encrypt     — SM4 加密
//	POST /api/v1/sdf/sm4/decrypt     — SM4 解密
//
// 认证：Bearer Token（独立 SDF token，ConstantTimeCompare）。
// 二进制数据（密钥/密文/签名）用 hex 编码传输。
package sdf

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
)

// Server 是 SDF HTTP 服务。
type Server struct {
	device Device
	token  string
}

// NewServer 创建 SDF HTTP 服务。
// token 为 SDF 专用认证 token（空=拒绝所有请求）。
func NewServer(dev Device, token string) *Server {
	return &Server{device: dev, token: token}
}

// auth 校验 Bearer Token。
func (s *Server) auth(req *http.Request) bool {
	if s.token == "" {
		return false
	}
	auth := req.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(s.token)) == 1
}

// ServeHTTP 实现 http.Handler。
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !s.auth(req) {
		writeSDFError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	switch req.URL.Path {
	case "/api/v1/sdf/device/info":
		s.handleDeviceInfo(w, req)
	case "/api/v1/sdf/random":
		s.handleRandom(w, req)
	case "/api/v1/sdf/sm2/generate":
		s.handleSM2Generate(w, req)
	case "/api/v1/sdf/sm2/sign":
		s.handleSM2Sign(w, req)
	case "/api/v1/sdf/sm2/verify":
		s.handleSM2Verify(w, req)
	case "/api/v1/sdf/sm2/encrypt":
		s.handleSM2Encrypt(w, req)
	case "/api/v1/sdf/sm2/decrypt":
		s.handleSM2Decrypt(w, req)
	case "/api/v1/sdf/sm3/hash":
		s.handleSM3Hash(w, req)
	case "/api/v1/sdf/sm4/encrypt":
		s.handleSM4Encrypt(w, req)
	case "/api/v1/sdf/sm4/decrypt":
		s.handleSM4Decrypt(w, req)
	default:
		writeSDFError(w, http.StatusNotFound, "unknown SDF endpoint: "+req.URL.Path)
	}
}

// --- Handlers ---

func (s *Server) handleDeviceInfo(w http.ResponseWriter, req *http.Request) {
	info, err := s.device.DeviceInfo()
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, info)
}

func (s *Server) handleRandom(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Length int `json:"length"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Length <= 0 || body.Length > 65536 {
		writeSDFError(w, http.StatusBadRequest, "length must be 1-65536")
		return
	}
	buf, err := s.device.GenerateRandom(body.Length)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"random": hex.EncodeToString(buf)})
}

func (s *Server) handleSM2Generate(w http.ResponseWriter, req *http.Request) {
	pub, priv, err := s.device.GenerateSM2KeyPair()
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{
		"public_key":  string(pub),
		"private_key": string(priv),
	})
}

func (s *Server) handleSM2Sign(w http.ResponseWriter, req *http.Request) {
	var body struct {
		PrivateKey string `json:"private_key"`
		Data       string `json:"data"` // hex 编码
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	data, err := hex.DecodeString(body.Data)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "data must be hex encoded")
		return
	}
	sig, err := s.device.SM2Sign([]byte(body.PrivateKey), data)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"signature": hex.EncodeToString(sig)})
}

func (s *Server) handleSM2Verify(w http.ResponseWriter, req *http.Request) {
	var body struct {
		PublicKey string `json:"public_key"`
		Data      string `json:"data"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	data, err := hex.DecodeString(body.Data)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "data must be hex")
		return
	}
	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "signature must be hex")
		return
	}
	valid, err := s.device.SM2Verify([]byte(body.PublicKey), data, sig)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]bool{"valid": valid})
}

func (s *Server) handleSM2Encrypt(w http.ResponseWriter, req *http.Request) {
	var body struct {
		PublicKey string `json:"public_key"`
		Data      string `json:"data"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	data, err := hex.DecodeString(body.Data)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "data must be hex")
		return
	}
	ct, err := s.device.SM2Encrypt([]byte(body.PublicKey), data)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"ciphertext": hex.EncodeToString(ct)})
}

func (s *Server) handleSM2Decrypt(w http.ResponseWriter, req *http.Request) {
	var body struct {
		PrivateKey string `json:"private_key"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	ct, err := hex.DecodeString(body.Ciphertext)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "ciphertext must be hex")
		return
	}
	pt, err := s.device.SM2Decrypt([]byte(body.PrivateKey), ct)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"plaintext": hex.EncodeToString(pt)})
}

func (s *Server) handleSM3Hash(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	data, err := hex.DecodeString(body.Data)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "data must be hex")
		return
	}
	hash, err := s.device.SM3Hash(data)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"hash": hex.EncodeToString(hash)})
}

func (s *Server) handleSM4Encrypt(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Key  string `json:"key"`
		Data string `json:"data"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	key, err := hex.DecodeString(body.Key)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "key must be hex")
		return
	}
	data, err := hex.DecodeString(body.Data)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "data must be hex")
		return
	}
	ct, err := s.device.SM4Encrypt(key, data)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"ciphertext": hex.EncodeToString(ct)})
}

func (s *Server) handleSM4Decrypt(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Key        string `json:"key"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeSDFError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	key, err := hex.DecodeString(body.Key)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "key must be hex")
		return
	}
	ct, err := hex.DecodeString(body.Ciphertext)
	if err != nil {
		writeSDFError(w, http.StatusBadRequest, "ciphertext must be hex")
		return
	}
	pt, err := s.device.SM4Decrypt(key, ct)
	if err != nil {
		writeSDFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeSDFOK(w, map[string]string{"plaintext": hex.EncodeToString(pt)})
}

// --- JSON helpers ---

func writeSDFJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeSDFError(w http.ResponseWriter, status int, msg string) {
	writeSDFJSON(w, status, map[string]interface{}{"ok": false, "error": msg})
}

func writeSDFOK(w http.ResponseWriter, data interface{}) {
	writeSDFJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": data})
}

// ErrSDFNotConfigured 表示 SDF 未配置。
var ErrSDFNotConfigured = errors.New("sdf: not configured")
