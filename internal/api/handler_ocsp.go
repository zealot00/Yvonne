// Package api - OCSP HTTP handler（v1.4.x 新增）。
//
// 端点：
//
//	GET  /api/v1/ocsp/{base64}    标准 RFC 6960 §A.1 GET 协议
//	POST /api/v1/ocsp             标准 RFC 6960 §A.2 POST 协议（raw DER）
//
// 协议要点：
//   - 响应 Content-Type 必须是 application/ocsp-response（RFC 6960 §A.1）
//   - 错误也按 RFC 6960 字节返回（MalformedRequestErrorResponse 等）
//   - 不强制走 authAndSeal（OCSP 是公开查询协议）
//
// 安全红线：
//   - 响应不返回 PEM/私钥（仅返回 OCSP DER）
//   - 审计日志记录 OCSPQuery 事件
//   - 错误响应不能泄露内部信息
package api

import (
	"crypto/subtle"
	"io"
	"net/http"
	"runtime"
	"strings"

	stdocsp "golang.org/x/crypto/ocsp"

	"yvonne/internal/crypto"
)

// ocspContentType 是 RFC 6960 §A.1 规定的响应 Content-Type。
const ocspContentType = "application/ocsp-response"

// ocspMaxRequestBytes 限制 POST body 大小（OCSP 请求通常 < 1KB）。
const ocspMaxRequestBytes = 8 * 1024

// HandleOCSPQuery 路由 OCSP GET/POST 请求（导出供 bootstrap 装配）。
//
// 路径解析：
//   - GET  /api/v1/ocsp/{base64} → base64 解码 reqDER
//   - POST /api/v1/ocsp          → body 即 reqDER
//
// 其他方法 → 405。
func (r *V1Router) HandleOCSPQuery(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", ocspContentType)

	var reqDER []byte
	switch req.Method {
	case http.MethodGet:
		// 提取 URL 末段（去掉前缀 /api/v1/ocsp/）。
		reqPath := strings.TrimPrefix(req.URL.Path, "/api/v1/ocsp/")
		if reqPath == "" || reqPath == req.URL.Path {
			writeOCSPError(w, stdocsp.MalformedRequestErrorResponse)
			return
		}
		decoded, err := crypto.DecodeOCSPRequestBase64(reqPath)
		if err != nil {
			writeOCSPError(w, stdocsp.MalformedRequestErrorResponse)
			return
		}
		reqDER = decoded
	case http.MethodPost:
		// 读取 body（限制大小）。
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, ocspMaxRequestBytes+1))
		if err != nil {
			writeOCSPError(w, stdocsp.MalformedRequestErrorResponse)
			return
		}
		// bodyBytes 内可能含敏感（请求方构造的二进制），用完即清零。
		defer func() {
			clear(bodyBytes)
			runtime.KeepAlive(bodyBytes)
		}()
		if len(bodyBytes) > ocspMaxRequestBytes {
			writeOCSPError(w, stdocsp.MalformedRequestErrorResponse)
			return
		}
		reqDER = bodyBytes
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write(stdocsp.MalformedRequestErrorResponse)
		return
	}

	// 委托给 core.OCSP。
	respDER, err := r.core.OCSP(req.Context(), reqDER)
	if err != nil {
		// 错误路径：返回 RFC 6960 错误响应字节（不泄露内部错误细节）。
		_ = subtle.ConstantTimeCompare // 占位（实际下方不直接处理比较）
		writeOCSPError(w, stdocsp.InternalErrorErrorResponse)
		return
	}

	// 正常响应：RFC 6960 DER 字节 + Content-Type。
	w.Header().Set("Content-Type", ocspContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}

// writeOCSPError 写入 RFC 6960 错误响应字节（固定 status code + application/ocsp-response）。
//
// 即使错误也按规范返回 application/ocsp-response 内容类型，让客户端能正确解析状态码。
func writeOCSPError(w http.ResponseWriter, errorBytes []byte) {
	w.Header().Set("Content-Type", ocspContentType)
	w.WriteHeader(http.StatusOK) // RFC 6960 错误响应仍用 200 + 错误字节
	_, _ = w.Write(errorBytes)
}
