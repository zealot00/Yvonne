#!/usr/bin/env python3
"""
Yvonne KMS Python SDK

轻量级 HTTP 客户端，封装 Yvonne KMS REST API。

安装：pip install requests
用法：
    from yvonne import YvonneClient
    client = YvonneClient("http://127.0.0.1:8400", "your-token")
    resp = client.encrypt("order-key", b"hello")
    print(resp["version"])
"""

import base64
import json
import requests
from typing import Optional, Dict, Any, List


class YvonneError(Exception):
    """Yvonne KMS 错误。"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Yvonne KMS error ({status_code}): {message}")


class YvonneClient:
    """Yvonne KMS 客户端。"""

    def __init__(
        self,
        base_url: str,
        token: str = "",
        timeout: float = 30.0,
        max_retries: int = 0,
        retry_backoff: float = 0.1,
        circuit_breaker_threshold: int = 0,
        circuit_breaker_reset: float = 60.0,
        trace_id_header: str = "",
    ):
        """
        Args:
            base_url: KMS 地址，如 http://127.0.0.1:8400
            token: Bearer Token（AppRole 或 JWT）。Dev 模式可留空。
            timeout: 请求超时（秒）。
            max_retries: 最大重试次数（0=不重试）。
            retry_backoff: 初始退避时间（秒，指数退避）。
            circuit_breaker_threshold: 熔断阈值（连续失败次数，0=不熔断）。
            circuit_breaker_reset: 熔断后恢复时间（秒）。
            trace_id_header: trace_id 透传的 header 名（如 X-Request-ID）。
        """
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.trace_id_header = trace_id_header

        # 熔断器状态。
        self._cb_threshold = circuit_breaker_threshold
        self._cb_reset = circuit_breaker_reset
        self._cb_failures = 0
        self._cb_opened_at = 0.0

        # 可重试的 HTTP 状态码。
        self._retryable_status = {502, 503, 504}

        self._session = requests.Session()
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Content-Type"] = "application/json"

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}{path}"

        # 生成/透传 trace_id。
        headers = {}
        if self.trace_id_header:
            import uuid
            headers[self.trace_id_header] = uuid.uuid4().hex

        # 熔断检查。
        if self._cb_threshold > 0 and self._cb_failures >= self._cb_threshold:
            import time as _time
            if _time.time() - self._cb_opened_at < self._cb_reset:
                raise YvonneError(503, "circuit breaker is open")
            # 半开状态：重置失败计数，允许尝试。
            self._cb_failures = 0

        # 重试循环。
        import time as _time
        last_err = None
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                backoff = self.retry_backoff * (2 ** (attempt - 1))
                _time.sleep(min(backoff, 5.0))

            try:
                resp = self._session.request(method, url, json=body, timeout=self.timeout, headers=headers)

                if resp.status_code >= 400:
                    try:
                        err = resp.json().get("error", resp.text)
                    except Exception:
                        err = resp.text

                    # 可重试的状态码。
                    if resp.status_code in self._retryable_status and attempt < self.max_retries:
                        last_err = YvonneError(resp.status_code, err)
                        # 记录熔断失败。
                        if self._cb_threshold > 0:
                            self._cb_failures += 1
                            if self._cb_failures >= self._cb_threshold:
                                self._cb_opened_at = _time.time()
                        continue
                    raise YvonneError(resp.status_code, err)

                # 成功：重置熔断器。
                if self._cb_threshold > 0:
                    self._cb_failures = 0
                return resp.json()

            except requests.ConnectionError as e:
                if attempt < self.max_retries:
                    last_err = YvonneError(0, str(e))
                    if self._cb_threshold > 0:
                        self._cb_failures += 1
                        if self._cb_failures >= self._cb_threshold:
                            self._cb_opened_at = _time.time()
                    continue
                raise YvonneError(0, str(e))

        raise last_err or YvonneError(500, "max retries exceeded")

    # === 系统 ===

    def health(self) -> Dict:
        """健康检查（无需认证）。"""
        return self._request("GET", "/api/v1/sys/health")

    # === 密钥管理 ===

    def create_key(self, key_id: str, return_dek: bool = True) -> Dict:
        """创建密钥。"""
        body = {"key_id": key_id, "return_dek": return_dek}
        return self._request("POST", "/api/v1/keys", body)

    def rotate_key(self, key_id: str) -> Dict:
        """轮转密钥。"""
        return self._request("POST", f"/api/v1/keys/{key_id}/rotate")

    def shred_key(self, key_id: str, version: int) -> Dict:
        """物理粉碎密钥版本。"""
        return self._request("DELETE", f"/api/v1/keys/{key_id}/shred", {"version": version})

    def soft_delete_key(self, key_id: str, version: int) -> Dict:
        """软删除密钥版本。"""
        return self._request("PATCH", f"/api/v1/keys/{key_id}/soft-delete", {"version": version})

    def restore_key(self, key_id: str, version: int) -> Dict:
        """恢复软删除的密钥版本。"""
        return self._request("POST", f"/api/v1/keys/{key_id}/restore", {"version": version})

    def generate_data_key(self, key_id: str) -> Dict:
        """生成数据密钥（GDK）。"""
        return self._request("POST", f"/api/v1/keys/{key_id}/generate-data-key")

    # === 加解密 ===

    def encrypt(self, key_id: str, plaintext: bytes) -> Dict:
        """
        加密数据。

        Returns: {"ciphertext": "base64...", "version": 1}
        """
        body = {
            "key_id": key_id,
            "plaintext": base64.b64encode(plaintext).decode(),
        }
        return self._request("POST", "/api/v1/encrypt", body)

    def decrypt(self, key_id: str, ciphertext_b64: str) -> Dict:
        """
        解密数据。

        Args:
            ciphertext_b64: base64 编码的密文（从 encrypt 返回）。

        Returns: {"plaintext": "base64...", "version": 1}
        """
        body = {
            "key_id": key_id,
            "ciphertext": ciphertext_b64,
        }
        return self._request("POST", "/api/v1/decrypt", body)

    def decrypt_bytes(self, key_id: str, ciphertext_b64: str) -> bytes:
        """解密并直接返回明文 bytes。"""
        resp = self.decrypt(key_id, ciphertext_b64)
        return base64.b64decode(resp["data"]["plaintext"])

    # === 审计 ===

    def audit_query(self, limit: int = 100, **filters) -> Dict:
        """查询审计日志。"""
        body = {"limit": limit, **filters}
        return self._request("POST", "/api/v1/audit/query", body)

    # === BYOK ===

    def transit_pub(self) -> Dict:
        """获取 BYOK 传输公钥。"""
        return self._request("GET", "/api/v1/keys/transit-pub")

    def import_key(self, key_id: str, transit_key_id: str, wrapped_material_b64: str) -> Dict:
        """导入外部密钥（BYOK）。"""
        body = {
            "key_id": key_id,
            "transit_key_id": transit_key_id,
            "wrapped_material": wrapped_material_b64,
        }
        return self._request("POST", "/api/v1/keys/import", body)

    # === v1.2: 签名 / 验签 / MAC ===

    def sign(self, key_id: str, data: bytes) -> Dict:
        """非对称签名。"""
        body = {"key_id": key_id, "data": base64.b64encode(data).decode()}
        return self._request("POST", "/api/v1/sign", body)

    def verify(self, key_id: str, data: bytes, signature_b64: str) -> Dict:
        """验签。"""
        body = {"key_id": key_id, "data": base64.b64encode(data).decode(), "signature": signature_b64}
        return self._request("POST", "/api/v1/verify", body)

    def generate_mac(self, key_id: str, data: bytes) -> Dict:
        """生成 HMAC。"""
        body = {"key_id": key_id, "data": base64.b64encode(data).decode()}
        return self._request("POST", "/api/v1/mac/generate", body)

    def verify_mac(self, key_id: str, data: bytes, mac_b64: str) -> Dict:
        """验证 HMAC。"""
        body = {"key_id": key_id, "data": base64.b64encode(data).decode(), "mac": mac_b64}
        return self._request("POST", "/api/v1/mac/verify", body)

    def re_encrypt(self, source_key_id: str, dest_key_id: str, ciphertext_b64: str) -> Dict:
        """KMS 内重加密。"""
        body = {"source_key_id": source_key_id, "dest_key_id": dest_key_id, "ciphertext": ciphertext_b64}
        return self._request("POST", "/api/v1/re-encrypt", body)

    def create_asymmetric_key(self, key_id: str, key_type: str = "rsa") -> Dict:
        """创建非对称密钥（rsa/ecdsa/sm2）。"""
        body = {"key_id": key_id, "key_type": key_type}
        return self._request("POST", "/api/v1/keys/asymmetric", body)

    def get_public_key(self, key_id: str) -> Dict:
        """获取非对称密钥公钥。"""
        return self._request("GET", f"/api/v1/keys/public-key?key_id={key_id}")

    def generate_data_key_without_plaintext(self, key_id: str) -> Dict:
        """生成无明文 DEK（仅返回密文）。"""
        return self._request("POST", f"/api/v1/keys/gdk-no-plaintext?key_id={key_id}")

    # === v1.3: MFA / Quorum ===

    def mfa_setup(self, role_id: str) -> Dict:
        """MFA TOTP 注册（返回 secret + QR code URI）。"""
        return self._request("POST", "/api/v1/auth/mfa/setup", {"role_id": role_id})

    def mfa_verify(self, role_id: str, code: str) -> Dict:
        """MFA TOTP 验证 + 启用。"""
        return self._request("POST", "/api/v1/auth/mfa/verify", {"role_id": role_id, "code": code})

    def mfa_disable(self, role_id: str, code: str) -> Dict:
        """禁用 MFA（需验证当前 code）。"""
        return self._request("POST", "/api/v1/auth/mfa/disable", {"role_id": role_id, "code": code})

    def create_approval(self, operation: str, key_id: str = "", required: int = 2, ttl_hours: int = 24) -> Dict:
        """创建 Quorum 审批 ticket。"""
        body = {"operation": operation, "key_id": key_id, "required": required, "ttl_hours": ttl_hours}
        return self._request("POST", "/api/v1/approvals", body)

    def get_approval(self, ticket_id: str) -> Dict:
        """查询审批 ticket。"""
        return self._request("GET", f"/api/v1/approvals?id={ticket_id}")

    def list_approvals(self) -> Dict:
        """列出 pending 审批。"""
        return self._request("GET", "/api/v1/approvals")

    def approve_ticket(self, ticket_id: str) -> Dict:
        """审批通过。"""
        return self._request("POST", "/api/v1/approvals/approve", {"ticket_id": ticket_id})

    def reject_ticket(self, ticket_id: str) -> Dict:
        """审批拒绝。"""
        return self._request("POST", "/api/v1/approvals/reject", {"ticket_id": ticket_id})
