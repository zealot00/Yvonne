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

    def __init__(self, base_url: str, token: str = "", timeout: float = 30.0):
        """
        Args:
            base_url: KMS 地址，如 http://127.0.0.1:8400
            token: Bearer Token（AppRole 或 JWT）。Dev 模式可留空。
            timeout: 请求超时（秒）。
        """
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._session = requests.Session()
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.headers["Content-Type"] = "application/json"

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}{path}"
        resp = self._session.request(method, url, json=body, timeout=self.timeout)
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", resp.text)
            except Exception:
                err = resp.text
            raise YvonneError(resp.status_code, err)
        return resp.json()

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
