#!/usr/bin/env python3
"""
Yvonne KMS Release Gate E2E Suite
=================================
每次 release 前必须运行本脚本，全绿才能打 tag。

包含三个部分：
  1. HTTP API 测试 — Encrypt/Decrypt/Sign/Verify/MAC/GDK/Rotate/SoftDelete/Restore
     (MFA/Quorum/AuditQuery 需要 authenticator + auditDir，仅 cluster 模式测试)
  2. Admin API 测试 — Dashboard/Keys/Crypto encrypt+decrypt/Audit
  3. Selenium 浏览器测试 — 完整 UX 流程（页面加载/CSS/JS/CSP/导航/加密/解密/审计/MFA）

依赖：
  - Python 3.9+
  - selenium（pip install selenium）
  - Chrome（Applications/Google Chrome.app）
  - chromedriver（Selenium Manager 自动下载）

用法：
  ./scripts/release_gate_e2e.py
  ./scripts/release_gate_e2e.py --api-port 8200 --admin-port 8250
  ./scripts/release_gate_e2e.py --no-browser   # 跳过 Selenium
  ./scripts/release_gate_e2e.py --token <bearer-token>  # 启用 MFA/Quorum 测试

前置条件：
  - yvonne dev --demo 已启动（dev 模式）
  - 或完整 cluster 模式启动（带 authenticator + auditDir）
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
import urllib.error
from typing import Any

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

DEFAULT_API_PORT = 8200
DEFAULT_ADMIN_PORT = 8250
DEFAULT_TIMEOUT = 10
SELENIUM_IMPLICIT_WAIT = 5
PAGE_LOAD_TIMEOUT = 15

# ---------------------------------------------------------------------------
# 测试结果统计
# ---------------------------------------------------------------------------

passed: list[str] = []
failed: list[tuple[str, str]] = []
skipped: list[tuple[str, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        passed.append(name)
        print(f"  ✅ {name}")
    else:
        failed.append((name, detail))
        print(f"  ❌ {name} — {detail}")


def skip(name: str, reason: str) -> None:
    skipped.append((name, reason))
    print(f"  ⏭️  {name} (SKIP: {reason})")


# ---------------------------------------------------------------------------
# HTTP 工具
# ---------------------------------------------------------------------------

def http_request(method: str, url: str, body: Any = None, token: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": str(e)}


def http_request_raw(method: str, url: str, body: bytes | None, content_type: str,
                     token: str | None = None) -> tuple[int, bytes, dict]:
    """发送二进制请求（OCSP raw DER / 其他 application/*）。返回 (status, body_bytes, headers_dict)。"""
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), dict(e.headers)
        except Exception:
            return e.code, b"", {}


def b64(s: str) -> str:
    """字符串 → base64 编码字符串（用于 JSON 请求体中的 []byte 字段）。"""
    return base64.b64encode(s.encode()).decode()


# ---------------------------------------------------------------------------
# OCSP 测试辅助（v1.4.x）
# ---------------------------------------------------------------------------

def _openssl_or_pycrypto_imports():
    """尽量导入 cryptography 库（OCSP 请求构造需要 ASN.1 编码）。失败则抛错。"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        return {
            "x509": x509, "NameOID": NameOID,
            "hashes": hashes, "serialization": serialization,
            "rsa": rsa, "default_backend": default_backend,
        }
    except ImportError as e:
        raise RuntimeError(
            "OCSP E2E requires 'cryptography' package: pip install cryptography"
        ) from e


def generate_test_rsa_priv_pem() -> str:
    """生成测试用 RSA-2048 私钥 PEM（PKCS#8）。"""
    c = _openssl_or_pycrypto_imports()
    priv = c["rsa"].generate_private_key(
        public_exponent=65537, key_size=2048, backend=c["default_backend"]())
    return priv.private_bytes(
        encoding=c["serialization"].Encoding.PEM,
        format=c["serialization"].PrivateFormat.PKCS8,
        encryption_algorithm=c["serialization"].NoEncryption(),
    ).decode()


def derive_pub_pem_from_priv_pem(priv_pem: str) -> str:
    """从 PKCS#8 私钥 PEM 推导对应公钥 PEM。"""
    c = _openssl_or_pycrypto_imports()
    priv = c["serialization"].load_pem_private_key(priv_pem.encode(), password=None,
                                                   backend=c["default_backend"]())
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=c["serialization"].Encoding.PEM,
        format=c["serialization"].PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def build_ocsp_request_der(ca_pem_b64_or_pem: str, serial_decimal: str) -> bytes:
    """构造 OCSP Request DER（RFC 6960 §4.1.1）。

    参数:
      ca_pem_b64_or_pem: CA 证书 PEM 文本（CreateCA 返回的 data.pem 已是 PEM 文本字符串，
                         不需要再 base64 解码）
      serial_decimal:    待查询证书序列号（十进制字符串）
    """
    c = _openssl_or_pycrypto_imports()
    import hashlib
    import struct

    # 1. 解析 CA 证书 → 提取 RawSubject (DER-encoded issuer DN) + RawSubjectPublicKeyInfo
    ca_cert = c["x509"].load_pem_x509_certificate(ca_pem_b64_or_pem.encode(),
                                                  backend=c["default_backend"]())
    issuer_name_der = ca_cert.subject.public_bytes(c["serialization"].Encoding.DER)
    issuer_key_der = ca_cert.public_key().public_bytes(
        encoding=c["serialization"].Encoding.DER,
        format=c["serialization"].PublicFormat.SubjectPublicKeyInfo,
    )
    issuer_name_hash = hashlib.sha1(issuer_name_der).digest()
    issuer_key_hash = hashlib.sha1(issuer_key_der).digest()

    # 2. serial → ASN.1 INTEGER DER
    serial_int = int(serial_decimal)
    if serial_int == 0:
        serial_der = b"\x02\x01\x00"
    else:
        # 转无符号字节（大端）。
        n_bytes = (serial_int.bit_length() + 7) // 8
        serial_bytes = serial_int.to_bytes(n_bytes, "big")
        # 如果最高位是 1，前面补 0x00 避免被解析为负数。
        if serial_bytes[0] & 0x80:
            serial_bytes = b"\x00" + serial_bytes
        serial_der = b"\x02" + bytes([len(serial_bytes)]) + serial_bytes

    # 3. 手工组装 OCSP Request DER：
    #   SEQUENCE {                            -- OCSPRequest
    #     SEQUENCE {                          -- TBSRequest
    #       [0] EXPLICIT INTEGER 0            -- version (optional, default v1)
    #       SEQUENCE {                        -- requestList
    #         SEQUENCE {                      -- Request
    #           SEQUENCE {                    -- CertID
    #             SEQUENCE { OID, NULL }      -- AlgorithmIdentifier (SHA-1)
    #             OCTET STRING (20B)          -- issuerNameHash
    #             OCTET STRING (20B)          -- issuerKeyHash
    #             INTEGER                     -- serialNumber
    #           }
    #         }
    #       }
    #     }
    #   }

    def tlv(tag: int, value: bytes) -> bytes:
        """Tag-Length-Value 编码。tag 单字节。"""
        l = len(value)
        if l < 0x80:
            return bytes([tag, l]) + value
        elif l < 0x100:
            return bytes([tag, 0x81, l]) + value
        elif l < 0x10000:
            return bytes([tag, 0x82, (l >> 8) & 0xff, l & 0xff]) + value
        else:
            raise ValueError(f"TLV too long: {l}")

    # SHA-1 OID = 1.3.14.3.2.26
    sha1_oid = bytes([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a])
    # AlgorithmIdentifier = SEQUENCE { OID, NULL }
    alg_id = tlv(0x30, sha1_oid + b"\x05\x00")
    # CertID = SEQUENCE { alg_id, issuerNameHash, issuerKeyHash, serial }
    cert_id = tlv(0x30, alg_id + tlv(0x04, issuer_name_hash) + tlv(0x04, issuer_key_hash) + serial_der)
    # Request = SEQUENCE { CertID }
    request = tlv(0x30, cert_id)
    # requestList = SEQUENCE { Request }
    request_list = tlv(0x30, request)
    # version = [0] EXPLICIT INTEGER 0
    version = bytes([0xa0, 0x03, 0x02, 0x01, 0x00])
    # TBSRequest = SEQUENCE { version, requestList }
    tbs_request = tlv(0x30, version + request_list)
    # OCSPRequest = SEQUENCE { TBSRequest }
    return tlv(0x30, tbs_request)


# ---------------------------------------------------------------------------
# Part 1: HTTP API 测试
# ---------------------------------------------------------------------------

def test_http_api(api_base: str, token: str | None) -> None:
    print("\n[Part 1] HTTP API 测试")
    has_auth = token is not None

    # 1. Health
    code, resp = http_request("GET", f"{api_base}/api/v1/sys/health")
    record("1.1 Health check",
           code == 200 and resp.get("data", {}).get("sealed") is False,
           f"code={code} resp={resp}")

    # 创建密钥（重复创建返回 409/400，忽略 — 说明已存在）
    for kid, alg, is_asym in [
        ("rel-aes-key", "AES-256-GCM", False),
        ("rel-hmac-key", "AES-256-GCM", False),
        ("rel-aes-key-2", "AES-256-GCM", False),
    ]:
        code, _ = http_request("POST", f"{api_base}/api/v1/keys",
                               {"key_id": kid, "algorithm": alg}, token)
        if code not in (200, 400, 409):
            record(f"创建 {kid}", False, f"create failed code={code}")
    # 非对称密钥：字段名是 key_type
    for kid, kt in [("rel-rsa-key", "rsa"), ("rel-ecdsa-key", "ecdsa")]:
        code, _ = http_request("POST", f"{api_base}/api/v1/keys/asymmetric",
                               {"key_id": kid, "key_type": kt}, token)
        if code not in (200, 400, 409):
            record(f"创建 {kid}", False, f"create failed code={code}")

    # 2. Encrypt
    code, resp = http_request("POST", f"{api_base}/api/v1/encrypt",
                              {"key_id": "rel-aes-key", "plaintext": b64("release-gate-test")}, token)
    ct = resp.get("data", {}).get("ciphertext", "")
    record("2.1 Encrypt", code == 200 and ct and ct.startswith("AAAA"), f"code={code} resp={resp}")

    # 3. Decrypt
    code, resp = http_request("POST", f"{api_base}/api/v1/decrypt",
                              {"key_id": "rel-aes-key", "ciphertext": ct}, token)
    pt_b64 = resp.get("data", {}).get("plaintext", "")
    try:
        pt = base64.b64decode(pt_b64).decode()
    except Exception:
        pt = ""
    record("3.1 Decrypt round-trip",
           code == 200 and pt == "release-gate-test", f"pt={pt!r}")

    # 4. Rotate
    code, _ = http_request("POST", f"{api_base}/api/v1/keys/rel-aes-key/rotate", None, token)
    record("4.1 Rotate key", code == 200, f"code={code}")

    # 5. Decrypt with old ciphertext (version routing)
    code, resp = http_request("POST", f"{api_base}/api/v1/decrypt",
                              {"key_id": "rel-aes-key", "ciphertext": ct}, token)
    try:
        pt2 = base64.b64decode(resp.get("data", {}).get("plaintext", "")).decode()
    except Exception:
        pt2 = ""
    record("5.1 Decrypt old version ciphertext (auto-routing)",
           code == 200 and pt2 == "release-gate-test", f"pt={pt2!r}")

    # 6. GenerateDataKey (GDK with plaintext)
    code, resp = http_request("POST", f"{api_base}/api/v1/keys/rel-aes-key/generate-data-key", None, token)
    record("6.1 GenerateDataKey (with plaintext)",
           code == 200 and resp.get("data", {}).get("plaintext_dek") and resp.get("data", {}).get("ciphertext_dek"),
           f"code={code}")

    # 7. GDK without plaintext — POST /api/v1/keys/gdk-no-plaintext?key_id=...
    code, resp = http_request("POST", f"{api_base}/api/v1/keys/gdk-no-plaintext?key_id=rel-aes-key", None, token)
    record("7.1 GenerateDataKeyWithoutPlaintext",
           code == 200 and (resp.get("data", {}).get("ciphertext") or resp.get("data", {}).get("ciphertext_dek")),
           f"code={code} resp={resp}")

    # 8. Sign (RSA) — 字段名 data，不是 message
    code, resp = http_request("POST", f"{api_base}/api/v1/sign",
                              {"key_id": "rel-rsa-key", "data": b64("sign-me")}, token)
    sig = resp.get("data", {}).get("signature", "")
    record("8.1 Sign (RSA-4096)", code == 200 and sig, f"code={code} resp={resp}")

    # 9. Verify (RSA)
    if sig:
        code, resp = http_request("POST", f"{api_base}/api/v1/verify",
                                  {"key_id": "rel-rsa-key", "data": b64("sign-me"), "signature": sig}, token)
        record("9.1 Verify (RSA-4096)",
               code == 200 and resp.get("data", {}).get("valid") is True, f"resp={resp}")
    else:
        skip("9.1 Verify (RSA-4096)", "Sign failed, cannot verify")

    # 10. Sign (ECDSA)
    code, resp = http_request("POST", f"{api_base}/api/v1/sign",
                              {"key_id": "rel-ecdsa-key", "data": b64("ecdsa-sign")}, token)
    sig_ec = resp.get("data", {}).get("signature", "")
    record("10.1 Sign (ECDSA-P256)", code == 200 and sig_ec, f"code={code}")

    # 11. Verify (ECDSA)
    if sig_ec:
        code, resp = http_request("POST", f"{api_base}/api/v1/verify",
                                  {"key_id": "rel-ecdsa-key", "data": b64("ecdsa-sign"), "signature": sig_ec}, token)
        record("11.1 Verify (ECDSA-P256)",
               code == 200 and resp.get("data", {}).get("valid") is True, f"resp={resp}")
    else:
        skip("11.1 Verify (ECDSA-P256)", "Sign failed")

    # 12. Generate MAC — POST /api/v1/mac/generate，字段名 data
    code, resp = http_request("POST", f"{api_base}/api/v1/mac/generate",
                              {"key_id": "rel-hmac-key", "data": b64("mac-data")}, token)
    mac = resp.get("data", {}).get("mac", "")
    record("12.1 GenerateMac", code == 200 and mac, f"code={code} resp={resp}")

    # 13. Verify MAC — POST /api/v1/mac/verify
    if mac:
        code, resp = http_request("POST", f"{api_base}/api/v1/mac/verify",
                                  {"key_id": "rel-hmac-key", "data": b64("mac-data"), "mac": mac}, token)
        record("13.1 VerifyMac",
               code == 200 and resp.get("data", {}).get("valid") is True, f"resp={resp}")
    else:
        skip("13.1 VerifyMac", "GenerateMac failed")

    # 14. GetPublicKey — GET /api/v1/keys/public-key?key_id=...
    code, resp = http_request("GET", f"{api_base}/api/v1/keys/public-key?key_id=rel-rsa-key", None, token)
    record("14.1 GetPublicKey (RSA)",
           code == 200 and resp.get("data", {}).get("public_key"), f"code={code} resp={resp}")

    # 15. ReEncrypt — 字段名 dest_key_id（不是 target_key_id）
    code, resp = http_request("POST", f"{api_base}/api/v1/encrypt",
                              {"key_id": "rel-aes-key", "plaintext": b64("reencrypt-me")}, token)
    ct2 = resp.get("data", {}).get("ciphertext", "")
    code, resp = http_request("POST", f"{api_base}/api/v1/re-encrypt",
                              {"source_key_id": "rel-aes-key", "dest_key_id": "rel-aes-key-2",
                               "ciphertext": ct2}, token)
    record("15.1 ReEncrypt",
           code == 200 and resp.get("data", {}).get("ciphertext"), f"code={code} resp={resp}")

    # 16. Soft-delete — 需要 body {"version": 1}
    code, _ = http_request("PATCH", f"{api_base}/api/v1/keys/rel-aes-key-2/soft-delete",
                           {"version": 1}, token)
    record("16.1 Soft-delete key", code == 200, f"code={code}")

    # 17. Restore — 需要 body {"version": 1}
    code, _ = http_request("POST", f"{api_base}/api/v1/keys/rel-aes-key-2/restore",
                           {"version": 1}, token)
    record("17.1 Restore key", code == 200, f"code={code}")

    # 18. MFA setup — 需要 authenticator
    if has_auth:
        code, resp = http_request("POST", f"{api_base}/api/v1/auth/mfa/setup",
                                  {"role_id": "e2e-role"}, token)
        record("18.1 MFA TOTP setup",
               code in (200, 201) and (resp.get("data", {}).get("secret") or resp.get("data", {}).get("uri")),
               f"code={code} resp={resp}")
    else:
        skip("18.1 MFA TOTP setup", "dev 模式无 authenticator（需 cluster 模式 + token）")

    # 19. Quorum approval create — 需要 authenticator
    if has_auth:
        code, resp = http_request("POST", f"{api_base}/api/v1/approvals",
                                  {"operation": "ShredKey", "key_id": "rel-aes-key",
                                   "required": 2, "requestor": "rel-user"}, token)
        record("19.1 Quorum approval create",
               code in (200, 201), f"code={code} resp={resp}")
    else:
        skip("19.1 Quorum approval create", "dev 模式无 authenticator")

    # 20. Quorum list — 需要 authenticator
    if has_auth:
        code, _ = http_request("GET", f"{api_base}/api/v1/approvals", None, token)
        record("20.1 Quorum list", code == 200, f"code={code}")
    else:
        skip("20.1 Quorum list", "dev 模式无 authenticator")

    # === v1.4.x: OCSP Responder (RFC 6960) ===
    # 端点：POST /api/v1/ocsp (raw DER) / GET /api/v1/ocsp/{base64}
    # 响应 Content-Type: application/ocsp-response
    # 注意：dev 模式默认未启用 PKI/OCSP → 跳过（需要 cfg.pki.enabled + cfg.pki.ocsp_enabled）

    # 21. PKI/CA 创建（OCSP 前置：需要先有 CA 才能查）
    code, ca_resp = http_request("POST", f"{api_base}/api/v1/pki/ca",
                                 {"key_id": "rel-ocsp-ca", "algo": "rsa",
                                  "subject": "CN=Release OCSP CA", "ttl_years": 10}, token)
    ca_ok = code == 200 and ca_resp.get("data", {}).get("key_id")
    if not ca_ok:
        skip("21.x OCSP 测试套件", f"PKI/OCSP 未启用或 CreateCA 失败 (code={code})")
    else:
        ca_key_id = ca_resp["data"]["key_id"]
        # data.pem 是 []byte 字段（x509 PEM 文本），JSON 自动 base64 编码；客户端需 base64 解码。
        ca_pem_bytes = base64.b64decode(ca_resp["data"]["pem"])
        ca_pem_text = ca_pem_bytes.decode("utf-8", errors="replace")

        # 22. 签发 leaf 证书（OCSP 查询目标）
        # 生成 leaf RSA 密钥对 → 公钥 PEM → base64 编码（因为 handler 字段类型是 []byte，
        # JSON 反序列化时会按 base64 解码）。
        leaf_priv_pem = generate_test_rsa_priv_pem()
        leaf_pub_pem = derive_pub_pem_from_priv_pem(leaf_priv_pem)
        leaf_pub_b64 = base64.b64encode(leaf_pub_pem.encode()).decode()
        code, leaf_resp = http_request("POST", f"{api_base}/api/v1/pki/issue",
                                        {"ca_key_id": ca_key_id, "subject": "CN=rel-ocsp-leaf",
                                         "algo": "rsa", "public_key_pem": leaf_pub_b64,
                                         "cert_type": "sign", "ttl_days": 30}, token)
        leaf_serial = leaf_resp.get("data", {}).get("serial", "") if code == 200 else ""
        record("21.1 PKI 签发 leaf 证书", code == 200 and leaf_serial,
               f"code={code} resp={leaf_resp}")

        # 23. OCSP POST (raw DER) — 用 Python 内置构造 OCSP Request DER
        if leaf_serial:
            ocsp_req_der = build_ocsp_request_der(ca_pem_text, leaf_serial)
            code, body, hdrs = http_request_raw(
                "POST", f"{api_base}/api/v1/ocsp",
                body=ocsp_req_der,
                content_type="application/ocsp-request",
                token=token)
            ct = hdrs.get("Content-Type", "") or hdrs.get("content-type", "")
            # 检查响应是合法 OCSP DER（首字节 0x30 = SEQUENCE）。
            ok_post = (code == 200 and
                       "application/ocsp-response" in ct.lower() and
                       len(body) > 0 and body[0] == 0x30)
            record("22.1 OCSP POST raw DER (RFC 6960 §A.2)",
                   ok_post,
                   f"code={code} ct={ct} body={len(body)}B")
        else:
            skip("22.1 OCSP POST raw DER", "leaf 签发失败，前置缺失")

        # 24. OCSP GET base64 — URL-safe base64 编码后作为 path 段
        if leaf_serial:
            ocsp_req_der = build_ocsp_request_der(ca_pem_text, leaf_serial)
            encoded = base64.urlsafe_b64encode(ocsp_req_der).rstrip(b"=").decode()
            code, body, hdrs = http_request_raw(
                "GET", f"{api_base}/api/v1/ocsp/{encoded}",
                body=None,
                content_type="application/ocsp-request",
                token=token)
            ct = hdrs.get("Content-Type", "") or hdrs.get("content-type", "")
            ok_get = (code == 200 and
                      "application/ocsp-response" in ct.lower() and
                      len(body) > 0 and body[0] == 0x30)
            record("23.1 OCSP GET base64 (RFC 6960 §A.1)",
                   ok_get,
                   f"code={code} ct={ct} body={len(body)}B")
        else:
            skip("23.1 OCSP GET base64", "leaf 签发失败，前置缺失")


# ---------------------------------------------------------------------------
# Part 2: Admin API 测试
# ---------------------------------------------------------------------------

def test_admin_api(admin_base: str, api_base: str = "", token: str | None = None) -> None:
    print("\n[Part 2] Admin API 测试")

    code, resp = http_request("GET", f"{admin_base}/admin/api/dashboard", token=token)
    record("A1 Dashboard",
           code == 200 and resp.get("ok") is True and "key_count" in resp.get("data", {}),
           f"code={code} resp={resp}")

    code, resp = http_request("GET", f"{admin_base}/admin/api/keys", token=token)
    keys = resp.get("data", {}).get("keys", [])
    record("A2 Keys list",
           code == 200 and isinstance(keys, list) and len(keys) > 0, f"keys={len(keys)}")

    # demo-order-key 由 --demo 标志自动创建；用 --config 启动时不会自动创建。
    # 自愈：缺失时通过 API 端口建一次（忽略 409 已存在错误）。
    if api_base:
        http_request("POST", f"{api_base}/api/v1/keys",
                     {"key_id": "demo-order-key", "algorithm": "AES-256-GCM"}, token)

    code, resp = http_request("POST", f"{admin_base}/admin/api/crypto/encrypt",
                              {"key_id": "demo-order-key", "plaintext": b64("admin-api-test")}, token)
    ct = resp.get("data", {}).get("ciphertext", "")
    record("A3 Admin crypto encrypt",
           code == 200 and ct and ct.startswith("AAAA"), f"code={code}")

    code, resp = http_request("POST", f"{admin_base}/admin/api/crypto/decrypt",
                              {"key_id": "demo-order-key", "ciphertext": ct}, token)
    try:
        pt = base64.b64decode(resp.get("data", {}).get("plaintext", "")).decode()
    except Exception:
        pt = ""
    record("A4 Admin crypto decrypt round-trip",
           code == 200 and pt == "admin-api-test", f"pt={pt!r}")

    code, resp = http_request("GET", f"{admin_base}/admin/api/audit?limit=5", token=token)
    record("A5 Audit log",
           code == 200 and resp.get("ok") is True, f"code={code}")


# ---------------------------------------------------------------------------
# Part 3: Selenium 浏览器测试
# ---------------------------------------------------------------------------

def test_browser(admin_base: str, admin_token: str | None = None) -> None:
    print("\n[Part 3] Selenium 浏览器测试")
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from webdriver_manager.chrome import ChromeDriverManager
    except ImportError:
        record("Selenium import", False, "selenium not installed (pip install selenium webdriver-manager)")
        return

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,900")
    # 启用浏览器控制台日志（用于 B15）
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    try:
        # v1.4.2: 显式用 webdriver-manager 装匹配版本的 chromedriver。
        # selenium 内置 Manager 经常下载老版本（与本机 Chrome 不匹配）。
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
    except Exception as e:
        record("Selenium 启动 Chrome", False, str(e))
        return

    driver.implicitly_wait(SELENIUM_IMPLICIT_WAIT)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)

    def safe_test(name: str, fn):
        try:
            fn()
        except Exception as e:
            record(name, False, f"异常: {type(e).__name__}: {e}")

    # B0. Admin 登录（v1.4.2 双因子登录重做）。
    #
    # 三种情形：
    #   (a) --admin-token 未传：dev/cluster 模式均自动认证（adminToken="" → isAuth=true）
    #       → 访问 /admin/ 直接看到 dashboard
    #   (b) --admin-token 已传 + dev 模式（_dev_captcha_text 端点可用）：
    #       真实表单登录：GET /admin/login → 填 captcha_text via dev 端点
    #       → POST /admin/api/login → session cookie → /admin/ dashboard
    #       这是 v1.4.2 重点覆盖的双因子登录路径
    #   (c) --admin-token 已传 + cluster 模式（无 dev 端点，devMode=false）：
    #       退回 Bearer Token 兼容路径（CDP 注入 Authorization 头）
    #       双因子核心由 handlers_auth_test.go (Go 单元测试) 覆盖
    def is_dev_mode() -> bool:
        """探测 _dev_captcha_text 端点是否可用（仅 dev 模式启用）。
        - dev 模式：返回 200 / 400 / 404（按 id 是否合法 / 存在）
        - cluster 模式：返回 403 (disabled_in_production)
        """
        try:
            code, _ = http_request("GET",
                f"{admin_base}/admin/api/_dev_captcha_text?id=__probe__")
            return code in (200, 400, 404)
        except Exception:
            return False

    def b0_form_login_inner():
        """真实表单提交登录（v1.4.2 双因子）。仅 dev 模式可用。
        异常抛出由 b0_login 捕获。
        """
        # 1. 导航 /admin/ → 302 → /admin/login
        driver.get(admin_base + "/admin/")
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            EC.presence_of_element_located((By.ID, "login-form"))
        )
        # 2. 等 captcha 自动加载（auth.js 调 /admin/api/captcha）
        WebDriverWait(driver, 5).until(
            lambda d: d.find_element(By.ID, "captcha_id").get_attribute("value") or ""
        )
        captcha_id = driver.find_element(By.ID, "captcha_id").get_attribute("value")
        if not captcha_id:
            raise RuntimeError("captcha 未渲染完成")

        # 3. 通过 dev 端点拉 captcha text（避开 OCR）
        code, resp = http_request("GET",
            f"{admin_base}/admin/api/_dev_captcha_text?id={captcha_id}")
        if code != 200:
            raise RuntimeError(f"captcha text 端点 code={code} resp={resp}")
        captcha_text = resp.get("text", "")
        if not captcha_text:
            raise RuntimeError(f"captcha text 为空 resp={resp}")

        # 4. 填表。TOTP 未配置时填任意 6 位均可通过（dev mode 默认无 TOTP）
        driver.find_element(By.ID, "admin_token").clear()
        driver.find_element(By.ID, "admin_token").send_keys(admin_token)
        driver.find_element(By.ID, "totp_code").clear()
        driver.find_element(By.ID, "totp_code").send_keys("000000")
        driver.find_element(By.ID, "captcha_text").clear()
        driver.find_element(By.ID, "captcha_text").send_keys(captcha_text)

        # 5. 提交（auth.js 自动加 X-CSRF-Token header）
        driver.find_element(By.ID, "btn-submit").click()

        # 6. 等跳到 /admin/ + dashboard 可见
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            lambda d: admin_base + "/admin/" in d.current_url
        )
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            EC.presence_of_element_located((By.ID, "nav-dashboard"))
        )

    def b0_login():
        # (a) 无 admin_token：auto-authed
        if not admin_token:
            driver.get(admin_base + "/admin/")
            WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
                EC.presence_of_element_located((By.ID, "nav-dashboard"))
            )
            record("B0 Admin 登录 (auto-authed, no admin_token)", True)
            return

        # (b) admin_token + dev 模式：真实表单登录
        if is_dev_mode():
            try:
                b0_form_login_inner()
                record("B0 Admin 双因子表单登录 (admin_token + captcha + session cookie)", True)
            except Exception as e:
                record("B0 Admin 双因子表单登录", False,
                       f"异常: {type(e).__name__}: {e}")
            return

        # (c) admin_token + cluster 模式：CDP Bearer 兼容路径（保留 v1.4.0 行为）
        try:
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {
                "headers": {"Authorization": f"Bearer {admin_token}"}
            })
        except Exception as e:
            record("B0 cluster Bearer 兼容", False, f"CDP 注入失败: {e}")
            return
        driver.get(admin_base + "/admin/")
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            EC.presence_of_element_located((By.ID, "nav-dashboard"))
        )
        record("B0 cluster Bearer 兼容 (form login N/A — 双因子走 Go 单测)", True)
    safe_test("B0 Admin 登录", b0_login)

    # B1. 页面加载
    def b1():
        driver.get(admin_base + "/")
        WebDriverWait(driver, PAGE_LOAD_TIMEOUT).until(
            EC.presence_of_element_located((By.ID, "nav-dashboard"))
        )
        title = driver.title
        record("B1 页面加载（title 含 Yvonne）", "Yvonne" in title, f"title={title!r}")
    safe_test("B1 页面加载", b1)

    # B2. CSS 加载
    def b2():
        links = driver.find_elements(By.CSS_SELECTOR, 'link[rel="stylesheet"]')
        css_loaded = any("/static/style.css" in (l.get_attribute("href") or "") for l in links)
        record("B2 CSS 资源加载（/static/style.css）", css_loaded, f"links={len(links)}")
    safe_test("B2 CSS 加载", b2)

    # B3. JS 加载 + 无内联脚本
    def b3():
        scripts = driver.find_elements(By.TAG_NAME, "script")
        js_loaded = any("/static/console.js" in (s.get_attribute("src") or "") for s in scripts)
        inline_scripts = [s for s in scripts if s.get_attribute("src") is None and (s.text or "").strip()]
        record("B3 JS 资源加载 + 无内联脚本",
               js_loaded and len(inline_scripts) == 0,
               f"scripts={len(scripts)} inline={len(inline_scripts)}")
    safe_test("B3 JS 加载", b3)

    # B4. CSP 头
    def b4():
        import urllib.request as ur
        req = ur.Request(admin_base + "/")
        # Cluster 模式下页面需 Bearer 认证
        if admin_token:
            req.add_header("Authorization", f"Bearer {admin_token}")
        with ur.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            csp_header = resp.headers.get("Content-Security-Policy", "")
        record("B4 CSP 头存在 + script-src 'self'",
               "script-src" in csp_header and "'self'" in csp_header,
               f"csp={csp_header!r}")
    safe_test("B4 CSP 头", b4)

    # B5. 默认进入 Dashboard
    def b5():
        dashboard = driver.find_element(By.ID, "page-dashboard")
        is_visible = "hidden" not in (dashboard.get_attribute("class") or "")
        record("B5 默认显示 Dashboard 页面", is_visible, f"class={dashboard.get_attribute('class')!r}")
    safe_test("B5 Dashboard 默认显示", b5)

    # B6. Dashboard 数据加载
    def b6():
        WebDriverWait(driver, 5).until(
            lambda d: d.find_element(By.ID, "stat-keys").text not in ("", "-")
        )
        key_count = driver.find_element(By.ID, "stat-keys").text
        record("B6 Dashboard 数据加载（Key Count）", key_count and key_count != "-", f"count={key_count!r}")
    safe_test("B6 Dashboard 数据加载", b6)

    # B7. Vault State
    def b7():
        state = driver.find_element(By.ID, "stat-state").text
        record("B7 Dashboard Vault State", "unsealed" in state.lower(), f"state={state!r}")
    safe_test("B7 Vault State", b7)

    # B8. 导航到 Keys
    def b8():
        driver.find_element(By.ID, "nav-keys").click()
        WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.ID, "btn-refresh-keys"))
        )
        record("B8 导航到 Keys 页面", True)
    safe_test("B8 导航 Keys", b8)

    # B9. 刷新密钥列表
    def b9():
        driver.find_element(By.ID, "btn-refresh-keys").click()
        WebDriverWait(driver, 5).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#keys-body tr")) > 0
        )
        rows = driver.find_elements(By.CSS_SELECTOR, "#keys-body tr")
        record("B9 Keys 列表加载", len(rows) > 0, f"rows={len(rows)}")
    safe_test("B9 Keys 列表加载", b9)

    # B10. 导航到 Crypto
    def b10():
        driver.find_element(By.ID, "nav-crypto").click()
        WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.ID, "btn-encrypt"))
        )
        record("B10 导航到 Crypto 页面", True)
    safe_test("B10 导航 Crypto", b10)

    # B11 + B12. 加密 + 解密 round-trip
    ciphertext_holder = [""]
    def b11():
        driver.find_element(By.ID, "crypto-keyid").clear()
        driver.find_element(By.ID, "crypto-keyid").send_keys("demo-order-key")
        driver.find_element(By.ID, "crypto-data").clear()
        driver.find_element(By.ID, "crypto-data").send_keys("browser-encrypt-test")
        driver.find_element(By.ID, "btn-encrypt").click()
        WebDriverWait(driver, 5).until(
            lambda d: "ciphertext" in d.find_element(By.ID, "crypto-output").text
        )
        output = driver.find_element(By.ID, "crypto-output").text
        import re
        m = re.search(r'"ciphertext"\s*:\s*"([^"]+)"', output)
        ciphertext_holder[0] = m.group(1) if m else ""
        record("B11 浏览器加密", "AAAA" in ciphertext_holder[0], f"ct={ciphertext_holder[0][:30]!r}")
    safe_test("B11 浏览器加密", b11)

    def b12():
        if not ciphertext_holder[0]:
            skip("B12 浏览器解密 round-trip", "加密未生成 ciphertext")
            return
        driver.find_element(By.ID, "crypto-data").clear()
        driver.find_element(By.ID, "crypto-data").send_keys(ciphertext_holder[0])
        driver.find_element(By.ID, "btn-decrypt").click()
        WebDriverWait(driver, 5).until(
            lambda d: "browser-encrypt-test" in d.find_element(By.ID, "crypto-output").text
        )
        output2 = driver.find_element(By.ID, "crypto-output").text
        record("B12 浏览器解密 round-trip",
               "browser-encrypt-test" in output2, f"output={output2[:80]!r}")
    safe_test("B12 浏览器解密", b12)

    # B13. 导航到 Audit
    def b13():
        driver.find_element(By.ID, "nav-audit").click()
        WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.ID, "page-audit"))
        )
        # audit-table 默认 hidden（dev 模式无 audit query 配置），
        # 检查 page-audit 可见即可
        record("B13 导航到 Audit 页面", True)
    safe_test("B13 导航 Audit", b13)

    # B14. 导航到 MFA & Quorum
    def b14():
        driver.find_element(By.ID, "nav-mfa").click()
        WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.ID, "page-mfa"))
        )
        mfa_heading = driver.find_element(By.CSS_SELECTOR, "#page-mfa h2").text
        record("B14 导航到 MFA & Quorum 页面",
               "MFA" in mfa_heading, f"heading={mfa_heading!r}")
    safe_test("B14 导航 MFA & Quorum", b14)

    # B15. 浏览器控制台无严重错误
    def b15():
        try:
            logs = driver.get_log("browser")
        except Exception:
            logs = []
        errors = [l for l in logs if l.get("level") == "SEVERE"]
        real_errors = [l for l in errors if "favicon" not in l.get("message", "").lower()]
        record("B15 浏览器控制台无严重错误", len(real_errors) == 0, f"errors={real_errors[:2]}")
    safe_test("B15 控制台无错误", b15)

    try:
        driver.quit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Yvonne KMS Release Gate E2E Suite")
    parser.add_argument("--api-port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--admin-port", type=int, default=DEFAULT_ADMIN_PORT)
    parser.add_argument("--no-browser", action="store_true", help="跳过 Selenium 浏览器测试")
    parser.add_argument("--token", default=None, help="Bearer Token（启用 MFA/Quorum 测试，需 cluster 模式）")
    parser.add_argument("--admin-token", default=None, help="Admin UI Bearer Token（cluster 模式启用全站认证时需要）")
    args = parser.parse_args()

    api_base = f"http://127.0.0.1:{args.api_port}"
    admin_base = f"http://127.0.0.1:{args.admin_port}"

    print("=" * 70)
    print("Yvonne KMS Release Gate E2E Suite")
    print(f"  API:     {api_base}")
    print(f"  Admin:   {admin_base}")
    print(f"  Browser: {'SKIP' if args.no_browser else 'ENABLED'}")
    print(f"  Token:   {'SET (MFA/Quorum enabled)' if args.token else 'NONE (dev mode)'}")
    print("=" * 70)

    # 前置：健康检查
    try:
        code, resp = http_request("GET", f"{api_base}/api/v1/sys/health")
        if code != 200:
            print(f"❌ 服务不可达 (code={code}). 请先启动: ./bin/yvonne dev --demo")
            return 2
        if resp.get("data", {}).get("sealed") is True:
            print("❌ 服务处于 sealed 状态，需先 unseal")
            return 2
        print(f"✅ 服务健康（unsealed）")
    except Exception as e:
        print(f"❌ 服务不可达: {e}")
        print("   请先启动: ./bin/yvonne dev --demo")
        return 2

    test_http_api(api_base, args.token)
    test_admin_api(admin_base, api_base, args.token)
    if not args.no_browser:
        test_browser(admin_base, args.admin_token)

    print("\n" + "=" * 70)
    total = len(passed) + len(failed) + len(skipped)
    print(f"总计: {len(passed)}/{len(passed) + len(failed)} 通过, {len(skipped)} 跳过, {len(failed)} 失败")
    if skipped:
        print(f"\n跳过项 ({len(skipped)}):")
        for name, reason in skipped:
            print(f"  ⏭️  {name} — {reason}")
    if failed:
        print(f"\n失败项 ({len(failed)}):")
        for name, detail in failed:
            print(f"  ❌ {name}")
            print(f"     {detail}")
    print("=" * 70)

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
