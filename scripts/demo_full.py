#!/usr/bin/env python3
"""
Yvonne 全功能演示脚本
=====================

一键展示 Yvonne 密码学平台的全部核心能力：
  1. KMS 信封加密（Create/Encrypt/Decrypt/Rotate/GDK/Sign/Verify/MAC/ReEncrypt）
  2. PKI 证书签发（CreateCA/Issue/Verify/Revoke/CRL）
  3. OCSP 在线证书状态查询（RFC 6960）
  4. SDF 软件密码机（GM/T 0018-2023，SM2/SM3/SM4）
  5. 审计日志（哈希链）

前置：
  go build -tags gmsm -o bin/yvonne ./cmd/yvonne
  ./bin/yvonne dev --demo

用法：
  python3 scripts/demo_full.py
  python3 scripts/demo_full.py --api-port 8200
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
import urllib.error

DEFAULT_API_PORT = 8200
SDF_TOKEN = "demo-sdf-token"


def http(method: str, url: str, body=None, token: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return -1, {"error": str(e)}


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64d(s: str) -> str:
    return base64.b64decode(s).decode()


def banner(title: str) -> None:
    print()
    print("=" * 66)
    print(f"  {title}")
    print("=" * 66)


def step(desc: str, detail: str = "") -> None:
    print(f"  ▶ {desc}")
    if detail:
        for line in detail.split("\n"):
            print(f"      {line}")


def must(code: int, resp: dict, what: str) -> dict:
    """检查 HTTP 响应，失败时打印完整响应并退出。"""
    if code != 200 or not resp.get("ok", False):
        print(f"  ❌ {what} 失败: code={code} resp={resp}")
        sys.exit(1)
    return resp.get("data", {})


def wait_ready(api: str) -> bool:
    for _ in range(30):
        code, resp = http("GET", f"{api}/api/v1/sys/health")
        if code == 200 and resp.get("data", {}).get("sealed") is False:
            return True
        time.sleep(0.5)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-port", type=int, default=DEFAULT_API_PORT)
    args = ap.parse_args()
    api = f"http://127.0.0.1:{args.api_port}"

    banner("🧊 Yvonne 全功能演示")
    step("目标: 一个平台完成密钥管理 + 证书签发 + 密码机服务 + 审计")
    step("文档: docs/manual/user-manual.zh.md")

    if not wait_ready(api):
        print("❌ yvonne 未就绪，请先启动: ./bin/yvonne dev --demo")
        return 1
    step("服务已就绪 (unsealed)")

    # ------------------------------------------------------------------
    # Part 1: KMS 信封加密
    # ------------------------------------------------------------------
    banner("Part 1/5: KMS 信封加密 — 密钥全生命周期")

    http("POST", f"{api}/api/v1/keys", {"key_id": "demo-aes", "algorithm": "AES-256-GCM"})
    step("创建 AES-256-GCM 密钥 demo-aes")

    code, r = http("POST", f"{api}/api/v1/encrypt",
                   {"key_id": "demo-aes", "plaintext": b64("身份证 110101199001011234")})
    ct = r.get("data", {}).get("ciphertext", "")
    step("加密敏感数据", f"密文(前32): {ct[:32]}...  版本化自路由格式 [ver|nonce|ct]")

    code, r = http("POST", f"{api}/api/v1/decrypt", {"key_id": "demo-aes", "ciphertext": ct})
    pt = b64d(r.get("data", {}).get("plaintext", ""))
    step("解密回原文", f"plaintext: {pt}")

    http("POST", f"{api}/api/v1/keys/demo-aes/rotate", None)
    step("轮转密钥 → v2（旧密文仍可解密，版本自动路由）")

    code, r = http("POST", f"{api}/api/v1/decrypt", {"key_id": "demo-aes", "ciphertext": ct})
    step("用 v2 解 v1 密文", f"仍得到: {b64d(r.get('data', {}).get('plaintext', ''))}")

    code, r = http("POST", f"{api}/api/v1/keys/demo-aes/generate-data-key", None)
    step("GenerateDataKey", "明文 DEK 经 SecureBuffer 受控暴露，写响应后立即 Wipe")

    http("POST", f"{api}/api/v1/keys/asymmetric", {"key_id": "demo-rsa", "key_type": "rsa"})
    code, r = http("POST", f"{api}/api/v1/sign", {"key_id": "demo-rsa", "data": b64("合同内容")})
    sig = r.get("data", {}).get("signature", "")
    code, r = http("POST", f"{api}/api/v1/verify",
                   {"key_id": "demo-rsa", "data": b64("合同内容"), "signature": sig})
    step("RSA-4096-PSS 签名验签", f"valid: {r.get('data', {}).get('valid')}")

    code, r = http("POST", f"{api}/api/v1/mac/generate", {"key_id": "demo-aes", "data": b64("phone:13800000000")})
    mac = r.get("data", {}).get("mac", "")
    step("HMAC 盲索引", "加密字段也能等值查询（HMAC 做索引列，不可逆）")

    # ------------------------------------------------------------------
    # Part 2: PKI 证书签发
    # ------------------------------------------------------------------
    banner("Part 2/5: PKI — 自建 CA 签发 X.509 证书")

    code, r = http("POST", f"{api}/api/v1/pki/ca",
                   {"key_id": "demo-root-ca", "algo": "rsa",
                    "subject": "CN=Yvonne Demo Root CA,O=Yvonne", "ttl_years": 10})
    d = must(code, r, "CreateCA")
    ca_pem_b64 = d.get("pem", "")
    ca_pem = base64.b64decode(ca_pem_b64).decode() if ca_pem_b64 else ""
    step("创建自签根 CA (RSA-4096)",
         f"serial: {d.get('serial', '')[:24]}...\n"
         f"PEM: {ca_pem.splitlines()[0] if ca_pem else ''}")

    # 生成 leaf 公钥（复用 Part 1 创建的 demo-rsa 的公钥）。
    # 注意：public_key 字段是 []byte JSON 编码 = base64(PEM 文本)，
    #       IssueCert 的 public_key_pem 同样是 []byte（客户端传 base64(PEM)），
    #       因此直接透传即可，不要二次 base64 编码。
    code, r = http("GET", f"{api}/api/v1/keys/public-key?key_id=demo-rsa")
    d = must(code, r, "GetPublicKey")
    leaf_pub_b64 = d.get("public_key", "")
    code, r = http("POST", f"{api}/api/v1/pki/issue",
                   {"ca_key_id": "demo-root-ca", "subject": "CN=demo-service",
                    "algo": "rsa", "public_key_pem": leaf_pub_b64,
                    "cert_type": "sign", "ttl_days": 365})
    d = must(code, r, "IssueCert")
    leaf_pem_b64 = d.get("pem", "")
    leaf_serial = d.get("serial", "")
    leaf_cert_id = d.get("cert_id", "")
    step("签发服务器证书 demo-service",
         f"serial: {leaf_serial[:24]}...  TTL: 365d")

    code, r = http("POST", f"{api}/api/v1/pki/verify",
                   {"cert_pem": leaf_pem_b64, "ca_cert_pem": ca_pem_b64})
    v = must(code, r, "VerifyCert")
    step("验证证书链", f"valid: {v.get('valid')}  revoked: {v.get('revoked')}")

    # ------------------------------------------------------------------
    # Part 3: OCSP 在线状态查询
    # ------------------------------------------------------------------
    banner("Part 3/5: OCSP — 证书吊销 + 在线状态查询 (RFC 6960)")

    code, r = http("POST", f"{api}/api/v1/pki/revoke",
                   {"ca_key_id": "demo-root-ca", "cert_id": leaf_cert_id,
                    "reason": "keyCompromise"})
    must(code, r, "RevokeCert")
    step("吊销 demo-service 证书", "reason: keyCompromise")

    code, r = http("GET", f"{api}/api/v1/pki/ca/demo-root-ca/crl")
    d = must(code, r, "GetCRL")
    crl = d.get("crl", "")
    step("获取 CRL", f"CRL DER: {len(base64.b64decode(crl)) if crl else 0} bytes（含已吊销序列号）")

    code, r = http("POST", f"{api}/api/v1/pki/verify",
                   {"cert_pem": leaf_pem_b64, "ca_cert_pem": ca_pem_b64})
    v = must(code, r, "VerifyCert(revoked)")
    step("吊销后再次验证", f"valid: {v.get('valid')}  revoked: {v.get('revoked')}")

    # ------------------------------------------------------------------
    # Part 4: SDF 软件密码机
    # ------------------------------------------------------------------
    banner("Part 4/5: SDF 软件密码机 — GM/T 0018-2023 国密设备接口")

    code, r = http("POST", f"{api}/api/v1/sdf/device/info", {}, SDF_TOKEN)
    info = r.get("data", {})
    step("SDF 设备信息", f"{info.get('name')}  {info.get('version')}")

    code, r = http("POST", f"{api}/api/v1/sdf/sm2/generate", {}, SDF_TOKEN)
    kp = r.get("data", {})
    step("SM2 密钥对生成", f"pub: {str(kp.get('public_key', ''))[:40]}...")

    code, r = http("POST", f"{api}/api/v1/sdf/sm2/sign",
                   {"private_key": kp.get("private_key"), "data": b"SM2 signature demo".hex()},
                   SDF_TOKEN)
    sm2_sig = r.get("data", {}).get("signature", "")
    code, r = http("POST", f"{api}/api/v1/sdf/sm2/verify",
                   {"public_key": kp.get("public_key"),
                    "data": b"SM2 signature demo".hex(),
                    "signature": sm2_sig}, SDF_TOKEN)
    step("SM2 签名验签 (SM2WithSM3)", f"valid: {r.get('data', {}).get('valid')}")

    code, r = http("POST", f"{api}/api/v1/sdf/sm3/hash",
                   {"data": b"abc".hex()}, SDF_TOKEN)
    step("SM3 哈希", f"SM3('abc') = {r.get('data', {}).get('hash', '')[:32]}...")

    sm4_key = "30313233343536373839616263646566"
    code, r = http("POST", f"{api}/api/v1/sdf/sm4/encrypt",
                   {"key": sm4_key, "data": b"SM4 secret".hex()}, SDF_TOKEN)
    sm4_ct = r.get("data", {}).get("ciphertext", "")
    code, r = http("POST", f"{api}/api/v1/sdf/sm4/decrypt",
                   {"key": sm4_key, "ciphertext": sm4_ct}, SDF_TOKEN)
    sm4_pt = bytes.fromhex(r.get("data", {}).get("plaintext", "")).decode()
    step("SM4 加解密往返", f"plaintext: {sm4_pt}")

    # ------------------------------------------------------------------
    # Part 5: 审计
    # ------------------------------------------------------------------
    banner("Part 5/5: 审计 — 哈希链完整性")

    code, r = http("POST", f"{api}/api/v1/audit/query", {"limit": 5})
    entries = []
    if code == 200 and r.get("ok"):
        data = r.get("data", {})
        if isinstance(data, dict):
            entries = data.get("entries", []) or []
        elif isinstance(data, list):
            entries = data
    if entries:
        step("最近审计记录", f"共 {len(entries)} 条（HMAC 哈希链，篡改即断链报警）")
        for e in entries[-3:]:
            if isinstance(e, dict):
                step("", f"[{e.get('action', '?')}] {e.get('resource', '?')} → {e.get('result', '?')}")
    else:
        step("审计链（dev 模式说明）",
             "dev 模式审计实时输出到服务 stdout（JSON 行），含 HMAC 链 prev_hash。\n"
             "上方演示的所有操作（CreateKey/Encrypt/Sign/CreateCA/Issue/Revoke/SDF）\n"
             "均已逐条记录。cluster 模式落盘 + Syslog 双写，可用 /api/v1/audit/query 检索。")

    # ------------------------------------------------------------------
    banner("✅ 演示完成")
    print("""
  Yvonne 一个二进制提供：
    • KMS    信封加密 + 密钥生命周期 + 自动轮转
    • PKI    X.509 证书签发 + 链验证 + CRL + OCSP（SM2/RSA/ECDSA）
    • SDF    GM/T 0018-2023 软件密码机（SM2/SM3/SM4）
    • 审计    哈希链 + Syslog 双写 + MFA + Quorum
    • 接入    HTTP REST + gRPC + MCP + Go/Python/Java SDK + Web 控制台

  Web 控制台: http://127.0.0.1:8250
  用户手册:   docs/manual/user-manual.zh.md
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
