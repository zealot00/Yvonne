#!/usr/bin/env python3
"""
Yvonne KMS Python SDK 快速开始示例。

前提：yvonne dev --demo --port 8200 已启动。
运行：python sdk/python/examples/quickstart.py
"""

import sys
import os

# 添加 SDK 到路径。
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from yvonne import YvonneClient

def main():
    client = YvonneClient("http://127.0.0.1:8200")

    # 1. 健康检查
    health = client.health()
    print(f"State: {health['data']['state']}")

    # 2. 创建密钥
    resp = client.create_key("python-demo-key")
    print(f"Created: {resp['data']['key_id']} v{resp['data']['version']}")

    # 3. 加密
    plaintext = b"Hello Yvonne from Python!"
    enc = client.encrypt("python-demo-key", plaintext)
    print(f"Encrypted: v{enc['data']['version']}")

    # 4. 解密
    dec_bytes = client.decrypt_bytes("python-demo-key", enc["data"]["ciphertext"])
    print(f"Decrypted: {dec_bytes.decode()}")

    # 5. 轮转
    rot = client.rotate_key("python-demo-key")
    print(f"Rotated to v{rot['data']['version']}")

    # 6. 旧密文仍可解密
    dec_old = client.decrypt_bytes("python-demo-key", enc["data"]["ciphertext"])
    print(f"v1 still decrypts: {dec_old.decode()}")

    print("\n✅ Python SDK quickstart complete!")

if __name__ == "__main__":
    main()
