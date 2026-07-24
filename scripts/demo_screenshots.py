#!/usr/bin/env python3
"""截图 Yvonne Admin Web UI（演示报告素材）。

用法：
  python3 scripts/demo_screenshots.py --admin-token demo-admin-token
输出：
  docs/demo/screenshots/*.png
"""
from __future__ import annotations

import argparse
import os
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin-base", default="http://127.0.0.1:8250")
    ap.add_argument("--admin-token", required=True)
    ap.add_argument("--out", default="docs/demo/screenshots")
    args = ap.parse_args()

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from webdriver_manager.chrome import ChromeDriverManager
    except ImportError:
        print("pip install selenium webdriver-manager")
        return 1

    os.makedirs(args.out, exist_ok=True)

    # 与 release_gate_e2e.py 完全一致的 Chrome 配置（已在当前环境验证可用）。
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,900")

    service = ChromeService(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.implicitly_wait(5)
    driver.set_page_load_timeout(20)

    try:
        # CDP 注入 Bearer Token（cluster 模式 admin UI 认证兼容路径）。
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {
            "headers": {"Authorization": f"Bearer {args.admin_token}"}
        })

        def shot(name: str, wait_id: str, settle: float = 2.0) -> bool:
            try:
                WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.ID, wait_id))
                )
                time.sleep(settle)
                path = os.path.join(args.out, f"{name}.png")
                driver.save_screenshot(path)
                print(f"  ✅ {path}")
                return True
            except Exception as e:
                print(f"  ⚠️  {name}: {type(e).__name__}: {e}")
                return False

        # 1. Dashboard
        driver.get(args.admin_base + "/admin/")
        shot("01-dashboard", "nav-dashboard")

        # auto-authed 模式下，在顶部 Bearer Token 输入框填入 token，
        # 使 audit 页等需要 API token 的数据可见。
        if args.admin_token:
            try:
                ti = driver.find_element(By.ID, "tokenInput")
                ti.clear()
                ti.send_keys(args.admin_token)
                time.sleep(0.5)
            except Exception:
                pass

        # 2-4. Keys / Crypto / Audit
        for nav_id, name in [
            ("nav-keys", "02-keys"),
            ("nav-crypto", "03-crypto"),
            ("nav-audit", "04-audit"),
        ]:
            try:
                driver.find_element(By.ID, nav_id).click()
                shot(name, nav_id)
            except Exception as e:
                print(f"  ⚠️  {name}: {e}")

        # 5. MFA & Quorum（可选）
        try:
            driver.find_element(By.ID, "nav-mfa").click()
            shot("05-mfa-quorum", "nav-mfa", settle=1.5)
        except Exception:
            print("  ⏭️  05-mfa-quorum: nav-mfa 不存在，跳过")

        print("截图完成")
        return 0
    finally:
        driver.quit()


if __name__ == "__main__":
    sys.exit(main())
