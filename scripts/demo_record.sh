#!/bin/bash
# Yvonne 全功能演示录制脚本（asciinema 用）。
#
# 用法:
#   asciinema rec -c "bash scripts/demo_record.sh" docs/demo/yvonne-demo.cast
#
# 前提:
#   1. /tmp/yvonne-rec/ 已 init（unseal key + config + PG 库 yvonne_demo3）
#   2. bin/yvonne 已用 -tags gmsm 编译

set -u
cd "$(dirname "$0")/.."

TOKEN="demo-admin-token"
API="http://127.0.0.1:8200"
CFG=/tmp/yvonne-rec/config.json

# ---- 打字机效果 ----
type_cmd() {
  printf '\033[1;32m$\033[0m '
  local cmd="$1"
  for ((i=0; i<${#cmd}; i++)); do
    printf '%s' "${cmd:i:1}"
    sleep 0.03
  done
  printf '\n'
  sleep 0.4
}

# 注释标题
say() {
  printf '\n\033[1;36m# %s\033[0m\n' "$1"
  sleep 0.8
}

# 执行并展示（显示美化命令，执行真实命令）
run() { type_cmd "$1"; eval "$1"; sleep 0.6; }

# 只打印美化命令（不执行占位符命令，真实执行在下一行）
show() { type_cmd "$1"; }

jqget() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

clear
printf '\033[1;35m'
cat <<'EOF'
  __   __
  \ \ / /__  _   _ _ __  _ __   ___
   \ V / _ \| | | | '_ \| '_ \ / _ \
    | | (_) | |_| | | | | | | |  __/
    |_|\___/ \__,_|_| |_|_| |_|\___|

  Yvonne 全功能演示 — cluster 模式（PostgreSQL 持久化）
  KMS + PKI + SDF + OCSP + 审计链  |  v1.4.2
EOF
printf '\033[0m\n'
sleep 2

# ============ 1. 启动 ============
say "1. 启动 Yvonne server（cluster 模式 + local_pki 自动解封）"
type_cmd "cat /tmp/yvonne-rec/config.json | jq '{mode, storage: .storage.type, unseal: .unseal.type, pki: .pki, sdf: .sdf}'"
cat /tmp/yvonne-rec/config.json | python3 -c "import sys,json;c=json.load(sys.stdin);print(json.dumps({'mode':c['mode'],'storage':c['storage']['type'],'unseal':c['unseal']['type'],'pki':c.get('pki'),'sdf':c.get('sdf')},indent=2))"
sleep 1

type_cmd "./bin/yvonne server --config $CFG &"
nohup ./bin/yvonne server --config "$CFG" > /tmp/yvonne-rec/server.log 2>&1 &
sleep 4
grep -E "unsealed|SDF|OCSP|listening" /tmp/yvonne-rec/server.log | head -5
sleep 1.5

run "curl -s $API/api/v1/sys/health | jq .data"

# ============ 2. KMS ============
say "2. KMS 信封加密 — 创建密钥 → 加密 → 解密 → 轮转"
run "curl -s -X POST $API/api/v1/keys -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"key_id\":\"demo-aes\"}' | jq -c '{ok, version: .data.version}'"

PLAIN_B64=$(echo -n 'ID-Card-110101199001011234' | base64)
show "curl -s -X POST $API/api/v1/encrypt -d '{\"key_id\":\"demo-aes\",\"plaintext\":\"<base64>\"}' | jq -r .data.ciphertext"
CT=$(curl -s -X POST $API/api/v1/encrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"key_id\":\"demo-aes\",\"plaintext\":\"$PLAIN_B64\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['ciphertext'])")
echo "密文(前64): ${CT:0:64}..."
sleep 0.8

say "  ↳ 真实性证明①：密文与明文肉眼不可对应（AES-256-GCM）"
printf '    明文: %s\n' "ID-Card-110101199001011234"
printf '    密文: %s...\n' "${CT:0:40}"
sleep 1.2

show "curl -s -X POST $API/api/v1/decrypt -d '{\"key_id\":\"demo-aes\",\"ciphertext\":\"<密文>\"}' | jq -r .data.plaintext | base64 -d"
curl -s -X POST $API/api/v1/decrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"key_id\":\"demo-aes\",\"ciphertext\":\"$CT\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['plaintext'])" | base64 -d
printf '\n'
sleep 1

say "  ↳ 真实性证明②：篡改密文任意 1 字节 → GCM 认证失败，拒绝解密"
TAMPERED=$(python3 -c "ct='$CT'; import base64; raw=bytearray(base64.b64decode(ct)); raw[-1]^=0x01; print(base64.b64encode(bytes(raw)).decode())")
show "curl -s -X POST $API/api/v1/decrypt -d '{\"key_id\":\"demo-aes\",\"ciphertext\":\"<篡改后密文>\"}' | jq -c ."
curl -s -X POST $API/api/v1/decrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"key_id\":\"demo-aes\",\"ciphertext\":\"$TAMPERED\"}" | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d))"
sleep 1

say "  ↳ 真实性证明③：用另一个密钥解密 → 失败（密钥隔离）"
run "curl -s -X POST $API/api/v1/keys -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"key_id\":\"demo-other\"}' | jq -c .ok"
show "curl -s -X POST $API/api/v1/decrypt -d '{\"key_id\":\"demo-other\",\"ciphertext\":\"<密文>\"}' | jq -c ."
curl -s -X POST $API/api/v1/decrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"key_id\":\"demo-other\",\"ciphertext\":\"$CT\"}" | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d))"
sleep 1

run "curl -s -X POST $API/api/v1/keys/demo-aes/rotate -H 'Authorization: Bearer $TOKEN' | jq -c '{ok, version: .data.version}'"

say "  ↳ 轮转后用 v2 解 v1 的密文（版本化自路由）"
show "curl -s -X POST $API/api/v1/decrypt -d '{\"key_id\":\"demo-aes\",\"ciphertext\":\"<旧密文>\"}' | jq -r .data.plaintext | base64 -d"
curl -s -X POST $API/api/v1/decrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"key_id\":\"demo-aes\",\"ciphertext\":\"$CT\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['plaintext'])" | base64 -d
printf '\n'
sleep 1

# ============ 3. PKI ============
say "3. PKI — 自建 CA → 签发证书 → 验证 → 吊销 → CRL"
show "curl -s -X POST $API/api/v1/pki/ca -d '{\"key_id\":\"demo-root-ca\",\"algo\":\"rsa\",\"subject\":\"CN=Demo Root CA\",\"ttl_years\":10}'"
CA_RESP=$(curl -s -X POST $API/api/v1/pki/ca -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"key_id":"demo-root-ca","algo":"rsa","subject":"CN=Yvonne Demo Root CA","ttl_years":10}')
echo "$CA_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];print(json.dumps({'cert_id':d['cert_id'],'serial':d['serial'][:24]+'...'},indent=2))"
CA_PEM=$(echo "$CA_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['pem'])")
sleep 1

run "curl -s -X POST $API/api/v1/keys/asymmetric -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"key_id\":\"demo-rsa\",\"key_type\":\"rsa\"}' | jq -c .ok"

PUB_B64=$(curl -s "$API/api/v1/keys/public-key?key_id=demo-rsa" -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['public_key'])")

show "curl -s -X POST $API/api/v1/pki/issue -d '{\"ca_key_id\":\"demo-root-ca\",\"subject\":\"CN=demo-service\",\"algo\":\"rsa\",\"public_key_pem\":\"<公钥>\",\"ttl_days\":365}'"
LEAF=$(curl -s -X POST $API/api/v1/pki/issue -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"ca_key_id\":\"demo-root-ca\",\"subject\":\"CN=demo-service\",\"algo\":\"rsa\",\"public_key_pem\":\"$PUB_B64\",\"ttl_days\":365}")
echo "$LEAF" | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];print(json.dumps({'cert_id':d['cert_id'],'serial':d['serial'][:20]+'...'},indent=2))"
LEAF_PEM=$(echo "$LEAF" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['pem'])")
LEAF_ID=$(echo "$LEAF" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['cert_id'])")
sleep 1

show "curl -s -X POST $API/api/v1/pki/verify -d '{\"cert_pem\":\"<leaf>\",\"ca_cert_pem\":\"<ca>\"}' | jq -c .data"
curl -s -X POST $API/api/v1/pki/verify -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"cert_pem\":\"$LEAF_PEM\",\"ca_cert_pem\":\"$CA_PEM\"}" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['data']))"
sleep 1

run "curl -s -X POST $API/api/v1/pki/revoke -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"ca_key_id\":\"demo-root-ca\",\"cert_id\":\"$LEAF_ID\",\"reason\":\"keyCompromise\"}' | jq -c .data"

say "  ↳ 吊销后再次验证 — revoked=true（吊销检查生效）"
show "curl -s -X POST $API/api/v1/pki/verify -d '{\"cert_pem\":\"<leaf>\",\"ca_cert_pem\":\"<ca>\"}' | jq -c .data"
curl -s -X POST $API/api/v1/pki/verify -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"cert_pem\":\"$LEAF_PEM\",\"ca_cert_pem\":\"$CA_PEM\"}" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['data']))"
sleep 1

run "curl -s $API/api/v1/pki/ca/demo-root-ca/crl -H 'Authorization: Bearer $TOKEN' | jq -c '{ok, crl_bytes: (.data.crl | length)}'"

# ============ 4. SDF ============
say "4. SDF 软件密码机 — GM/T 0018-2023（SM2/SM3/SM4）"
run "curl -s -X POST $API/api/v1/sdf/device/info -H 'Authorization: Bearer demo-sdf-token' -H 'Content-Type: application/json' -d '{}' | jq .data"

run "curl -s -X POST $API/api/v1/sdf/sm3/hash -H 'Authorization: Bearer demo-sdf-token' -H 'Content-Type: application/json' -d '{\"data\":\"616263\"}' | jq -r .data.hash"
sleep 0.5

SM4_KEY="30313233343536373839616263646566"
show "curl -s -X POST $API/api/v1/sdf/sm4/encrypt -d '{\"key\":\"<sm4 key>\",\"data\":\"<hex(plain)>\"}' | jq -r .data.ciphertext"
SM4_CT=$(curl -s -X POST $API/api/v1/sdf/sm4/encrypt -H 'Authorization: Bearer demo-sdf-token' -H 'Content-Type: application/json' -d "{\"key\":\"$SM4_KEY\",\"data\":\"$(printf 'SM4 secret' | xxd -p | tr -d '\n')\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['ciphertext'])")

say "  ↳ 真实性证明④：SM4 密文（hex）与明文完全不同"
printf '    明文: %s\n' "SM4 secret"
printf '    密文: %s\n' "$SM4_CT"
sleep 1.2

show "curl -s -X POST $API/api/v1/sdf/sm4/decrypt -d '{\"key\":\"<sm4 key>\",\"ciphertext\":\"<密文>\"}' | jq -r .data.plaintext"
curl -s -X POST $API/api/v1/sdf/sm4/decrypt -H 'Authorization: Bearer demo-sdf-token' -H 'Content-Type: application/json' -d "{\"key\":\"$SM4_KEY\",\"ciphertext\":\"$SM4_CT\"}" | python3 -c "import sys,json;h=json.load(sys.stdin)['data']['plaintext'];print(bytes.fromhex(h).decode())"
sleep 1

say "  ↳ 真实性证明⑤：错误密钥解密 SM4 密文 → 失败（非假密码机）"
WRONG_KEY="30313233343536373839616263646565"
show "curl -s -X POST $API/api/v1/sdf/sm4/decrypt -d '{\"key\":\"<错误key>\",\"ciphertext\":\"<密文>\"}' | jq -c ."
curl -s -X POST $API/api/v1/sdf/sm4/decrypt -H 'Authorization: Bearer demo-sdf-token' -H 'Content-Type: application/json' -d "{\"key\":\"$WRONG_KEY\",\"ciphertext\":\"$SM4_CT\"}" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)))"
sleep 1

say "  ↳ 真实性证明⑥：SM2 签名对篡改数据验签 → valid=false"
printf '    原文: transfer 100 yuan  |  篡改: transfer 999 yuan\n'
python3 - <<'PYEOF'
import json, urllib.request
def call(path, body):
    req = urllib.request.Request('http://127.0.0.1:8200'+path, data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer demo-sdf-token'}, method='POST')
    return json.loads(urllib.request.urlopen(req).read())
kp = call('/api/v1/sdf/sm2/generate', {})['data']
sig = call('/api/v1/sdf/sm2/sign', {'private_key': kp['private_key'], 'data': 'transfer 100 yuan'.encode().hex()})['data']['signature']
for text in ['transfer 100 yuan', 'transfer 999 yuan']:
    r = call('/api/v1/sdf/sm2/verify', {'public_key': kp['public_key'], 'data': text.encode().hex(), 'signature': sig})['data']
    print(f'    验签（{text}）: valid={r["valid"]}')
PYEOF
sleep 1

# ============ 5. audit/query（auditDir 修复验证） ============
say "5. 审计查询 — POST /api/v1/audit/query（auditDir 修复后可用）"
run "curl -s -X POST $API/api/v1/audit/query -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"limit\":5}' | jq -c '{ok, count: .data.count}'"
run "curl -s -X POST $API/api/v1/audit/query -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"limit\":4}' | jq -r '.data.entries[] | \"[\(.entry.action)] \(.entry.resource // \"-\") → \(.entry.status)\"'"
say "  ↳ 哈希链证据：每条记录含 prev_signature + chain_seq（篡改即断链）"
run "curl -s -X POST $API/api/v1/audit/query -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"limit\":1}' | jq -c '.data.entries[0].envelope | {chain_seq, prev_sig: .prev_signature[0:16], sig: .signature[0:16]}'"
sleep 1

# ============ 6. Web UI ============
say "6. Web 控制台（OLED 暗色主题，截图见 docs/demo/screenshots/）"
run "curl -s -o /dev/null -w 'Admin UI HTTP %{http_code}\n' http://127.0.0.1:8250/admin/"
printf '  Dashboard / Keys / Crypto / Audit / MFA 页面截图:\n'
ls docs/demo/screenshots/
sleep 2

# ============ 7. 持久化验证 ============
say "7. PG 持久化 — 停服 → 放回私钥 → 重启 → 数据保留"
show "pkill -f 'bin/yvonne'; echo stopped"
pkill -f 'bin/yvonne' 2>/dev/null; sleep 2; echo "stopped"

say "  ↳ local_pki 阅后即焚：unseal.pem 已被删除（私钥不滞留磁盘）"
show "ls /tmp/yvonne-rec/unseal.pem || echo '已阅后即焚'"
ls /tmp/yvonne-rec/unseal.pem 2>&1 || echo "已阅后即焚（符合安全设计）"

say "  ↳ 运维流程：从安全备份放回私钥"
run "cp /tmp/yvonne-rec/unseal-backup.pem /tmp/yvonne-rec/unseal.pem"

show "./bin/yvonne server --config $CFG &"
nohup ./bin/yvonne server --config "$CFG" > /tmp/yvonne-rec/server2.log 2>&1 &
sleep 5
grep -E "auto-unsealed|listening" /tmp/yvonne-rec/server2.log | head -3
sleep 1

say "  ↳ 验证：密钥/证书/吊销/审计 全部保留"
run "curl -s '$API/api/v1/keys/public-key?key_id=demo-rsa' -H 'Authorization: Bearer $TOKEN' | jq -c '{ok, pub_len: (.data.public_key | length)}'"

run "curl -s $API/api/v1/pki/ca/demo-root-ca/crl -H 'Authorization: Bearer $TOKEN' | jq -c '{ok, crl_bytes: (.data.crl | length)}'"

run "wc -l /tmp/yvonne-rec/audit/audit.log"

printf '\n\033[1;32m'
cat <<'EOF'
  ✅ 演示完成 — Yvonne：一个二进制提供
     KMS + PKI + SDF + OCSP + 审计链 + Web 控制台
     全部数据 PostgreSQL 持久化，重启后完整可用
EOF
printf '\033[0m\n'
sleep 3

pkill -f 'bin/yvonne' 2>/dev/null
exit 0
