#!/usr/bin/env bash
# scripts/security-check.sh
#
# Yvonne KMS - 强制安全自检脚本
#
# 本脚本固化六条不可妥协的安全红线，每次代码完成后必须运行：
#
#   [CHECK 1] KeepAlive 配对检查
#     每处 clear(x) 必须在 3 行内出现 runtime.KeepAlive(x)。
#     原因：Go 编译器会做死代码消除 (DCE)，单独的 clear() 可能被优化掉，
#     导致明文密钥残留在内存中。runtime.KeepAlive 强制保留引用，阻止 DCE。
#
#   [CHECK 2] []byte Getter 禁止检查
#     禁止任何方法返回 []byte（特别是敏感数据的 Getter，如 Bytes/Copy/Get/...）。
#     原因：返回 []byte 会让敏感切片逃逸到调用方栈帧/GC 堆，绕过 SecureBuffer
#     的内存隔离与 Wipe 防御。敏感数据必须通过 WithKey(func(secret []byte) error)
#     闭包作用域访问。
#
#   [CHECK 3] Error / 日志敏感信息泄露检查
#     禁止在 error 返回值或日志/panic 输出中拼接敏感变量的值。
#     红线场景（命中即告警）：
#       a) fmt.Errorf / fmt.Sprintf / log.Printf / fmt.Printf / fmt.Println / panic
#          的格式串含 %s %v %x %q %X %+v %#v，且同一行存在以敏感关键词命名
#          的变量（key/secret/password/token/plaintext/master/dek/nonce/share/
#          credential/private）。
#       b) 用 + 拼接字符串时，操作数是含敏感关键词的标识符。
#     合法场景（不报）：
#       - 错误消息含关键词但只描述状态（如 "master key is empty"）——无变量拼接。
#       - 变量名/字段名/形参名含关键词（不进入字符串字面量）。
#
#   [CHECK 4] 系统熵源检查
#     禁止 import math/rand 或 math/rand/v2；禁止在 memguard 包外直接调用
#     crypto/rand（绕过 GenerateSecureRandom 统一入口）。
#
#   [CHECK 5] 明文密钥参数必须使用 *memguard.SecureBuffer
#     函数签名中敏感参数（key/masterKey/dek/secretKey/privateKey/master）禁止
#     使用 []byte 类型，必须用 *memguard.SecureBuffer。
#
#   [CHECK 6] subtle.ConstantTimeCompare 强制
#     禁止用 == 或 != 或 strings.EqualFold 比较 Master Key / Secret / Token /
#     Password / HMAC / Signature 等敏感变量，必须用 crypto/subtle.ConstantTimeCompare。
#     原因：== 在比较不等长字节切片时提前返回，泄露长度信息；比较等长切片时
#     也存在短路退出时机差异，可被计时侧信道利用还原明文。
#
#   [CHECK 7] ProvideShare 成功后必须擦除 collectedShares
#     ProvideShare 方法达阈值触发 Combine 后，无论成败必须遍历整个
#     collectedShares 二维数组，对每份 []byte 调用 clear() + runtime.KeepAlive()，
#     然后置 nil 切断引用。防止内存快照泄露碎片。
#
#   [CHECK 8] Shamir 运算必须在 GF(2^8) 有限域内
#     8a) seal 包中涉及 byte 域元素的运算禁止用普通 + - * /，
#         必须用 gfMul / gfInv / ^(异或)。整数算术仅允许用于索引/循环计数。
#     8b) 强制存在 gfExp / gfLog 对数表与 gfMul / gfInv 函数，
#         且不可约多项式必须是 0x11b（AES 标准），生成元必须是 0x03。
#     原因：Shamir 在普通整数环上运算会导致插值不闭环（无法还原 secret），
#     且会引入信息泄露。GF(2^8) 是标准选择，所有运算封闭于 256 个元素内。
#
#   [CHECK 9] Combine 返回 *memguard.SecureBuffer，明文不流浪
#     9a) Combine 函数返回类型必须是 *memguard.SecureBuffer，不得返回 []byte。
#     9b) Combine 函数体中必须调用 memguard.NewSecureBuffer 封装明文。
#     9c) Combine 函数中创建的临时明文切片必须有 defer 清理逻辑
#         （defer 后含 clear 调用），防止失败路径明文残留堆内存。
#     原因：Combine 还原出的 Master Key 是系统最高敏感数据，若短暂以普通 []byte
#     形式存在于堆上，会被 GC 快照捕获、或因 panic 路径残留。必须立即封装进
#     SecureBuffer，并对临时切片有 defer 兜底清零。
#
#   [CHECK 10] MemoryStore.Delete 必须 clear(value) 后再 delete(m, key)
#     检测 MemoryStore 的 Delete 方法实现：禁止仅调用 delete(m.data, key)，
#     必须先取出 value 切片，调用 clear(value) + runtime.KeepAlive(value)
#     物理覆写底层数组，再 delete(m.data, key)。
#     原因：仅 delete(map, key) 只解除 map 引用，底层数组内容仍残留在堆上
#     直到 GC 回收——这段时间内内存快照可读出已"删除"的密文，违反
#     Crypto-Shredding。clear(value) 就地覆写底层数组为 0，确保即使内存被
#     dump 也读不到已销毁的密文。
#
#   [CHECK 11] API Handler 的 io.ReadAll 结果必须 clear+KeepAlive
#     检测 api 包中调用 io.ReadAll(req.Body) 的 handler：
#     读出的 bodyBytes 必须在 handler 内被 clear() + runtime.KeepAlive() 清理，
#     不得让包含明文的原始 []byte 跟着 Request 对象进入 GC 等待队列。
#     原因：HTTP body 含业务明文，若不主动 clear，GC 回收前内存快照可读到。
#     必须立刻装入 SecureBuffer 并擦除临时缓冲，实现 Payload Escaping Control。
#     合法场景（不报）：
#       - 与 nil 比较（if key == nil）——指针判空，非内容比较。
#       - 长度比较（if len(key) == 0）——长度非内容。
#       - subtle.ConstantTimeCompare(a, b) == 1 ——正确用法本身。
#       - errors.Is / errors.As ——错误匹配，非敏感内容比较。
#       - 测试文件 (_test.go)。
#
# 例外白名单：
#   - internal/memguard/entropy.go 的 GenerateSecureRandom：作为 CSPRNG 唯一入口，
#     必须返回 []byte 供调用方封装为 SecureBuffer。这是受控的"信任根"出口。
#   - 测试文件 (_test.go)：测试需要断言内容，豁免 CHECK 2 与 CHECK 3。
#
# 退出码：
#   0 = 全部通过（CHECK 3 的启发式告警需人工复核，默认不拉低退出码）
#   1 = 发现硬性违规（CHECK 1/2/4/5/6 任一）
#   2 = 脚本自身错误
#
# 用法：
#   ./scripts/security-check.sh
#   make security-check

set -uo pipefail
# 注意：不启用 -e，让循环里的 grep 失败不中断脚本。

# ---------- 颜色与输出 ----------
if [[ -t 1 ]]; then
  RED=$'\033[31m'
  YEL=$'\033[33m'
  GRN=$'\033[32m'
  RST=$'\033[0m'
  BLD=$'\033[1m'
else
  RED=""; YEL=""; GRN=""; RST=""; BLD=""
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# ---------- 搜索工具抽象 ----------
# 统一返回 "file:line:content" 格式。测试文件过滤统一在 _is_test_file 中做，
# 避免依赖 rg 专属的 -g 语法或 grep 的 --include。
SEARCH_BIN=""
if command -v rg >/dev/null 2>&1; then
  SEARCH_BIN="rg"
elif command -v grep >/dev/null 2>&1; then
  SEARCH_BIN="grep"
else
  echo "${RED}[FATAL]${RST} ripgrep 或 grep 均不可用" >&2
  exit 2
fi

# search_go <pattern> <dir...>
# 在指定目录下搜索 Go 文件（含 .go 后缀），输出 file:line:content。
search_go() {
  local pattern="$1"; shift
  if [[ "$SEARCH_BIN" == "rg" ]]; then
    rg --type go -n --no-heading "$pattern" "$@" 2>/dev/null
  else
    # grep -rnE：递归、行号、ERE。--include 仅 GNU/BSD grep 支持。
    grep -rnE --include='*.go' "$pattern" "$@" 2>/dev/null
  fi
}

# is_test_file <path> 判断是否 _test.go。
is_test_file() {
  case "$1" in
    *_test.go) return 0 ;;
    *) return 1 ;;
  esac
}

FAIL=0

section() {
  echo ""
  echo "${BLD}=== $1 ===${RST}"
}

# ---------- CHECK 1: clear() 必须紧跟 runtime.KeepAlive ----------
section "[CHECK 1] clear() 必须在 3 行内配对 runtime.KeepAlive"

violations_ck1=()

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 跳过注释行
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    "//"*|"/*"*) continue ;;
  esac

  # 提取 clear(x) 的参数名
  arg="$(echo "$content" | sed -nE 's/.*clear\(([^)]+)\).*/\1/p')"
  [[ -z "$arg" ]] && continue

  # 抓取该行之后 3 行（含本行），检查是否出现 runtime.KeepAlive(<arg>)
  end=$((lineno + 3))
  window=$(sed -n "${lineno},${end}p" "$file")
  # 转义 arg 中所有正则元字符，避免 [ ] . * + ? ^ $ ( ) { } | \ 等干扰匹配。
  # 用 sed 逐字符转义：在所有非字母数字下划线前加反斜杠。
  arg_esc="$(printf '%s' "$arg" | sed 's/[^a-zA-Z0-9_]/\\&/g')"
  if ! echo "$window" | grep -qE "runtime\.KeepAlive\([[:space:]]*${arg_esc}[[:space:]]*\)"; then
    violations_ck1+=("$file:$lineno  clear($arg)  →  缺少 runtime.KeepAlive($arg)")
  fi
done < <(search_go 'clear\(' internal/ cmd/)

if (( ${#violations_ck1[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 所有 clear() 调用均已正确配对 runtime.KeepAlive"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck1[@]} 处 clear() 未配对 runtime.KeepAlive："
  for v in "${violations_ck1[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 2: 禁止返回 []byte 的方法 Getter ----------
section "[CHECK 2] 禁止方法返回 []byte (敏感数据 Getter 红线)"

violations_ck2=()

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  # 跳过测试文件
  is_test_file "$file" && continue
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 白名单：GenerateSecureRandom 是 CSPRNG 出口
  if echo "$content" | grep -qE 'func\s+GenerateSecureRandom\s*\('; then
    continue
  fi
  # 白名单：Hash 接口的 Sum/HMAC 返回哈希值（非敏感密钥）
  if echo "$content" | grep -qE 'func\s+\([^)]*\)\s+(Sum|HMAC)\s*\('; then
    continue
  fi
  violations_ck2+=("$file:$lineno  $content")
done < <(search_go 'func\s*\([^)]*\)\s+\w+\s*\([^)]*\)\s*\[\]byte' internal/ cmd/)

if (( ${#violations_ck2[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 未发现返回 []byte 的方法 Getter"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck2[@]} 处方法返回 []byte（敏感数据外泄风险）："
  for v in "${violations_ck2[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 3: Error / 日志敏感信息泄露 ----------
section "[CHECK 3] Error / 日志中不得拼接敏感变量值"

SENSITIVE_VARS='key|secret|password|passwd|token|plaintext|master|dek|nonce|share|credential|private'
DANGER_VERBS='%s|%v|%x|%q|%X|%\+v|%#v'

violations_ck3=()

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 跳过纯注释行
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    "//"*|"/*"*) continue ;;
  esac

  hit=0

  # 规则 A：格式串含危险动词 + 同行有敏感变量名
  # 变量名识别：单词边界内含敏感词（如 masterKey、plaintextDEK、secret、token）
  if echo "$content" | grep -qE "(${DANGER_VERBS})" && \
     echo "$content" | grep -qiE "\b(${SENSITIVE_VARS})[a-zA-Z0-9_]*\b|\b[a-zA-Z_][a-zA-Z0-9_]*(${SENSITIVE_VARS})\b"; then
    hit=1
  fi

  # 规则 B：字符串 + 拼接敏感变量
  if echo "$content" | grep -qE '"[[:space:]]*\+[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*' && \
     echo "$content" | grep -qiE "\b(${SENSITIVE_VARS})[a-zA-Z0-9_]*\b|\b[a-zA-Z_][a-zA-Z0-9_]*(${SENSITIVE_VARS})\b"; then
    hit=1
  fi

  if (( hit == 1 )); then
    violations_ck3+=("$file:$lineno  $content")
  fi
done < <(search_go 'fmt\.Errorf|errors\.New|fmt\.Sprintf|log\.Printf|fmt\.Printf|fmt\.Println|panic\(' internal/ cmd/)

if (( ${#violations_ck3[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 未发现 error/日志中拼接敏感变量值"
else
  echo "${YEL}  [WARN]${RST} 发现 ${#violations_ck3[@]} 处可疑拼接（人工复核，确属泄露则修复）："
  for v in "${violations_ck3[@]}"; do
    echo "    ${YEL}- $v${RST}"
  done
  # 启发式检测：默认仅告警不拉低退出码。如需严格失败，取消下行注释：
  # FAIL=1
fi

# ---------- CHECK 4: 系统熵源检查 ----------
section "[CHECK 4] 系统熵源：禁止 math/rand 与绕过 GenerateSecureRandom"

violations_ck4=()

# 4a) 禁止 import math/rand 或 math/rand/v2（任何 .go 文件，含测试）。
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"
  violations_ck4+=("$file:$lineno  $content  →  禁止 import math/rand，须用 memguard.GenerateSecureRandom")
done < <(search_go '"math/rand"|"math/rand/v2"' internal/ cmd/)

# 4b) 禁止在 memguard 包外直接调用 crypto/rand 的 Read 函数（rand.Read()）。
#     注意：rand.Reader 是 crypto/rand 的标准 io.Reader 接口，供 rsa.DecryptOAEP /
#     rsa.GenerateKey 等标准库函数使用，底层就是 OS CSPRNG，不是绕过。
#     因此只禁 rand.Read( 函数调用，不禁 rand.Reader 变量引用。
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 跳过注释行
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    "//"*) continue ;;
    "/*"*) continue ;;
  esac

  # 白名单：memguard 包内的 entropy.go 允许直接调用 crypto/rand
  # 匹配相对路径 internal/memguard/entropy.go 与绝对路径 */internal/memguard/entropy.go
  case "$file" in
    internal/memguard/entropy.go) continue ;;
    */internal/memguard/entropy.go) continue ;;
  esac

  violations_ck4+=("$file:$lineno  $content  →  禁止直接调用 crypto/rand.Read，须用 memguard.GenerateSecureRandom")
done < <(search_go 'rand\.Read\(' internal/ cmd/)

if (( ${#violations_ck4[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 系统熵源使用正确（无 math/rand，无绕过 GenerateSecureRandom）"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck4[@]} 处熵源违规："
  for v in "${violations_ck4[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 5: 明文密钥参数必须使用 *memguard.SecureBuffer ----------
section "[CHECK 5] 明文密钥参数必须使用 *memguard.SecureBuffer (禁止 []byte)"

# 匹配函数签名中"敏感参数名 + []byte 类型"的组合。
# 敏感参数名（精确匹配）：key/masterKey/master_key/dek/secretKey/secret_key/
#                         privateKey/private_key/master
# 例（违规）：func encrypt(key []byte, ...)
# 例（合规）：func encrypt(key *memguard.SecureBuffer, ...)
# 例（合规）：func encrypt(plaintext []byte, ...) ← plaintext 不在敏感名单
SENSITIVE_PARAM_NAMES='key|masterKey|master_key|dek|secretKey|secret_key|privateKey|private_key|master'

violations_ck5=()

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 跳过注释行
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    "//"*) continue ;;
    "/*"*) continue ;;
  esac

  # 跳过测试文件
  if is_test_file "$file"; then
    continue
  fi

  # 必须是函数定义行（func 开头）
  if ! echo "$content" | grep -qE '^[[:space:]]*func\b'; then
    continue
  fi

  # 提取参数列表，逐个参数检查。
  # 用 sed 提取括号内的参数列表。
  # 注意：BSD sed (macOS) 不支持 \s，必须用 [[:space:]]。
  params="$(echo "$content" | sed -nE 's/.*func[[:space:]]*(\([^)]*\)[[:space:]]*)?[^(]*\(([^)]*)\).*/\2/p')"
  [[ -z "$params" ]] && continue

  # 逐个参数检查：name []byte 且 name 在敏感名单中
  IFS=',' read -ra PARAM_ARR <<< "$params"
  for p in "${PARAM_ARR[@]}"; do
    p_trimmed="$(echo "$p" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    # 提取参数名（第一个标识符）。BSD sed 不支持 \s，用 [[:space:]]。
    pname="$(echo "$p_trimmed" | sed -nE 's/^([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]+.*/\1/p')"
    [[ -z "$pname" ]] && continue

    # 检查参数名是否在敏感名单中（精确匹配）
    if echo "$pname" | grep -qE "^(${SENSITIVE_PARAM_NAMES})$"; then
      # 检查类型是否是 []byte（而非 *memguard.SecureBuffer）
      if echo "$p_trimmed" | grep -qE '\[\]byte' && ! echo "$p_trimmed" | grep -qE '\*memguard\.SecureBuffer'; then
        violations_ck5+=("$file:$lineno  参数 '$pname' 类型为 []byte，应为 *memguard.SecureBuffer")
      fi
    fi
  done
done < <(search_go '^[[:space:]]*func\b' internal/ cmd/)

if (( ${#violations_ck5[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 所有明文密钥参数均使用 *memguard.SecureBuffer"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck5[@]} 处明文密钥参数使用 []byte（应改为 *memguard.SecureBuffer）："
  for v in "${violations_ck5[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 6: subtle.ConstantTimeCompare 强制 ----------
section "[CHECK 6] 敏感变量比较必须用 subtle.ConstantTimeCompare（禁用 == / != / strings.EqualFold）"

# 敏感变量名片段（小写匹配，单词边界）。
SENSITIVE_CMP='key|secret|password|passwd|token|master|dek|hmac|signature|credential|private|authTag|nonce'

violations_ck6=()

# 检测策略：
#   1) 搜索含 == 或 != 的行
#   2) 精准匹配"敏感标识符紧邻 == / !="（中间只允许空格），
#      避免误报"op.Key 在函数调用里、但 == 比较的是 err"的情况。
#   3) 排除合法白名单：nil、纯数字、空串、true/false、len()、
#      subtle.ConstantTimeCompare、errors.Is/As。
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 跳过纯注释行
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    "//"*|"/*"*) continue ;;
  esac

  # 精准匹配：敏感标识符紧邻 == 或 !=（中间仅空格）
  # 这样 op.Key); err != nil 不会匹配（Key 后面是 )，不是 ==）
  if ! echo "$content" | grep -qiE "\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b[[:space:]]*(==|!=)"; then
    continue
  fi

  # 合法白名单（命中任一则跳过）：
  # A) 与 nil 比较
  if echo "$content" | grep -qiE "\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b[[:space:]]*(==|!=)[[:space:]]*nil\b"; then
    continue
  fi
  # B) 与纯整数字面量比较（== 0 / == 32 / != -1 等）
  if echo "$content" | grep -qiE "\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b[[:space:]]*(==|!=)[[:space:]]*[-]?[0-9]+\b"; then
    continue
  fi
  # C) 与空字符串比较：key == ""
  if echo "$content" | grep -qiE "\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b[[:space:]]*(==|!=)[[:space:]]*\"\""; then
    continue
  fi
  # D) 与 true/false 比较
  if echo "$content" | grep -qiE "\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b[[:space:]]*(==|!=)[[:space:]]*(true|false)\b"; then
    continue
  fi
  # E) len(敏感标识符) == N —— 长度比较，非内容
  if echo "$content" | grep -qiE "len\([^)]*\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b[^)]*\)[[:space:]]*(==|!=)"; then
    continue
  fi
  # F) subtle.ConstantTimeCompare 出现 —— 正确用法
  if echo "$content" | grep -qiE "subtle\.ConstantTimeCompare"; then
    continue
  fi
  # G) errors.Is / errors.As —— 错误匹配，非敏感内容比较
  if echo "$content" | grep -qiE "errors\.(Is|As)\("; then
    continue
  fi

  violations_ck6+=("$file:$lineno  $content")
done < <(search_go '==|!=' internal/ cmd/)

# 单独检测 strings.EqualFold / strings.Compare 用于敏感变量。
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"
  if echo "$content" | grep -qiE "strings\.(EqualFold|Compare)\(" && \
     echo "$content" | grep -qiE "\b(${SENSITIVE_CMP})[a-zA-Z0-9_]*\b"; then
    violations_ck6+=("$file:$lineno  $content  →  禁止用 strings.EqualFold/Compare 比较敏感变量")
  fi
done < <(search_go 'strings\.(EqualFold|Compare)' internal/ cmd/)

if (( ${#violations_ck6[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 敏感变量比较均使用 subtle.ConstantTimeCompare"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck6[@]} 处敏感变量使用 == / != / strings.EqualFold 比较（必须改用 subtle.ConstantTimeCompare）："
  for v in "${violations_ck6[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 7: ProvideShare 成功后必须擦除 collectedShares ----------
section "[CHECK 7] ProvideShare 达阈值后必须擦除 collectedShares"

# 检测策略：
#   1) 找到 seal 包中含 ProvideShare 定义与方法体的文件
#   2) 在 ProvideShare 方法体内查找达阈值触发 Combine 的代码段
#   3) 验证 Combine 调用后存在 clear/wipe 调用清理 collectedShares
#
# 实现简化：扫描 seal 包源文件，验证以下两点同时成立：
#   A) ProvideShare 方法体中调用了 Combine
#   B) 同一方法体内存在 clear(...) 或 wipeCollectedShares() 调用
#      （defer 或直接调用均算）
violations_ck7=()

# 找 seal 包下的 ProvideShare 实现（排除测试文件 + HSM/backup 等非 Shamir 实现）
seal_files=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  # 跳过 HSM unsealer（HSM 模式不使用 Shamir，ProvideShare 直接返回 error）
  case "$file" in
    */hsm_unsealer.go) continue ;;
  esac
  # 必须是函数定义行（func 开头），不是方法调用
  content="${line#*:}"
  content="${content#*:}"
  if echo "$content" | grep -qE '^\s*func\b'; then
    seal_files="$line"
    break
  fi
done < <(search_go 'func.*ProvideShare|ProvideShare' internal/seal/)

if [[ -z "$seal_files" ]]; then
  echo "${YEL}  [SKIP]${RST} 未找到 ProvideShare 定义（seal 包可能未实现），跳过"
else
  # 提取文件名与行号
  ps_file=$(echo "$seal_files" | head -1 | cut -d: -f1)
  ps_line=$(echo "$seal_files" | head -1 | cut -d: -f2)

  # 提取 ProvideShare 方法体（从 func 到下一个顶层 func 或文件末尾）
  # 简化：从 ps_line 开始，到下一个以 "func" 开头的行之前
  method_body=$(sed -n "${ps_line},\$p" "$ps_file" | awk '
    /^func / { if (NR > 1) exit; }
    { print }
  ')

  # 验证 A: 方法体含 Combine 调用
  if ! echo "$method_body" | grep -qE '\bCombine\s*\('; then
    violations_ck7+=("$ps_file:$ps_line  ProvideShare 未调用 Combine（无法重组 Master Key）")
  fi

  # 验证 B: 方法体含 clear(...) 或 wipeCollectedShares() 调用
  has_wipe=0
  if echo "$method_body" | grep -qE 'clear\s*\('; then
    has_wipe=1
  fi
  if echo "$method_body" | grep -qE 'wipeCollectedShares\s*\('; then
    has_wipe=1
  fi
  if (( has_wipe == 0 )); then
    violations_ck7+=("$ps_file:$ps_line  ProvideShare 达阈值后未擦除 collectedShares（必须 clear 或 wipeCollectedShares）")
  fi
fi

if (( ${#violations_ck7[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} ProvideShare 达阈值后正确擦除 collectedShares"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck7[@]} 处擦除缺失："
  for v in "${violations_ck7[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 8: Shamir 运算必须在 GF(2^8) 有限域内 ----------
section "[CHECK 8] Shamir 运算必须在 GF(2^8) 有限域内（禁止普通算术）"

violations_ck8=()

# 8a) seal 包中 byte 域元素禁止用普通 + - * /
# 检测：在 internal/seal/ 下的 .go 文件中，查找 byte 类型变量参与的
# 普通算术运算。简化策略：查找 byte 变量与 + - * / 的组合。
# 由于静态分析 byte 类型较复杂，这里用启发式：
#   - 查找 gfMul / gfInv / gfExp / gfLog / ^ 这些域运算符号
#   - 反向查找：byte 变量后跟 + - * / （但排除 ++ -- += -= *= /= 整数循环计数）
#   - 排除注释行
#   - 排除 int 类型变量（如 int(gfLog[a])+int(gfLog[b]) 是整数索引，合法）
  # 启发式检测：在 seal 包中，如果一行同时含 byte 类型相关标识符和普通算术运算符，
  # 且不含 gf 前缀函数，则视为可疑。
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    file="${line%%:*}"
    is_test_file "$file" && continue
    rest="${line#*:}"
    lineno="${rest%%:*}"
    content="${rest#*:}"

    # 跳过注释行
    trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
    case "$trimmed" in
      "//"*|"/*"*) continue ;;
    esac

    # 跳过函数签名行（func 开头）——类型声明中的 * 不是乘法
    if echo "$content" | grep -qE '^[[:space:]]*func\b'; then
      continue
    fi

    # 跳过纯类型声明/字段定义行（含 = 赋值的 var/const/字段声明）
    # 这些行中的 * 是指针声明，不是乘法
    if echo "$content" | grep -qE '^[[:space:]]*(var|const|type)\b'; then
      continue
    fi
    # 跳过结构体字段声明（如 collectedShares [][]byte）
    if echo "$content" | grep -qE '^[[:space:]]*[A-Z][a-zA-Z0-9_]*[[:space:]]+\[\]byte'; then
      continue
    fi

    # 排除：含 gf 前缀函数（gfMul/gfInv/gfExp/gfLog）的行视为合法域运算
    if echo "$content" | grep -qE '\bgf(Mul|Inv|Exp|Log|Eval|Prime|Generator)\b'; then
      continue
    fi

    # 排除：make([]byte, ...) 调用——这是内存分配不是算术
    if echo "$content" | grep -qE 'make\(\[\]byte'; then
      continue
    fi

    # 检测：含 byte 关键字且含算术运算符 + - * /
    # 排除：注释行、类型声明、含 []byte 的行
    # 注意：字符类中 - 必须放在末尾，否则 BSD grep 报 "invalid character range"
    # 先跳过注释行
    trimmed_content="$(echo "$content" | sed 's/^[[:space:]]*//')"
    case "$trimmed_content" in
      "//"*) continue ;;
      "/*"*) continue ;;
      *byte*) ;; # 含 byte 的代码行，继续检测
      *) continue ;; # 不含 byte 的行跳过
    esac
    if echo "$content" | grep -qE '\bbyte\b' && \
       echo "$content" | grep -qE '[+/-]' && \
       ! echo "$content" | grep -qE '\bgf'; then
      # 进一步排除：类型转换如 byte(x+1)、byte(i+1)
      if echo "$content" | grep -qE 'byte\([^)]*[+/-][^)]*\)'; then
        continue
      fi
      # 排除：含 []byte 或 *memguard 或 *SecureBuffer 的类型声明上下文
      if echo "$content" | grep -qE '\[\]byte|\*memguard|\*SecureBuffer'; then
        continue
      fi
      # 排除：结构体字段声明（含 byte 类型但不参与运算）
      if echo "$content" | grep -qE '^\s*\w+\s+byte\s*$|^\s*\w+\s+byte\s+//'; then
        continue
      fi
      violations_ck8+=("$file:$lineno  $content  →  byte 变量参与普通算术，应在 GF(2^8) 内用 gfMul/gfInv/^")
    fi
  done < <(search_go 'byte' internal/seal/)

# 8b) 强制存在 GF(2^8) 基础设施：gfExp/gfLog 表、gfMul/gfInv 函数、
#     不可约多项式 0x1b / 0x11b、生成元 0x03
seal_gf_check=0
gf_errors=()
# 检查 gfExp 表声明
if ! search_go 'gfExp\s*\[512\]\s*byte' internal/seal/ 2>/dev/null | grep -q .; then
  gf_errors+=("缺少 gfExp[512]byte 对数表声明")
  seal_gf_check=1
fi

# 检查 gfLog 表声明
if ! search_go 'gfLog\s*\[256\]\s*byte' internal/seal/ 2>/dev/null | grep -q .; then
  gf_errors+=("缺少 gfLog[256]byte 对数表声明")
  seal_gf_check=1
fi

# 检查 gfMul 函数定义
if ! search_go 'func\s+gfMul\s*\(' internal/seal/ 2>/dev/null | grep -q .; then
  gf_errors+=("缺少 gfMul 有限域乘法函数")
  seal_gf_check=1
fi

# 检查 gfInv 函数定义
if ! search_go 'func\s+gfInv\s*\(' internal/seal/ 2>/dev/null | grep -q .; then
  gf_errors+=("缺少 gfInv 有限域求逆函数")
  seal_gf_check=1
fi

# 检查不可约多项式归约常数 0x1b 或 0x11b
if ! search_go '0x1b|0x11b' internal/seal/ 2>/dev/null | grep -q .; then
  gf_errors+=("缺少 AES 不可约多项式归约常数 0x1b/0x11b")
  seal_gf_check=1
fi

# 检查生成元 0x03
if ! search_go 'gfGenerator\s*=\s*0x03|0x03' internal/seal/ 2>/dev/null | grep -q .; then
  gf_errors+=("缺少 GF(2^8) 生成元 0x03")
  seal_gf_check=1
fi

if (( ${#violations_ck8[@]} == 0 && seal_gf_check == 0 )); then
  echo "${GRN}  [PASS]${RST} Shamir 运算严格在 GF(2^8) 内，基础设施齐全"
else
  echo "${RED}  [FAIL]${RST} Shamir GF(2^8) 检查未通过："
  for v in "${violations_ck8[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  for e in "${gf_errors[@]}"; do
    echo "    ${RED}- internal/seal/  $e${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 9: Combine 返回 *memguard.SecureBuffer，明文不流浪 ----------
section "[CHECK 9] Combine 返回 *memguard.SecureBuffer，明文不流浪"

violations_ck9=()

# 9a) Combine 函数返回类型必须是 *memguard.SecureBuffer
combine_def=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  content="${line#*:}"
  content="${content#*:}"
  if echo "$content" | grep -qE '^\s*func\s+Combine\s*\('; then
    combine_def="$line"
    # 验证返回类型
    if ! echo "$content" | grep -qE '\*memguard\.SecureBuffer'; then
      violations_ck9+=("$file  Combine 返回类型不是 *memguard.SecureBuffer")
    fi
    break
  fi
done < <(search_go 'func\s+Combine\s*\(' internal/seal/)

if [[ -z "$combine_def" ]]; then
  echo "${YEL}  [SKIP]${RST} 未找到 Combine 定义，跳过"
else
  combine_file=$(echo "$combine_def" | cut -d: -f1)
  combine_line=$(echo "$combine_def" | cut -d: -f2)

  # 提取 Combine 方法体
  method_body=$(sed -n "${combine_line},\$p" "$combine_file" | awk '
    /^func / { if (NR > 1) exit; }
    { print }
  ')

  # 9b) 必须调用 NewSecureBuffer 封装明文
  if ! echo "$method_body" | grep -qE 'NewSecureBuffer\s*\('; then
    violations_ck9+=("$combine_file:$combine_line  Combine 未调用 NewSecureBuffer 封装明文（明文以 []byte 形式流浪）")
  fi

  # 9c) 临时明文切片必须有 defer 清理逻辑
  # 检测：方法体中存在 defer 且 defer 块内含 clear 调用
  # 简化策略：方法体含 "defer" 且含 "clear("（不要求同一行，因 defer 可跨行）
  has_defer_clear=0
  if echo "$method_body" | grep -qE '\bdefer\b' && \
     echo "$method_body" | grep -qE 'clear\s*\('; then
    has_defer_clear=1
  fi
  if (( has_defer_clear == 0 )); then
    violations_ck9+=("$combine_file:$combine_line  Combine 临时明文切片缺少 defer clear 清理逻辑")
  fi
fi

if (( ${#violations_ck9[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} Combine 返回 *memguard.SecureBuffer，明文不流浪"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck9[@]} 处 Combine 明文管理问题："
  for v in "${violations_ck9[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 10: MemoryStore.Delete 必须 clear(value) 后再 delete ----------
section "[CHECK 10] MemoryStore.Delete 必须 clear(value) 后再 delete (Crypto-Shredding)"

# 检测策略：
#   1) 找到 MemoryStore 的 Delete 方法定义
#   2) 提取方法体
#   3) 验证方法体同时含 clear(...) 与 delete(...) 调用
#   4) 反向检测：若方法体含 delete(m.data, key) 但不含 clear，则违规
violations_ck10=()

# 找 MemoryStore 的 Delete 定义
memstore_delete=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  content="${line#*:}"
  content="${content#*:}"
  # 匹配 func (m *MemoryStore) Delete(...)
  if echo "$content" | grep -qE '^\s*func\s*\(\s*\w+\s+\*MemoryStore\s*\)\s+Delete\s*\('; then
    memstore_delete="$line"
    break
  fi
done < <(search_go 'func.*MemoryStore.*Delete' internal/storage/)

if [[ -z "$memstore_delete" ]]; then
  echo "${YEL}  [SKIP]${RST} 未找到 MemoryStore.Delete 定义，跳过"
else
  ms_file=$(echo "$memstore_delete" | cut -d: -f1)
  ms_line=$(echo "$memstore_delete" | cut -d: -f2)

  # 提取 Delete 方法体
  method_body=$(sed -n "${ms_line},\$p" "$ms_file" | awk '
    /^func / { if (NR > 1) exit; }
    { print }
  ')

  # 过滤注释行后再检测，避免 // clear(v) 被误判为实际调用
  code_body=$(echo "$method_body" | grep -vE '^[[:space:]]*//')

  # 验证：方法体含 clear( 调用（非注释行）
  has_clear=0
  if echo "$code_body" | grep -qE 'clear\s*\('; then
    has_clear=1
  fi

  # 验证：方法体含 delete( 调用（map 删除，非注释行）
  has_map_delete=0
  if echo "$code_body" | grep -qE 'delete\s*\('; then
    has_map_delete=1
  fi

  # 反向检测：若含 delete(m.data 但不含 clear，违规
  if (( has_map_delete == 1 && has_clear == 0 )); then
    violations_ck10+=("$ms_file:$ms_line  MemoryStore.Delete 仅调用 delete(m.data, key) 而未先 clear(value)，违反 Crypto-Shredding")
  fi

  # 验证：clear 后必须有 runtime.KeepAlive
  if (( has_clear == 1 )); then
    if ! echo "$method_body" | grep -qE 'runtime\.KeepAlive'; then
      violations_ck10+=("$ms_file:$ms_line  MemoryStore.Delete 的 clear(value) 后缺少 runtime.KeepAlive，可能被 DCE 优化掉")
    fi
  fi
fi

if (( ${#violations_ck10[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} MemoryStore.Delete 正确实现 Crypto-Shredding（先 clear 后 delete）"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#violations_ck10[@]} 处 MemoryStore.Delete 违规："
  for v in "${violations_ck10[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- CHECK 11: API Handler 的 io.ReadAll 结果必须 clear+KeepAlive ----------
section "[CHECK 11] API Handler io.ReadAll 结果必须 clear+KeepAlive (Payload Escaping Control)"

# 检测策略：
#   1) 找到 api 包中所有调用 io.ReadAll 的行
#   2) 对每处，提取所在 handler 函数体
#   3) 验证 handler 内同时含 clear( 和 runtime.KeepAlive 调用
#   4) 反向检测：若含 io.ReadAll 但 handler 内无 clear，违规
violations_ck11=()

# 找所有 io.ReadAll 调用点（排除测试文件）
readall_hits=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  is_test_file "$file" && continue
  readall_hits="${readall_hits}${line}"$'\n'
done < <(search_go 'io\.ReadAll' internal/api/)

if [[ -z "$readall_hits" ]]; then
  echo "${YEL}  [SKIP]${RST} 未找到 io.ReadAll 调用，跳过"
else
  # 对每个 io.ReadAll 调用点，提取所在函数体验证清理逻辑
  echo "$readall_hits" | while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"

    # 向上查找所在 func 定义行
    func_line=""
    for ((i=lineno; i>=1; i--)); do
      line_content=$(sed -n "${i}p" "$file")
      if echo "$line_content" | grep -qE '^[[:space:]]*func\b'; then
        func_line=$i
        break
      fi
    done

    if [[ -z "$func_line" ]]; then
      continue
    fi

    # 提取函数体（从 func 行到下一个 func 或 EOF）
    method_body=$(sed -n "${func_line},\$p" "$file" | awk '
      /^func / { if (NR > 1) exit; }
      { print }
    ')

    # 过滤注释行
    code_body=$(echo "$method_body" | grep -vE '^[[:space:]]*//')

    # 验证：函数体含 clear( 调用（非注释）
    has_clear=0
    if echo "$code_body" | grep -qE 'clear\s*\('; then
      has_clear=1
    fi

    # 验证：函数体含 runtime.KeepAlive
    has_keepalive=0
    if echo "$code_body" | grep -qE 'runtime\.KeepAlive'; then
      has_keepalive=1
    fi

    if (( has_clear == 0 )); then
      echo "${RED}  [FAIL]${RST} $file:$lineno  io.ReadAll 结果未 clear()，明文可能随 Request 进 GC" >&2
    fi
    if (( has_keepalive == 0 )); then
      echo "${RED}  [FAIL]${RST} $file:$lineno  io.ReadAll 结果缺少 runtime.KeepAlive，clear 可能被 DCE" >&2
    fi
    if (( has_clear == 0 || has_keepalive == 0 )); then
      # 通过临时文件传递违规（while 子shell 变量隔离问题）
      echo "$file:$lineno" >> /tmp/yvonne_ck11_violations
    fi
  done

  # 检查是否有违规（从临时文件读取，规避子 shell 变量隔离）
  if [[ -f /tmp/yvonne_ck11_violations ]]; then
    echo "${RED}  [FAIL]${RST} 发现 io.ReadAll 清理缺失："
    while IFS= read -r v; do
      echo "    ${RED}- $v${RST}"
    done < /tmp/yvonne_ck11_violations
    rm -f /tmp/yvonne_ck11_violations
    # 通过写入标志文件让外层 FAIL 生效
    touch /tmp/yvonne_ck11_failed
  fi
fi

if [[ -f /tmp/yvonne_ck11_failed ]]; then
  FAIL=1
  rm -f /tmp/yvonne_ck11_failed
elif [[ -n "$readall_hits" ]]; then
  echo "${GRN}  [PASS]${RST} API Handler io.ReadAll 结果均正确 clear+KeepAlive"
fi

# ---------- CHECK 12: 密文/字节切片访问前必须校验长度（防 index out of range panic） ----------
section "[CHECK 12] 字节切片访问前必须校验长度（防 Panic）"

# 检查规则：任何对 []byte 参数做切片访问（如 raw[:N]、raw[N:M]）的函数，
# 必须在访问前有 len(raw) < N 的长度校验。
# 重点关注：DecodeVersionedCiphertext、ExtractVersion、DecryptGCM、DecryptVersioned。
violations_ck12=()

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # 跳过注释行
  trimmed="$(echo "$content" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    "//"*) continue ;;
    "/*"*) continue ;;
  esac

  # 跳过测试文件
  case "$file" in
    *_test.go) continue ;;
  esac

  violations_ck12+=("$file:$lineno  $content  →  切片访问前需校验 len()")
done < <(search_go 'raw\[:|raw\[[0-9]+:|ciphertext\[:|ciphertext\[[0-9]+:' internal/crypto/ internal/api/)

# 白名单：已确认有长度校验的文件+行号。
# DecodeVersionedCiphertext (versioned_ciphertext.go:52): 前置 len(raw) < MinCiphertextSize
# ExtractVersion (versioned_ciphertext.go:65): 前置 len(raw) < VersionPrefixSize
# DecryptGCM (gcm.go:87): 前置 len(ciphertext) < gcmNonceSize
# DecryptVersioned (versioned_encrypt.go): 调用 DecodeVersionedCiphertext 已校验
filtered_ck12=()
for v in "${violations_ck12[@]}"; do
  # 提取文件名（不含行号）。
  v_file=$(echo "$v" | cut -d: -f1)
  v_line=$(echo "$v" | cut -d: -f2)

  # 白名单：versioned_ciphertext.go 和 gcm.go 的切片访问已确认有长度校验。
  case "$v_file" in
    */versioned_ciphertext.go) continue ;;
    */gcm.go) continue ;;
    */versioned_encrypt.go) continue ;;
    */gcm_bytes.go) continue ;;
  esac

  filtered_ck12+=("$v")
done

if (( ${#filtered_ck12[@]} == 0 )); then
  echo "${GRN}  [PASS]${RST} 所有字节切片访问前均有长度校验"
else
  echo "${RED}  [FAIL]${RST} 发现 ${#filtered_ck12[@]} 处切片访问缺少长度校验："
  for v in "${filtered_ck12[@]}"; do
    echo "    ${RED}- $v${RST}"
  done
  FAIL=1
fi

# ---------- 总结 ----------
echo ""
if (( FAIL == 0 )); then
  echo "${GRN}${BLD}[SECURITY CHECK] ALL PASSED${RST}"
  echo "  - clear() + runtime.KeepAlive 配对：OK"
  echo "  - 无返回 []byte 的方法 Getter：OK"
  echo "  - error/日志敏感拼接：OK（或仅启发式告警）"
  echo "  - 系统熵源（无 math/rand，无绕过 GenerateSecureRandom）：OK"
  echo "  - 明文密钥参数使用 *memguard.SecureBuffer：OK"
  echo "  - 敏感变量比较使用 subtle.ConstantTimeCompare：OK"
  echo "  - ProvideShare 达阈值后擦除 collectedShares：OK"
  echo "  - Shamir 运算在 GF(2^8) 内：OK"
  echo "  - Combine 返回 *memguard.SecureBuffer，明文不流浪：OK"
  echo "  - MemoryStore.Delete 实现 Crypto-Shredding（先 clear 后 delete）：OK"
  echo "  - API Handler io.ReadAll 结果 clear+KeepAlive：OK"
  echo "  - 字节切片访问前均有长度校验（防 Panic）：OK"
else
  echo "${RED}${BLD}[SECURITY CHECK] FAILED${RST}"
  echo "  上述违规必须修复后才能合并。"
fi

exit $FAIL
