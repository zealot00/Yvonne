// Package main - CLI 辅助功能（completion + demo + dashboard）。
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// 包级变量（可被测试 mock）。
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
	osExit           = os.Exit
)

// runCompletionCmd 生成 shell 补全脚本。
func runCompletionCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: yvonne completion <bash|zsh|fish>")
		osExit(1)
	}
	shell := args[0]
	switch shell {
	case "bash":
		fmt.Fprint(stdout, bashCompletion)
	case "zsh":
		fmt.Fprint(stdout, zshCompletion)
	case "fish":
		fmt.Fprint(stdout, fishCompletion)
	default:
		fmt.Fprintf(stderr, "unsupported shell: %s (use bash|zsh|fish)\n", shell)
		osExit(1)
	}
}

// runDemoSetup 启动后等待 server 就绪，创建演示密钥并打印 curl 示例。
func runDemoSetup(addr string, port int) {
	baseURL := fmt.Sprintf("http://%s:%d", addr, port)

	// 等待 server 就绪。
	for i := 0; i < 30; i++ {
		resp, err := http.Get(baseURL + "/api/v1/sys/health")
		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
		if i == 29 {
			log.Printf("--demo: server not ready after 15s, skipping demo setup")
			return
		}
	}

	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│  🧊 Yvonne KMS Demo Setup                                   │")
	fmt.Println("│  自动创建演示密钥 + 打印 curl 示例                           │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// 创建演示密钥（Dev 模式无认证）。
	demoKeys := []string{"demo-order-key", "demo-payment-key", "demo-user-key"}
	for _, keyID := range demoKeys {
		createDemoKey(baseURL, keyID)
	}

	// 加密示例。
	plaintext := base64.StdEncoding.EncodeToString([]byte("Hello Yvonne!"))
	ct := encryptDemo(baseURL, "demo-order-key", plaintext)

	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│  📋 Quick Start Examples (copy & paste)                     │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Printf("  # 健康检查\n")
	fmt.Printf("  curl %s/api/v1/sys/health | jq .\n\n", baseURL)
	fmt.Printf("  # 加密\n")
	fmt.Printf("  curl -X POST %s/api/v1/encrypt \\\n", baseURL)
	fmt.Printf("    -H 'Content-Type: application/json' \\\n")
	fmt.Printf("    -d '{\"key_id\":\"demo-order-key\",\"plaintext\":\"%s\"}' | jq .\n\n", plaintext)
	fmt.Printf("  # 解密\n")
	fmt.Printf("  curl -X POST %s/api/v1/decrypt \\\n", baseURL)
	fmt.Printf("    -H 'Content-Type: application/json' \\\n")
	fmt.Printf("    -d '{\"key_id\":\"demo-order-key\",\"ciphertext\":\"%s\"}' | jq .\n\n", ct)
	fmt.Printf("  # 轮转密钥\n")
	fmt.Printf("  curl -X POST %s/api/v1/keys/demo-order-key/rotate | jq .\n\n", baseURL)
	fmt.Printf("  # 列出密钥（Admin UI）\n")
	fmt.Printf("  open http://127.0.0.1:8250\n\n")
	fmt.Printf("  # Go SDK\n")
	fmt.Printf("  client := yvonne.New(\"%s\", \"\")\n", baseURL)
	fmt.Printf("  resp, _ := client.Encrypt(ctx, &yvonne.EncryptRequest{\n")
	fmt.Printf("      KeyID: \"demo-order-key\",\n")
	fmt.Printf("      Plaintext: []byte(\"secret\"),\n")
	fmt.Printf("  })\n\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

func createDemoKey(baseURL, keyID string) {
	body := fmt.Sprintf(`{"key_id":"%s"}`, keyID)
	resp, err := http.Post(baseURL+"/api/v1/keys", "application/json", stringReader(body))
	if err != nil {
		log.Printf("--demo: create %s failed: %v", keyID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		fmt.Printf("  ✅ Created demo key: %s\n", keyID)
	} else {
		data, _ := io.ReadAll(resp.Body)
		log.Printf("--demo: create %s: HTTP %d: %s", keyID, resp.StatusCode, string(data))
	}
}

func encryptDemo(baseURL, keyID, plaintextB64 string) string {
	body := fmt.Sprintf(`{"key_id":"%s","plaintext":"%s"}`, keyID, plaintextB64)
	resp, err := http.Post(baseURL+"/api/v1/encrypt", "application/json", stringReader(body))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	// 简化：从 JSON 提取 ciphertext（不引 encoding/json 避免结构体定义）。
	return extractJSONField(string(data), "ciphertext")
}

// runDashboard 启动后打开浏览器到 Admin UI。
func runDashboard(port int) {
	adminURL := fmt.Sprintf("http://127.0.0.1:8250")

	// 等待 Admin UI 就绪。
	for i := 0; i < 20; i++ {
		resp, err := http.Get(adminURL)
		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
		if i == 19 {
			log.Printf("--dashboard: admin UI not ready, skipping browser open")
			return
		}
	}

	fmt.Printf("\n🌐 Opening Admin UI: %s\n\n", adminURL)
	openBrowser(adminURL)
}

// openBrowser 跨平台打开浏览器。
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		log.Printf("--dashboard: unsupported OS: %s", runtime.GOOS)
		return
	}
	if err := cmd.Run(); err != nil {
		log.Printf("--dashboard: open browser failed: %v", err)
	}
}

// stringReader 从 string 创建 io.Reader（避免 import strings.NewReader 冲突）。
func stringReader(s string) io.Reader {
	return &stringReaderImpl{s: s}
}

type stringReaderImpl struct {
	s   string
	pos int
}

func (r *stringReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}

// extractJSONField 简易 JSON 字段提取（避免 import encoding/json）。
func extractJSONField(json, field string) string {
	key := "\"" + field + "\":\""
	idx := indexOf(json, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := indexOf(json[start:], "\"")
	if end < 0 {
		return ""
	}
	return json[start : start+end]
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// === Shell 补全脚本 ===

const bashCompletion = `# Bash completion for yvonne
_yvonne() {
    local cur prev words cword
    _init_completion || return

    local commands="server dev unseal-keygen init backup-split backup-restore audit-verify completion help"

    if [ $cword -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return
    fi

    case ${words[1]} in
        server)
            COMPREPLY=( $(compgen -f -- "$cur") )
            ;;
        dev)
            if [[ "$cur" == --* ]]; then
                COMPREPLY=( $(compgen -W "--port --addr --demo --dashboard" -- "$cur") )
            fi
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            ;;
        unseal-keygen|init|backup-split|backup-restore|audit-verify)
            COMPREPLY=( $(compgen -f -- "$cur") )
            ;;
    esac
}
complete -F _yvonne yvonne
`

const zshCompletion = `#compdef yvonne
# Zsh completion for yvonne
_yvonne() {
    local -a commands
    commands=(
        'server:Start with config file'
        'dev:Quick dev mode'
        'unseal-keygen:Generate RSA key pair'
        'init:Initialize CMK'
        'backup-split:Split wrapped CMK into Shamir shares'
        'backup-restore:Restore wrapped CMK'
        'audit-verify:Verify audit log'
        'completion:Generate shell completion'
    )

    if (( CURRENT == 2 )); then
        _describe 'command' commands
        return
    fi

    case $words[2] in
        dev)
            _arguments '--port[port]:port:' '--addr[address]:addr:' '--demo[demo mode]' '--dashboard[open browser]'
            ;;
        completion)
            _values 'shell' bash zsh fish
            ;;
        server|unseal-keygen|init|backup-split|backup-restore|audit-verify)
            _files
            ;;
    esac
}
_yvonne "$@"
`

const fishCompletion = `# Fish completion for yvonne
complete -c yvonne -n "__fish_use_subcommand" -a "server" -d "Start with config file"
complete -c yvonne -n "__fish_use_subcommand" -a "dev" -d "Quick dev mode"
complete -c yvonne -n "__fish_use_subcommand" -a "unseal-keygen" -d "Generate RSA key pair"
complete -c yvonne -n "__fish_use_subcommand" -a "init" -d "Initialize CMK"
complete -c yvonne -n "__fish_use_subcommand" -a "backup-split" -d "Split wrapped CMK"
complete -c yvonne -n "__fish_use_subcommand" -a "backup-restore" -d "Restore wrapped CMK"
complete -c yvonne -n "__fish_use_subcommand" -a "audit-verify" -d "Verify audit log"
complete -c yvonne -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion"

complete -c yvonne -n "__fish_seen_subcommand_from dev" -l port -d "Bind port"
complete -c yvonne -n "__fish_seen_subcommand_from dev" -l addr -d "Bind address"
complete -c yvonne -n "__fish_seen_subcommand_from dev" -l demo -d "Auto-create demo keys"
complete -c yvonne -n "__fish_seen_subcommand_from dev" -l dashboard -d "Open browser"

complete -c yvonne -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
`
