package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunCompletionCmd_Bash 验证 bash 补全脚本生成。
func TestRunCompletionCmd_Bash(t *testing.T) {
	// 捕获 stdout。
	old := stdout
	var buf bytes.Buffer
	stdout = &buf
	defer func() { stdout = old }()

	runCompletionCmd([]string{"bash"})
	output := buf.String()
	if !strings.Contains(output, "_yvonne()") {
		t.Fatal("bash completion should contain _yvonne()")
	}
	if !strings.Contains(output, "complete -F _yvonne yvonne") {
		t.Fatal("bash completion should contain complete command")
	}
}

// TestRunCompletionCmd_Zsh 验证 zsh 补全脚本生成。
func TestRunCompletionCmd_Zsh(t *testing.T) {
	old := stdout
	var buf bytes.Buffer
	stdout = &buf
	defer func() { stdout = old }()

	runCompletionCmd([]string{"zsh"})
	output := buf.String()
	if !strings.Contains(output, "#compdef yvonne") {
		t.Fatal("zsh completion should contain #compdef")
	}
}

// TestRunCompletionCmd_Fish 验证 fish 补全脚本生成。
func TestRunCompletionCmd_Fish(t *testing.T) {
	old := stdout
	var buf bytes.Buffer
	stdout = &buf
	defer func() { stdout = old }()

	runCompletionCmd([]string{"fish"})
	output := buf.String()
	if !strings.Contains(output, "complete -c yvonne") {
		t.Fatal("fish completion should contain complete -c")
	}
}

// TestRunCompletionCmd_Invalid 无效 shell 退出。
func TestRunCompletionCmd_Invalid(t *testing.T) {
	old := stderr
	var buf bytes.Buffer
	stderr = &buf
	defer func() { stderr = old }()

	exitCalled := false
	oldExit := osExit
	osExit = func(code int) { exitCalled = true }
	defer func() { osExit = oldExit }()

	runCompletionCmd([]string{"powershell"})
	if !exitCalled {
		t.Fatal("invalid shell should call exit")
	}
}

// TestExtractJSONField 从 JSON 提取字段值。
func TestExtractJSONField(t *testing.T) {
	json := `{"ok":true,"data":{"ciphertext":"AQAA123456","version":1}}`

	got := extractJSONField(json, "ciphertext")
	if got != "AQAA123456" {
		t.Fatalf("extractJSONField ciphertext = %q, want AQAA123456", got)
	}

	// version 是 int（无引号），extractJSONField 仅匹配字符串值。
	// 不存在的字段。
	got = extractJSONField(json, "nonexistent")
	if got != "" {
		t.Fatalf("nonexistent field should return empty, got %q", got)
	}

	// 嵌套字段。
	json2 := `{"key":"value","nested":{"inner":"found"}}`
	got = extractJSONField(json2, "inner")
	if got != "found" {
		t.Fatalf("extractJSONField inner = %q, want found", got)
	}
}

// TestIndexOf 字符串查找。
func TestIndexOf(t *testing.T) {
	if idx := indexOf("hello world", "world"); idx != 6 {
		t.Fatalf("indexOf = %d, want 6", idx)
	}
	if idx := indexOf("hello", "xyz"); idx != -1 {
		t.Fatalf("indexOf not found = %d, want -1", idx)
	}
	if idx := indexOf("abc", ""); idx != 0 {
		t.Fatalf("indexOf empty = %d, want 0", idx)
	}
}

// TestStringReader 读取字符串。
func TestStringReader(t *testing.T) {
	r := stringReader("hello")
	buf := make([]byte, 5)
	n, err := r.Read(buf)
	if n != 5 || err != nil {
		t.Fatalf("Read: n=%d err=%v", n, err)
	}
	if string(buf) != "hello" {
		t.Fatalf("buf = %q", string(buf))
	}

	// 再读应返回 EOF。
	_, err = r.Read(buf)
	if err.Error() != "EOF" {
		t.Fatalf("second Read err = %v, want EOF", err)
	}
}
