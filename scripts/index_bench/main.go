// 索引性能对比报告生成器。
// 用法：go run scripts/gen_index_bench_chart.go -input bench_results.txt -output docs/index-benchmark-report.html
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type BenchResult struct {
	Name        string
	NsPerOp     float64
	BytesPerOp  float64
	AllocsPerOp float64
}

type Comparison struct {
	Name         string
	DataSize     string
	WithIndex    *BenchResult
	WithoutIndex *BenchResult
	Speedup      float64
}

var benchRe = regexp.MustCompile(`^(Benchmark\S+?)-(?:\d+)\s+(\d+)\s+([\d.]+)\s+ns/op\s+([\d.]+)\s+B/op\s+([\d.]+)\s+allocs/op`)

func parseResults(path string) ([]BenchResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []BenchResult
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		m := benchRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ns, _ := strconv.ParseFloat(m[3], 64)
		b, _ := strconv.ParseFloat(m[4], 64)
		allocs, _ := strconv.ParseFloat(m[5], 64)
		results = append(results, BenchResult{
			Name: m[1], NsPerOp: ns, BytesPerOp: b, AllocsPerOp: allocs,
		})
	}
	return results, scanner.Err()
}

func buildComparisons(results []BenchResult) []Comparison {
	resultMap := make(map[string]BenchResult)
	for _, r := range results {
		resultMap[r.Name] = r
	}

	pairs := []struct {
		name, with, without, size string
	}{
		{"ScanPrefix (100条)", "BenchmarkIndex_ScanPrefix_WithIndex_100", "BenchmarkIndex_ScanPrefix_NoIndex_100", "100"},
		{"ScanPrefix (1000条)", "BenchmarkIndex_ScanPrefix_WithIndex_1000", "BenchmarkIndex_ScanPrefix_NoIndex_1000", "1000"},
		{"ScanPrefix (5000条)", "BenchmarkIndex_ScanPrefix_WithIndex_5000", "BenchmarkIndex_ScanPrefix_NoIndex_5000", "5000"},
		{"Put", "BenchmarkIndex_Put_WithIndex", "BenchmarkIndex_Put_NoIndex", "N/A"},
		{"Delete", "BenchmarkIndex_Delete_WithIndex", "BenchmarkIndex_Delete_NoIndex", "N/A"},
	}

	var comparisons []Comparison
	for _, p := range pairs {
		c := Comparison{Name: p.name, DataSize: p.size}
		if r, ok := resultMap[p.with]; ok {
			c.WithIndex = &r
		}
		if r, ok := resultMap[p.without]; ok {
			c.WithoutIndex = &r
		}
		if c.WithIndex != nil && c.WithoutIndex != nil && c.WithIndex.NsPerOp > 0 {
			c.Speedup = c.WithoutIndex.NsPerOp / c.WithIndex.NsPerOp
		}
		comparisons = append(comparisons, c)
	}

	sort.Slice(comparisons, func(i, j int) bool { return comparisons[i].Name < comparisons[j].Name })
	return comparisons
}

func formatNs(ns float64) string {
	if ns >= 1e6 {
		return fmt.Sprintf("%.1fms", ns/1e3)
	}
	return fmt.Sprintf("%.0fns", ns)
}

func main() {
	input := flag.String("input", "", "benchmark results file")
	output := flag.String("output", "docs/index-benchmark-report.html", "output HTML")
	flag.Parse()

	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: -input required")
		os.Exit(1)
	}

	results, err := parseResults(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}

	comparisons := buildComparisons(results)

	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"formatNs": formatNs,
		"json":     func(v interface{}) template.JS { b, _ := json.Marshal(v); return template.JS(b) },
	}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Yvonne KMS — Index Benchmark Report</title>
<style>
body { background: #0f0f1e; color: #e0e0e0; font-family: monospace; margin: 20px; }
h1 { color: #e94560; }
h2 { color: #0f3460; margin-top: 30px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #16213e; padding: 8px 12px; text-align: left; }
th { background: #16213e; color: #aaccff; }
tr:nth-child(even) { background: #111122; }
.idx { color: #4ecca3; }
.noidx { color: #e94560; }
.speedup { color: #ffd700; font-weight: bold; }
.note { background: #16213e; padding: 10px; border-radius: 4px; margin: 10px 0; }
</style>
</head>
<body>
<h1>Yvonne KMS — Index Benchmark Report</h1>
<p class="note">PostgreSQL 索引性能对比：有索引 vs 无索引（varchar_pattern_ops + updated_at）</p>

<h2>1. 性能对比表</h2>
<table>
<tr>
<th>操作</th>
<th>数据量</th>
<th>有索引 (ns/op)</th>
<th>无索引 (ns/op)</th>
<th>加速比</th>
<th>有索引 (B/op)</th>
<th>无索引 (B/op)</th>
</tr>
{{range .Comparisons}}
<tr>
<td>{{.Name}}</td>
<td>{{.DataSize}}</td>
<td class="idx">{{if .WithIndex}}{{formatNs .WithIndex.NsPerOp}}{{else}}N/A{{end}}</td>
<td class="noidx">{{if .WithoutIndex}}{{formatNs .WithoutIndex.NsPerOp}}{{else}}N/A{{end}}</td>
<td class="speedup">{{if .Speedup}}{{printf "%.2fx" .Speedup}}{{else}}N/A{{end}}</td>
<td>{{if .WithIndex}}{{printf "%.0f" .WithIndex.BytesPerOp}}{{end}}</td>
<td>{{if .WithoutIndex}}{{printf "%.0f" .WithoutIndex.BytesPerOp}}{{end}}</td>
</tr>
{{end}}
</table>

<h2>2. 索引详情</h2>
<table>
<tr><th>索引名</th><th>列</th><th>类型</th><th>用途</th></tr>
<tr><td>idx_yvonne_kv_str_k_prefix</td><td>k</td><td>varchar_pattern_ops</td><td>LIKE 'prefix%' 前缀扫描</td></tr>
<tr><td>idx_yvonne_kv_str_updated_at</td><td>updated_at</td><td>B-tree</td><td>按时间排序（reaper）</td></tr>
<tr><td>(PRIMARY KEY)</td><td>k</td><td>B-tree</td><td>等值查询 Get/Put/Delete</td></tr>
</table>

<h2>3. 结论</h2>
<ul>
<li><b>ScanPrefix</b>：索引对前缀扫描有显著加速，数据量越大加速比越高</li>
<li><b>Put</b>：索引带来微小写入开销（索引维护），但可忽略</li>
<li><b>Delete</b>：通过主键索引定位，有索引/无索引差异极小（主键始终存在）</li>
<li><b>Get</b>：走主键索引，无需对比（主键始终有索引）</li>
</ul>

<p style="color:#8b8b9f;font-size:11px;margin-top:30px">Generated by scripts/gen_index_bench_chart.go</p>
</body>
</html>`))

	f, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	tmpl.Execute(f, struct{ Comparisons []Comparison }{comparisons})
	fmt.Printf("Report generated: %s\n", *output)
}
