# Hướng Dẫn Sử Dụng Offline (Không Cần Claude)

`code-review-graph` có thể chạy **hoàn toàn độc lập** mà không cần Claude hay MCP server. Bạn có 2 cách sử dụng: **CLI** (dòng lệnh) và **Python API** (import trực tiếp).

---

## Cài Đặt

```bash
# Cài từ source
cd /Users/bopbap/Workspace/Code/code-review-graph
pip install -e .

# Nếu muốn semantic search (tùy chọn)
pip install -e ".[embeddings]"
```

**Yêu cầu:** Python ≥ 3.10, Git (cho incremental update)

---

## Cách 1: CLI (Dòng Lệnh)

### Xây dựng đồ thị

```bash
# Full build — parse toàn bộ repo
code-review-graph build

# Incremental update — chỉ parse file thay đổi
code-review-graph update --base HEAD~1

# Chỉ định repo khác
code-review-graph build --repo /path/to/project
```

### Xem thống kê

```bash
code-review-graph status
# Output:
# Nodes: 245
# Edges: 512
# Files: 37
# Languages: python, javascript
# Last updated: 2026-03-20 09:30:00
```

### Tự động cập nhật khi file thay đổi

```bash
code-review-graph watch
```

### Xuất đồ thị dạng HTML tương tác

```bash
code-review-graph visualize
# Mở file .code-review-graph/graph.html trong trình duyệt
```

---

## Cách 2: Python API (Import Trực Tiếp)

Tất cả tool trong `tools.py` đều là **hàm Python thuần** — gọi được trực tiếp mà không cần MCP.

### Build đồ thị

```python
from code_review_graph.tools import build_or_update_graph

# Full build
result = build_or_update_graph(full_rebuild=True, repo_root="/path/to/repo")
print(result["summary"])

# Incremental update
result = build_or_update_graph(full_rebuild=False, base="HEAD~3")
print(result["summary"])
```

### Phân tích blast radius

```python
from code_review_graph.tools import get_impact_radius

# Tự phát hiện file thay đổi từ git diff
result = get_impact_radius(base="HEAD~1")
print(result["summary"])
for node in result["impacted_nodes"]:
    print(f"  {node['qualified_name']} ({node['kind']})")

# Chỉ định file cụ thể
result = get_impact_radius(changed_files=["src/auth.py", "src/api.py"])
```

### Truy vấn đồ thị

```python
from code_review_graph.tools import query_graph

# Tìm hàm nào gọi hàm target
result = query_graph(pattern="callers_of", target="authenticate_user")

# Tìm hàm nào được gọi bởi target
result = query_graph(pattern="callees_of", target="process_request")

# Tóm tắt nội dung một file
result = query_graph(pattern="file_summary", target="src/auth.py")

# Tìm test cho một hàm
result = query_graph(pattern="tests_for", target="validate_input")
```

**Các pattern có sẵn:**

| Pattern | Mô tả |
|---------|-------|
| `callers_of` | Tìm hàm gọi target |
| `callees_of` | Tìm hàm được gọi bởi target |
| `imports_of` | Tìm các import của file/module |
| `importers_of` | Tìm file nào import target |
| `children_of` | Tìm node con trong file/class |
| `tests_for` | Tìm test cho hàm/class |
| `inheritors_of` | Tìm class kế thừa |
| `file_summary` | Tóm tắt node trong file |

### 🔒 Truy Vấn Bảo Mật (Security)

```python
from code_review_graph.tools import query_graph

# Liệt kê tất cả node có security tag trong file
result = query_graph(pattern="security_profile", target="src/api.py")
for node in result.get("nodes", []):
    print(f"  [{', '.join(node.get('security_tags', []))}] {node['name']}")

# Tìm đường dẫn taint từ hàm đến dangerous sink
result = query_graph(pattern="taint_path", target="handle_request")
for path in result.get("taint_paths", []):
    print(f"  {' → '.join(path['path'])}")

# Tìm ranh giới auth — hàm auth và callee của chúng
result = query_graph(pattern="auth_boundary", target="src/")

# Tìm dangerous sink không có auth guard
result = query_graph(pattern="unguarded_sinks", target="src/")
```

### Security Scan (Quét Anti-Pattern)

```python
from code_review_graph.tools import security_scan

# Quét file thay đổi, phát hiện anti-pattern
result = security_scan(base="HEAD~1", severity_threshold="medium")
for finding in result.get("findings", []):
    print(f"  [{finding['severity']}] {finding['pattern']}: {finding['message']}")
    print(f"    File: {finding['file_path']}:{finding['line']}")
    print(f"    Fix: {finding['suggestion']}")
```

**Các pattern phát hiện được:**

| Pattern | Severity | Ví dụ |
|---------|----------|-------|
| `DANGEROUS_CALL` | Critical | `eval()`, `exec()` |
| `COMMAND_INJECTION` | Critical | `os.system()` |
| `SUBPROCESS_SHELL` | High | `subprocess.run(cmd, shell=True)` |
| `HARDCODED_SECRET` | High | `api_key = "sk-..."` |
| `SQL_STRING_FORMAT` | High | `f"SELECT * FROM {table}"` |
| `INSECURE_DESERIALIZE` | Critical | `pickle.loads()` |
| `WEAK_CRYPTO` | Medium | `hashlib.md5()` |

### Review Context (Ngữ Cảnh Review Toàn Diện)

```python
from code_review_graph.tools import get_review_context
import json

# Tạo ngữ cảnh review đầy đủ, bao gồm phân tích bảo mật
result = get_review_context(base="HEAD~1", include_source=True)

# Xem hướng dẫn review
print(result.get("review_guidance", ""))

# Xem phân tích bảo mật
security = result.get("security_analysis", {})
print(json.dumps(security, indent=2, ensure_ascii=False))

# Xem security guidance
print(result.get("security_guidance", ""))
```

### Tìm kiếm node

```python
from code_review_graph.tools import semantic_search_nodes

# Tìm kiếm keyword
result = semantic_search_nodes(query="authentication", kind="Function")
for node in result.get("nodes", []):
    print(f"  {node['name']} in {node['file_path']}:{node['line_start']}")
```

### Thống kê đồ thị

```python
from code_review_graph.tools import list_graph_stats

stats = list_graph_stats()
print(json.dumps(stats, indent=2))
```

---

## Cách 3: Dùng Trực Tiếp GraphStore + Parser (Low-Level)

Nếu muốn kiểm soát chi tiết hơn:

```python
from pathlib import Path
from code_review_graph.graph import GraphStore, node_to_dict, edge_to_dict
from code_review_graph.parser import CodeParser

# === Parse code thành nodes/edges ===
parser = CodeParser()
source = Path("src/auth.py").read_bytes()
nodes, edges = parser.parse_bytes(Path("src/auth.py"), source)

for node in nodes:
    tags = node.extra.get("security_tags", [])
    tag_str = f" [{', '.join(tags)}]" if tags else ""
    print(f"  {node.kind}: {node.name}{tag_str} (L{node.line_start}-{node.line_end})")

for edge in edges:
    taint = " ⚠️ TAINT" if edge.extra.get("taint_relevant") else ""
    print(f"  {edge.source} --{edge.kind}--> {edge.target}{taint}")

# === Lưu vào graph store ===
store = GraphStore(Path(".code-review-graph/graph.db"))
for n in nodes:
    store.upsert_node(n)
for e in edges:
    store.upsert_edge(e)
store.commit()

# === Truy vấn bảo mật ===
# Tìm node có tag "auth"
auth_nodes = store.get_nodes_by_security_tag("auth")
for n in auth_nodes:
    print(f"  Auth: {n.qualified_name}")

# Tìm dangerous sink
sinks = store.get_nodes_by_security_tag("dangerous_sink")
for s in sinks:
    print(f"  Sink: {s.qualified_name}")

# Tìm đường taint path
paths = store.find_paths_to_sinks("src/auth.py::handle_login")
for path in paths:
    print(f"  Path: {' → '.join(path)}")

store.close()
```

---

## Security Tags Reference

Khi parse code, mỗi hàm và lời gọi được tự động gắn tag bảo mật:

| Tag | Phát hiện bằng | Ví dụ |
|-----|----------------|-------|
| `auth` | Tên hàm chứa `login`, `auth`, `verify_token`, `permission`; decorator `@login_required` | `def authenticate_user()` |
| `crypto` | `encrypt`, `decrypt`, `hash`, `sha256`, `hmac` | `hashlib.sha256(data)` |
| `input_handler` | `handle_`, `parse_`, `validate_`, `sanitize_` | `def handle_request()` |
| `dangerous_sink` | `eval`, `exec`, `system`, `popen`, `compile` | `eval(user_data)` |
| `data_access` | `query`, `execute`, `cursor`, `fetchall`, `fetchone` | `cursor.execute(sql)` |
| `file_io` | `open`, `read_file`, `write_file`, `readlines` | `open("/etc/passwd")` |
| `network` | `request`, `urlopen`, `connect`, `fetch`, `socket` | `requests.get(url)` |
| `serialization` | `loads`, `dumps`, `pickle`, `deserialize`, `marshal` | `pickle.loads(data)` |

---

## Ví Dụ: Script Review Bảo Mật Hoàn Chỉnh

```python
#!/usr/bin/env python3
"""Standalone security review script — không cần Claude."""

import json
import sys
from code_review_graph.tools import (
    build_or_update_graph,
    get_review_context,
    security_scan,
    query_graph,
)

def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else None
    base = sys.argv[2] if len(sys.argv) > 2 else "HEAD~1"

    # 1. Cập nhật đồ thị
    print("🔨 Building graph...")
    result = build_or_update_graph(full_rebuild=False, repo_root=repo, base=base)
    print(f"   {result['summary']}")

    # 2. Quét security anti-patterns
    print("\n🔍 Scanning for security anti-patterns...")
    scan = security_scan(repo_root=repo, base=base, severity_threshold="medium")
    findings = scan.get("findings", [])
    if findings:
        for f in findings:
            print(f"   ⚠️  [{f['severity'].upper()}] {f['pattern']}: {f['message']}")
            print(f"      {f['file_path']}:{f['line']}")
            print(f"      💡 {f['suggestion']}")
    else:
        print("   ✅ Không tìm thấy anti-pattern nào")

    # 3. Phân tích taint paths
    print("\n🔗 Checking taint paths to dangerous sinks...")
    ctx = get_review_context(repo_root=repo, base=base)
    security = ctx.get("security_analysis", {})
    taint_paths = security.get("taint_paths", [])
    if taint_paths:
        for tp in taint_paths:
            print(f"   ⚠️  {tp['source']} → ... → {tp['sink']} ({tp['length']} hops)")
    else:
        print("   ✅ Không có taint path nào")

    # 4. Tìm unguarded sinks
    print("\n🛡️  Checking for unguarded dangerous sinks...")
    unguarded = query_graph(pattern="unguarded_sinks", target="", repo_root=repo)
    sinks = unguarded.get("nodes", [])
    if sinks:
        for s in sinks:
            print(f"   ⚠️  {s['name']} tại {s['file_path']}:{s['line_start']}")
    else:
        print("   ✅ Tất cả dangerous sink đều có auth guard")

    # 5. Security guidance
    guidance = ctx.get("security_guidance", "")
    if guidance:
        print(f"\n📋 Security Guidance:\n{guidance}")

    print("\n✅ Security review hoàn tất!")

if __name__ == "__main__":
    main()
```

**Chạy:**

```bash
python security_review.py /path/to/repo HEAD~5
```

---

## Ngôn Ngữ Hỗ Trợ

Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, Ruby, PHP, Kotlin, Swift, Scala, Lua, Haskell, Elixir, Dart, Zig, Bash, R, TOML, YAML, HCL.

## Dữ Liệu Lưu Ở Đâu?

```
project-root/
└── .code-review-graph/
    ├── graph.db          # SQLite — đồ thị code
    ├── embeddings.db     # SQLite — vector embeddings (nếu có)
    └── graph.html        # HTML — visualization (nếu chạy visualize)
```
