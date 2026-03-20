"""Tests for security hardening and security pattern detection."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from code_review_graph.incremental import _is_safe_path, _validate_git_ref
from code_review_graph.security_patterns import (
    SecurityFinding,
    finding_to_dict,
    scan_file_security,
)


# ===========================================================================
# Part 1: Hardening tests
# ===========================================================================


class TestValidateGitRef:
    """Tests for _validate_git_ref()."""

    @pytest.mark.parametrize(
        "ref",
        [
            "HEAD~1",
            "HEAD",
            "main",
            "origin/main",
            "v1.0.0",
            "abc123",
            "HEAD~3",
            "HEAD^2",
            "refs/heads/main",
            "feature/branch-name",
            "HEAD@{0}",
        ],
    )
    def test_valid_refs(self, ref: str) -> None:
        assert _validate_git_ref(ref) == ref

    @pytest.mark.parametrize(
        "ref",
        [
            "--exec=whoami",
            "-a",
            "--upload-pack=evil",
        ],
    )
    def test_reject_dash_prefix(self, ref: str) -> None:
        with pytest.raises(ValueError, match="must not start with a dash"):
            _validate_git_ref(ref)

    @pytest.mark.parametrize(
        "ref",
        [
            "HEAD; rm -rf /",
            "main && echo pwned",
            "$(whoami)",
            "`id`",
            "ref|command",
            "branch name with spaces",
        ],
    )
    def test_reject_unsafe_chars(self, ref: str) -> None:
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_git_ref(ref)

    def test_reject_empty(self) -> None:
        with pytest.raises(ValueError, match="empty or too long"):
            _validate_git_ref("")

    def test_reject_too_long(self) -> None:
        with pytest.raises(ValueError, match="empty or too long"):
            _validate_git_ref("a" * 257)


class TestIsSafePath:
    """Tests for _is_safe_path()."""

    def test_safe_path(self, tmp_path: Path) -> None:
        f = tmp_path / "file.py"
        f.touch()
        assert _is_safe_path(f, tmp_path) is True

    def test_safe_nested_path(self, tmp_path: Path) -> None:
        d = tmp_path / "sub" / "dir"
        d.mkdir(parents=True)
        f = d / "file.py"
        f.touch()
        assert _is_safe_path(f, tmp_path) is True

    def test_symlink_outside_repo(self, tmp_path: Path) -> None:
        """Symlink pointing outside repo should be rejected."""
        import tempfile

        with tempfile.TemporaryDirectory() as outside_dir:
            outside_file = Path(outside_dir) / "secret.txt"
            outside_file.write_text("secret")
            link = tmp_path / "link.py"
            link.symlink_to(outside_file)
            assert _is_safe_path(link, tmp_path) is False


# ===========================================================================
# Part 2: Security pattern detection tests
# ===========================================================================


class TestScanFileSecurity:
    """Tests for security pattern detection via AST analysis."""

    def _scan(self, code: str, language: str = "python") -> list[SecurityFinding]:
        """Helper: scan code snippet and return findings."""
        source = textwrap.dedent(code).encode("utf-8")
        return scan_file_security(Path("test.py"), source, language)

    def test_detect_eval(self) -> None:
        findings = self._scan("result = eval(user_input)")
        assert any(f.pattern == "DANGEROUS_CALL" and "eval" in f.message for f in findings)

    def test_detect_exec(self) -> None:
        findings = self._scan("exec(code_string)")
        assert any(f.pattern == "DANGEROUS_CALL" and "exec" in f.message for f in findings)

    def test_detect_subprocess_shell_true(self) -> None:
        findings = self._scan(
            'import subprocess\nsubprocess.run(cmd, shell=True)'
        )
        assert any(f.pattern == "SUBPROCESS_SHELL" for f in findings)

    def test_safe_subprocess(self) -> None:
        findings = self._scan(
            'import subprocess\nsubprocess.run(["git", "status"])'
        )
        assert not any(f.pattern == "SUBPROCESS_SHELL" for f in findings)

    def test_detect_os_system(self) -> None:
        findings = self._scan('import os\nos.system("rm -rf /")')
        assert any(f.pattern == "COMMAND_INJECTION" for f in findings)

    def test_detect_hardcoded_secret(self) -> None:
        findings = self._scan('api_key = "sk-1234567890abcdef"')
        assert any(f.pattern == "HARDCODED_SECRET" for f in findings)

    def test_no_false_positive_empty_secret(self) -> None:
        findings = self._scan('password = ""')
        # Empty string (len <= 3 after quotes): no finding
        assert not any(f.pattern == "HARDCODED_SECRET" for f in findings)

    def test_detect_sql_fstring(self) -> None:
        findings = self._scan(
            'query = f"SELECT * FROM users WHERE id = {user_id}"'
        )
        assert any(f.pattern == "SQL_STRING_FORMAT" for f in findings)

    def test_safe_sql_parameterized(self) -> None:
        findings = self._scan(
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        )
        assert not any(f.pattern == "SQL_STRING_FORMAT" for f in findings)

    def test_detect_pickle_loads(self) -> None:
        findings = self._scan("import pickle\ndata = pickle.loads(payload)")
        assert any(f.pattern == "INSECURE_DESERIALIZE" for f in findings)

    def test_detect_weak_crypto(self) -> None:
        findings = self._scan("import hashlib\nhash = hashlib.md5(data)")
        assert any(f.pattern == "WEAK_CRYPTO" for f in findings)

    def test_safe_strong_crypto(self) -> None:
        findings = self._scan("import hashlib\nhash = hashlib.sha256(data)")
        assert not any(f.pattern == "WEAK_CRYPTO" for f in findings)


class TestFindingToDict:
    """Tests for the finding serialization helper."""

    def test_serialization(self) -> None:
        finding = SecurityFinding(
            pattern="DANGEROUS_CALL",
            severity="critical",
            message="eval() detected",
            file_path="/tmp/test.py",
            line=5,
            code_snippet="eval(user_input)",
            suggestion="Use ast.literal_eval()",
        )
        d = finding_to_dict(finding)
        assert d["pattern"] == "DANGEROUS_CALL"
        assert d["severity"] == "critical"
        assert d["line"] == 5
        assert "suggestion" in d

    def test_truncates_long_snippet(self) -> None:
        finding = SecurityFinding(
            pattern="TEST",
            severity="low",
            message="test",
            file_path="test.py",
            line=1,
            code_snippet="x" * 500,
            suggestion="test",
        )
        d = finding_to_dict(finding)
        assert len(d["code_snippet"]) == 200


# ===========================================================================
# Part 3: Graph-level security tests (security-aware graph)
# ===========================================================================


from code_review_graph.parser import (
    CodeParser,
    EdgeInfo,
    NodeInfo,
    _classify_call_security,
    _classify_func_security,
)
from code_review_graph.graph import (
    GraphStore,
    node_to_dict,
    edge_to_dict,
)


class TestClassifyCallSecurity:
    """Tests for _classify_call_security()."""

    def test_eval_is_dangerous_sink(self) -> None:
        tags = _classify_call_security("eval")
        assert "dangerous_sink" in tags

    def test_exec_is_dangerous_sink(self) -> None:
        tags = _classify_call_security("exec")
        assert "dangerous_sink" in tags

    def test_system_is_dangerous_sink(self) -> None:
        tags = _classify_call_security("system")
        assert "dangerous_sink" in tags

    def test_execute_is_data_access(self) -> None:
        tags = _classify_call_security("execute")
        assert "data_access" in tags

    def test_authenticate_is_auth(self) -> None:
        tags = _classify_call_security("authenticate")
        assert "auth" in tags

    def test_sha256_is_crypto(self) -> None:
        tags = _classify_call_security("sha256")
        assert "crypto" in tags

    def test_open_is_file_io(self) -> None:
        tags = _classify_call_security("open")
        assert "file_io" in tags

    def test_urlopen_is_network(self) -> None:
        tags = _classify_call_security("urlopen")
        assert "network" in tags

    def test_loads_is_serialization(self) -> None:
        tags = _classify_call_security("loads")
        assert "serialization" in tags

    def test_regular_function_no_tags(self) -> None:
        tags = _classify_call_security("calculate_total")
        assert len(tags) == 0

    def test_dotted_name_strips_prefix(self) -> None:
        tags = _classify_call_security("os.system")
        assert "dangerous_sink" in tags


class TestClassifyFuncSecurity:
    """Tests for _classify_func_security() with name-based detection."""

    def test_login_handler_tagged_auth(self) -> None:
        # Create a minimal mock AST node (just needs .children)
        class MockNode:
            children = []
        tags = _classify_func_security("login_user", MockNode(), "python", b"")
        assert "auth" in tags

    def test_encrypt_data_tagged_crypto(self) -> None:
        class MockNode:
            children = []
        tags = _classify_func_security("encrypt_data", MockNode(), "python", b"")
        assert "crypto" in tags

    def test_handle_request_tagged_input(self) -> None:
        class MockNode:
            children = []
        tags = _classify_func_security("handle_request", MockNode(), "python", b"")
        assert "input_handler" in tags

    def test_query_users_tagged_data_access(self) -> None:
        class MockNode:
            children = []
        tags = _classify_func_security("query_users", MockNode(), "python", b"")
        assert "data_access" in tags

    def test_regular_function_no_tags(self) -> None:
        class MockNode:
            children = []
        tags = _classify_func_security("calculate_total", MockNode(), "python", b"")
        assert len(tags) == 0


class TestParserSecurityTagging:
    """Tests that parser correctly tags nodes and edges with security metadata."""

    def test_parser_tags_auth_function(self) -> None:
        code = textwrap.dedent("""\
            def login_user(username, password):
                pass
        """)
        parser = CodeParser()
        nodes, edges = parser.parse_bytes(Path("/test.py"), code.encode())
        func_nodes = [n for n in nodes if n.kind == "Function" and n.name == "login_user"]
        assert len(func_nodes) == 1
        assert "auth" in func_nodes[0].extra.get("security_tags", [])

    def test_parser_tags_call_to_eval(self) -> None:
        code = textwrap.dedent("""\
            def process(data):
                result = eval(data)
        """)
        parser = CodeParser()
        nodes, edges = parser.parse_bytes(Path("/test.py"), code.encode())
        call_edges = [e for e in edges if e.kind == "CALLS" and e.target == "eval"]
        assert len(call_edges) >= 1
        assert "dangerous_sink" in call_edges[0].extra.get("security_tags", [])
        assert call_edges[0].extra.get("taint_relevant") is True

    def test_parser_no_tags_for_regular_function(self) -> None:
        code = textwrap.dedent("""\
            def calculate_sum(a, b):
                return a + b
        """)
        parser = CodeParser()
        nodes, edges = parser.parse_bytes(Path("/test.py"), code.encode())
        func_nodes = [n for n in nodes if n.kind == "Function"]
        assert len(func_nodes) == 1
        assert not func_nodes[0].extra.get("security_tags")


class TestNodeEdgeDictSecurity:
    """Tests that node_to_dict/edge_to_dict surface security metadata."""

    def test_node_to_dict_includes_security_tags(self) -> None:
        from code_review_graph.graph import GraphNode
        node = GraphNode(
            id=1, kind="Function", name="login",
            qualified_name="/test.py::login",
            file_path="/test.py", line_start=1, line_end=3,
            language="python", parent_name=None,
            params="(user, pw)", return_type=None,
            is_test=False, file_hash="abc",
            extra={"security_tags": ["auth", "crypto"]},
        )
        d = node_to_dict(node)
        assert d["security_tags"] == ["auth", "crypto"]

    def test_node_to_dict_no_tags_when_empty(self) -> None:
        from code_review_graph.graph import GraphNode
        node = GraphNode(
            id=1, kind="Function", name="calc",
            qualified_name="/test.py::calc",
            file_path="/test.py", line_start=1, line_end=3,
            language="python", parent_name=None,
            params="(a, b)", return_type=None,
            is_test=False, file_hash="abc",
            extra={},
        )
        d = node_to_dict(node)
        assert "security_tags" not in d

    def test_edge_to_dict_includes_security_metadata(self) -> None:
        from code_review_graph.graph import GraphEdge
        edge = GraphEdge(
            id=1, kind="CALLS",
            source_qualified="/test.py::process",
            target_qualified="eval",
            file_path="/test.py", line=5,
            extra={"security_tags": ["dangerous_sink"], "taint_relevant": True},
        )
        d = edge_to_dict(edge)
        assert d["security_tags"] == ["dangerous_sink"]
        assert d["taint_relevant"] is True


class TestGraphStoreSecurityQueries:
    """Tests for security-focused graph query methods."""

    def _make_store(self, tmp_path: Path) -> GraphStore:
        store = GraphStore(tmp_path / "test.db")
        return store

    def test_get_nodes_by_security_tag(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        # Insert nodes with and without security tags
        store.upsert_node(NodeInfo(
            kind="Function", name="login", file_path="/test.py",
            line_start=1, line_end=5, language="python",
            extra={"security_tags": ["auth"]},
        ))
        store.upsert_node(NodeInfo(
            kind="Function", name="calc", file_path="/test.py",
            line_start=6, line_end=10, language="python",
        ))
        store.commit()

        auth_nodes = store.get_nodes_by_security_tag("auth")
        assert len(auth_nodes) == 1
        assert auth_nodes[0].name == "login"
        store.close()

    def test_get_nodes_by_security_tag_no_match(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.upsert_node(NodeInfo(
            kind="Function", name="calc", file_path="/test.py",
            line_start=1, line_end=5, language="python",
        ))
        store.commit()

        crypto_nodes = store.get_nodes_by_security_tag("crypto")
        assert len(crypto_nodes) == 0
        store.close()

    def test_find_paths_to_sinks(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        # Create a chain: handler -> process -> eval
        store.upsert_node(NodeInfo(
            kind="Function", name="handler", file_path="/test.py",
            line_start=1, line_end=5, language="python",
            extra={"security_tags": ["input_handler"]},
        ))
        store.upsert_node(NodeInfo(
            kind="Function", name="process", file_path="/test.py",
            line_start=6, line_end=10, language="python",
        ))
        store.upsert_edge(EdgeInfo(
            kind="CALLS", source="/test.py::handler",
            target="/test.py::process", file_path="/test.py", line=3,
        ))
        store.upsert_edge(EdgeInfo(
            kind="CALLS", source="/test.py::process",
            target="eval", file_path="/test.py", line=8,
            extra={"security_tags": ["dangerous_sink"], "taint_relevant": True},
        ))
        store.commit()

        paths = store.find_paths_to_sinks("/test.py::handler")
        assert len(paths) >= 1
        # Path should go from handler through (at least) to eval
        found_eval = any("eval" in p for p in paths)
        assert found_eval
        store.close()

    def test_find_paths_no_sinks(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.upsert_node(NodeInfo(
            kind="Function", name="safe_func", file_path="/test.py",
            line_start=1, line_end=5, language="python",
        ))
        store.upsert_edge(EdgeInfo(
            kind="CALLS", source="/test.py::safe_func",
            target="/test.py::another_safe", file_path="/test.py", line=3,
        ))
        store.commit()

        paths = store.find_paths_to_sinks("/test.py::safe_func")
        assert len(paths) == 0
        store.close()


class TestGenerateSecurityGuidance:
    """Tests for _generate_security_guidance()."""

    def test_generates_tag_summary(self) -> None:
        from code_review_graph.tools import _generate_security_guidance
        analysis = {
            "security_tagged_nodes": [
                {"name": "login", "security_tags": ["auth"]},
                {"name": "hash_pw", "security_tags": ["crypto", "auth"]},
            ],
            "taint_paths": [],
            "auth_crossings": [],
        }
        result = _generate_security_guidance(analysis)
        assert "[auth]" in result
        assert "[crypto]" in result

    def test_generates_taint_path_warning(self) -> None:
        from code_review_graph.tools import _generate_security_guidance
        analysis = {
            "security_tagged_nodes": [],
            "taint_paths": [
                {"source": "/test.py::handler", "sink": "eval", "path": ["/test.py::handler", "eval"], "length": 2},
            ],
            "auth_crossings": [],
        }
        result = _generate_security_guidance(analysis)
        assert "taint path" in result
        assert "handler" in result

    def test_empty_analysis_returns_empty(self) -> None:
        from code_review_graph.tools import _generate_security_guidance
        analysis = {
            "security_tagged_nodes": [],
            "taint_paths": [],
            "auth_crossings": [],
        }
        result = _generate_security_guidance(analysis)
        assert result == ""

