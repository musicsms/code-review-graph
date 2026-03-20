"""Security pattern detection for code review.

Scans source files using Tree-sitter AST to detect dangerous code patterns
such as eval/exec calls, shell injection, SQL string formatting, hardcoded
secrets, insecure deserialization, and more.

Findings are returned as structured ``SecurityFinding`` objects suitable
for inclusion in MCP tool responses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import tree_sitter_language_pack as tslp

from .parser import EXTENSION_TO_LANGUAGE

# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------


@dataclass
class SecurityFinding:
    """A single security anti-pattern detected in source code."""

    pattern: str  # e.g. "DANGEROUS_CALL"
    severity: str  # "critical", "high", "medium", "low"
    message: str  # Human-readable description
    file_path: str
    line: int
    code_snippet: str  # The offending source line
    suggestion: str  # How to fix it
    extra: dict = field(default_factory=dict)


def finding_to_dict(f: SecurityFinding) -> dict:
    return {
        "pattern": f.pattern,
        "severity": f.severity,
        "message": f.message,
        "file_path": f.file_path,
        "line": f.line,
        "code_snippet": f.code_snippet[:200],  # Truncate long lines
        "suggestion": f.suggestion,
    }


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

# Dangerous function names by language
_DANGEROUS_CALLS: dict[str, dict[str, tuple[str, str, str]]] = {
    # language -> { func_name -> (pattern, severity, suggestion) }
    "python": {
        "eval": (
            "DANGEROUS_CALL",
            "critical",
            "Replace eval() with ast.literal_eval() or a safe parser",
        ),
        "exec": (
            "DANGEROUS_CALL",
            "critical",
            "Avoid exec(); use structured dispatch or importlib instead",
        ),
        "__import__": (
            "DANGEROUS_CALL",
            "high",
            "Use importlib.import_module() instead of __import__()",
        ),
    },
}

_COMMAND_INJECTION_CALLS: dict[str, set[str]] = {
    "python": {"system", "popen", "popen2", "popen3", "popen4"},
}

_INSECURE_DESERIALIZE: dict[str, dict[str, tuple[str, str]]] = {
    "python": {
        "loads": (
            "pickle.loads() deserializes arbitrary objects — use json.loads() instead",
            "critical",
        ),
        "load": (
            "yaml.load() without SafeLoader can execute arbitrary code — "
            "use yaml.safe_load() instead",
            "high",
        ),
    },
}

_WEAK_CRYPTO_NAMES = {"md5", "sha1"}

# Patterns for hardcoded secrets (variable name patterns)
_SECRET_VAR_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|api_key|apikey|token|private_key|auth_token"
    r"|access_key|secret_key|credentials)",
)

# SQL string formatting patterns (in source text)
_SQL_FSTRING_PATTERN = re.compile(
    r"""(?i)(?:"""
    # f-string or format() containing SQL
    r"""f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s"""
    r"""|"""
    # SQL keyword followed by .format() or %
    r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*"""
    r"""(?:\.format\(|%\s*[(\"])"""
    r""")""",
)


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


def scan_file_security(
    path: Path,
    source: bytes,
    language: str,
) -> list[SecurityFinding]:
    """Scan a single file for security anti-patterns using Tree-sitter AST.

    Args:
        path: File path for reporting.
        source: Raw file bytes.
        language: Language identifier (e.g. ``"python"``).

    Returns:
        List of security findings.
    """
    findings: list[SecurityFinding] = []
    source_text = source.decode("utf-8", errors="replace")
    source_lines = source_text.splitlines()
    file_str = str(path)

    try:
        parser = tslp.get_parser(language)
    except Exception:
        return findings

    tree = parser.parse(source)

    # Walk the AST
    _walk_node(
        tree.root_node,
        source,
        source_lines,
        language,
        file_str,
        findings,
    )

    # Line-level heuristic checks (supplement AST analysis)
    _check_source_lines(source_lines, language, file_str, findings)

    return findings


def _walk_node(
    node,
    source: bytes,
    source_lines: list[str],
    language: str,
    file_path: str,
    findings: list[SecurityFinding],
    parent_type: str = "",
) -> None:
    """Recursively walk AST nodes looking for security anti-patterns."""

    node_type = node.type

    # --- Dangerous function calls ---
    if node_type in ("call", "call_expression"):
        _check_dangerous_call(
            node, source, source_lines, language, file_path, findings
        )

    # --- Hardcoded secrets in assignments ---
    if node_type in ("assignment", "variable_declarator", "short_var_declaration"):
        _check_hardcoded_secret(
            node, source, source_lines, language, file_path, findings
        )

    for child in node.children:
        _walk_node(
            child, source, source_lines, language, file_path, findings,
            parent_type=node_type,
        )


def _check_dangerous_call(
    node,
    source: bytes,
    source_lines: list[str],
    language: str,
    file_path: str,
    findings: list[SecurityFinding],
) -> None:
    """Check if a call expression is a known dangerous function."""
    # Get the function name
    func_name = _extract_call_name(node, language)
    if not func_name:
        return

    line_num = node.start_point[0] + 1
    snippet = _get_line(source_lines, line_num)

    # Check direct dangerous calls (eval, exec, __import__)
    dangerous = _DANGEROUS_CALLS.get(language, {})
    if func_name in dangerous:
        pattern_name, severity, suggestion = dangerous[func_name]
        findings.append(SecurityFinding(
            pattern=pattern_name,
            severity=severity,
            message=f"Dangerous function call: {func_name}()",
            file_path=file_path,
            line=line_num,
            code_snippet=snippet,
            suggestion=suggestion,
        ))
        return

    # Check os.system, os.popen etc.
    cmd_calls = _COMMAND_INJECTION_CALLS.get(language, set())
    if func_name in cmd_calls:
        findings.append(SecurityFinding(
            pattern="COMMAND_INJECTION",
            severity="critical",
            message=f"Command injection risk: os.{func_name}()",
            file_path=file_path,
            line=line_num,
            code_snippet=snippet,
            suggestion="Use subprocess.run() with shell=False and a list of arguments",
        ))
        return

    # Check subprocess with shell=True
    if func_name in ("run", "call", "Popen", "check_output", "check_call"):
        if _has_shell_true(node, source):
            findings.append(SecurityFinding(
                pattern="SUBPROCESS_SHELL",
                severity="high",
                message=f"subprocess.{func_name}() called with shell=True",
                file_path=file_path,
                line=line_num,
                code_snippet=snippet,
                suggestion="Use shell=False with a list of arguments instead",
            ))
            return

    # Check insecure deserialization
    deser = _INSECURE_DESERIALIZE.get(language, {})
    if func_name in deser:
        # Disambiguate: only flag if the module is pickle or yaml
        full_text = node.text.decode("utf-8", errors="replace")
        if "pickle" in full_text or ("yaml" in full_text and "safe_load" not in full_text):
            msg, severity = deser[func_name]
            findings.append(SecurityFinding(
                pattern="INSECURE_DESERIALIZE",
                severity=severity,
                message=msg,
                file_path=file_path,
                line=line_num,
                code_snippet=snippet,
                suggestion=msg,
            ))
            return

    # Check weak crypto
    if func_name in _WEAK_CRYPTO_NAMES:
        findings.append(SecurityFinding(
            pattern="WEAK_CRYPTO",
            severity="medium",
            message=f"Weak hash function: {func_name}() — not suitable for security purposes",
            file_path=file_path,
            line=line_num,
            code_snippet=snippet,
            suggestion="Use hashlib.sha256() or hashlib.sha3_256() instead",
        ))


def _check_hardcoded_secret(
    node,
    source: bytes,
    source_lines: list[str],
    language: str,
    file_path: str,
    findings: list[SecurityFinding],
) -> None:
    """Check if a variable assignment contains a hardcoded secret."""
    # Get variable name
    var_name = None
    has_string_value = False

    for child in node.children:
        if child.type in ("identifier", "name", "property_identifier"):
            var_name = child.text.decode("utf-8", errors="replace")
        elif child.type in ("string", "string_literal", "interpreted_string_literal"):
            text = child.text.decode("utf-8", errors="replace")
            # Only flag non-empty strings that look like real values
            if len(text) > 3:  # Not just "" or ''
                has_string_value = True

    if var_name and has_string_value and _SECRET_VAR_PATTERNS.search(var_name):
        line_num = node.start_point[0] + 1
        findings.append(SecurityFinding(
            pattern="HARDCODED_SECRET",
            severity="high",
            message=f"Possible hardcoded secret in variable: {var_name}",
            file_path=file_path,
            line=line_num,
            code_snippet=_get_line(source_lines, line_num),
            suggestion="Use environment variables or a secrets manager instead",
        ))


def _check_source_lines(
    source_lines: list[str],
    language: str,
    file_path: str,
    findings: list[SecurityFinding],
) -> None:
    """Line-level heuristic checks that complement AST analysis."""
    for i, line in enumerate(source_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        # SQL string formatting
        if language in ("python",) and _SQL_FSTRING_PATTERN.search(stripped):
            findings.append(SecurityFinding(
                pattern="SQL_STRING_FORMAT",
                severity="high",
                message="SQL query built with string formatting — risk of SQL injection",
                file_path=file_path,
                line=i,
                code_snippet=stripped[:200],
                suggestion="Use parameterized queries (?, %s placeholders) instead",
            ))


# ---------------------------------------------------------------------------
# AST helper functions
# ---------------------------------------------------------------------------


def _extract_call_name(node, language: str) -> Optional[str]:
    """Extract the function name from a call node."""
    if not node.children:
        return None

    first = node.children[0]

    # Simple call: func(args)
    if first.type == "identifier":
        return first.text.decode("utf-8", errors="replace")

    # Method call: obj.method(args)  or  module.func(args)
    member_types = (
        "attribute", "member_expression",
        "field_expression", "selector_expression",
    )
    if first.type in member_types:
        for child in reversed(first.children):
            if child.type in (
                "identifier", "property_identifier", "field_identifier",
            ):
                return child.text.decode("utf-8", errors="replace")

    return None


def _has_shell_true(node, source: bytes) -> bool:
    """Check if a call node has shell=True as a keyword argument."""
    text = node.text.decode("utf-8", errors="replace")
    return "shell=True" in text or "shell = True" in text


def _get_line(lines: list[str], line_num: int) -> str:
    """Safely get a source line by 1-based line number."""
    if 1 <= line_num <= len(lines):
        return lines[line_num - 1].strip()
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_changed_files_security(
    repo_root: Path,
    changed_files: list[str],
    severity_threshold: str = "low",
) -> list[SecurityFinding]:
    """Scan a list of changed files for security anti-patterns.

    Args:
        repo_root: Repository root path.
        changed_files: List of relative file paths.
        severity_threshold: Minimum severity to include.

    Returns:
        List of security findings at or above the threshold.
    """
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_level = severity_order.get(severity_threshold, 1)

    all_findings: list[SecurityFinding] = []

    for rel_path in changed_files:
        full_path = repo_root / rel_path
        if not full_path.is_file():
            continue

        suffix = full_path.suffix.lower()
        language = EXTENSION_TO_LANGUAGE.get(suffix)
        if not language:
            continue

        try:
            source = full_path.read_bytes()
        except (OSError, PermissionError):
            continue

        findings = scan_file_security(full_path, source, language)
        for f in findings:
            if severity_order.get(f.severity, 0) >= min_level:
                all_findings.append(f)

    # Sort by severity (critical first)
    all_findings.sort(
        key=lambda f: severity_order.get(f.severity, 0), reverse=True
    )
    return all_findings
