"""Deterministic, read-only scanner for bounded MCP security checks."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SCANNER_VERSION = "1"
SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}
_SUMMARY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")
_SCAN_SUFFIXES = {".py", ".json", ".yaml", ".yml", ".toml", ".md"}
_SKIP_DIRS = {".git", ".venv", "__pycache__", "dist", "build", "node_modules"}
_SECURITY_SENSITIVE_PATHS = ("stipul/token/", "stipul/signing/", "stipul/wrapper/", "stipul/proxy/")
_EVIDENCE_ARTIFACTS = ("events.jsonl", "decisions.jsonl", "summary.json", "manifest.json", "scan_report.json")
_WRITE_HELPERS = ("write_text(", "write_bytes(", "write_json(", "write_jsonl(", 'open(')
_SAFE_PATH_TOKENS = ("resolve(", "relative_to(", "is_relative_to(", "normpath(", "safe_join(", "commonpath(", "abspath(")


@dataclass(frozen=True)
class ScannerFinding:
    finding_id: str
    category: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    file_path: str
    line_start: int | None
    line_end: int | None
    evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    target: str
    scanned_files: int
    skipped_files: int
    findings: list[ScannerFinding]
    summary: dict[str, int]
    scanner_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "scanned_files": self.scanned_files,
            "scanner_version": self.scanner_version,
            "skipped_files": self.skipped_files,
            "summary": dict(self.summary),
            "target": self.target,
        }


class MCPScanner:
    """Read-only scanner with bounded, deterministic heuristics."""

    def __init__(self, *, max_file_bytes: int = 512_000) -> None:
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int):
            raise ValueError("max_file_bytes must be an integer")
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be > 0")
        self.max_file_bytes = max_file_bytes

    def scan_path(self, target: Path) -> ScanReport:
        resolved_target = Path(target)
        if not resolved_target.exists():
            raise FileNotFoundError(f"Scan target not found: {resolved_target}")

        root_dir = resolved_target if resolved_target.is_dir() else resolved_target.parent
        candidate_files = _collect_candidate_files(resolved_target)

        findings: list[ScannerFinding] = []
        scanned_files = 0
        skipped_files = 0
        for path in candidate_files:
            try:
                file_size = path.stat().st_size
            except OSError:
                skipped_files += 1
                continue
            if file_size > self.max_file_bytes:
                skipped_files += 1
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped_files += 1
                continue

            scanned_files += 1
            display_path = _display_path(path, resolved_target, root_dir)
            findings.extend(_scan_file(path, display_path, text))

        if not (root_dir / "SECURITY.md").exists():
            findings.append(
                ScannerFinding(
                    finding_id="AS-SCAN-012",
                    category="security_policy",
                    severity="info",
                    title="Repository is missing SECURITY.md",
                    description="The repository root does not contain a SECURITY.md disclosure policy.",
                    recommendation="Add SECURITY.md with supported versions, reporting steps, and a disclosure contact placeholder.",
                    file_path="SECURITY.md",
                    line_start=None,
                    line_end=None,
                    evidence=["SECURITY.md not found at scan root"],
                )
            )

        sorted_findings = sorted(findings, key=_finding_sort_key)
        return ScanReport(
            target=str(resolved_target.resolve()),
            scanned_files=scanned_files,
            skipped_files=skipped_files,
            findings=sorted_findings,
            summary=_build_summary(sorted_findings),
            scanner_version=SCANNER_VERSION,
        )


def format_scan_report(report: ScanReport) -> str:
    lines = [
        f"Scan target: {report.target}",
        f"Scanned files: {report.scanned_files} | Skipped files: {report.skipped_files}",
        "Findings: " + ", ".join(f"{severity}={report.summary[severity]}" for severity in _SUMMARY_ORDER),
    ]
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    for finding in report.findings:
        location = finding.file_path
        if finding.line_start is not None:
            location = f"{location}:{finding.line_start}"
        lines.append(
            f"{finding.severity.upper()} {finding.finding_id} {location} {finding.title}"
        )
        if finding.evidence:
            lines.append(f"  evidence: {finding.evidence[0]}")
    return "\n".join(lines)


def scan_report_from_dict(payload: dict[str, Any]) -> ScanReport:
    if not isinstance(payload, dict):
        raise ValueError("scan report must be a JSON object")

    target = payload.get("target")
    scanned_files = payload.get("scanned_files")
    skipped_files = payload.get("skipped_files")
    scanner_version = payload.get("scanner_version")
    findings_payload = payload.get("findings")
    summary_payload = payload.get("summary")

    if not isinstance(target, str) or not target:
        raise ValueError("scan report target must be a non-empty string")
    if isinstance(scanned_files, bool) or not isinstance(scanned_files, int) or scanned_files < 0:
        raise ValueError("scan report scanned_files must be a non-negative integer")
    if isinstance(skipped_files, bool) or not isinstance(skipped_files, int) or skipped_files < 0:
        raise ValueError("scan report skipped_files must be a non-negative integer")
    if not isinstance(scanner_version, str) or not scanner_version:
        raise ValueError("scan report scanner_version must be a non-empty string")
    if not isinstance(findings_payload, list):
        raise ValueError("scan report findings must be a list")
    if not isinstance(summary_payload, dict):
        raise ValueError("scan report summary must be an object")

    findings = [_scan_finding_from_dict(item) for item in findings_payload]
    summary = _summary_from_dict(summary_payload)
    expected_summary = _build_summary(findings)
    if summary != expected_summary:
        raise ValueError("scan report summary does not match findings")

    return ScanReport(
        target=target,
        scanned_files=scanned_files,
        skipped_files=skipped_files,
        findings=findings,
        summary=summary,
        scanner_version=scanner_version,
    )


def severity_trips_threshold(findings: list[ScannerFinding], threshold: Severity) -> bool:
    threshold_value = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] >= threshold_value for finding in findings)


def _scan_finding_from_dict(payload: Any) -> ScannerFinding:
    if not isinstance(payload, dict):
        raise ValueError("scan finding must be an object")
    severity = payload.get("severity")
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"invalid finding severity: {severity!r}")

    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        raise ValueError("scan finding evidence must be a list of strings")
    line_start = payload.get("line_start")
    line_end = payload.get("line_end")
    if line_start is not None and (isinstance(line_start, bool) or not isinstance(line_start, int)):
        raise ValueError("scan finding line_start must be an integer or null")
    if line_end is not None and (isinstance(line_end, bool) or not isinstance(line_end, int)):
        raise ValueError("scan finding line_end must be an integer or null")

    for field in ("finding_id", "category", "title", "description", "recommendation", "file_path"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"scan finding {field} must be a non-empty string")

    return ScannerFinding(
        finding_id=payload["finding_id"],
        category=payload["category"],
        severity=severity,
        title=payload["title"],
        description=payload["description"],
        recommendation=payload["recommendation"],
        file_path=payload["file_path"],
        line_start=line_start,
        line_end=line_end,
        evidence=evidence,
    )


def _summary_from_dict(payload: dict[str, Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for severity in _SUMMARY_ORDER:
        value = payload.get(severity)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"scan report summary[{severity!r}] must be a non-negative integer")
        summary[severity] = value
    return summary


def _collect_candidate_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]

    output: list[Path] = []
    for root_text, dirnames, filenames in os.walk(target, topdown=True):
        root = Path(root_text)
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for filename in sorted(filenames):
            path = root / filename
            if path.suffix.lower() in _SCAN_SUFFIXES:
                output.append(path)
    return output


def _scan_file(path: Path, display_path: str, text: str) -> list[ScannerFinding]:
    lines = text.splitlines()
    tree = _parse_python_ast(text) if path.suffix.lower() == ".py" else None

    findings: list[ScannerFinding] = []
    findings.extend(_check_path_traversal(display_path, lines, tree))
    findings.extend(_check_command_execution(display_path, lines, tree))
    findings.extend(_check_missing_token_validation(path, display_path, lines, text))
    findings.extend(_check_hardcoded_secrets(display_path, lines))
    findings.extend(_check_wildcard_allowlists(path, display_path, lines))
    findings.extend(_check_unsafe_yaml_load(display_path, lines, tree))
    findings.extend(_check_insecure_tempfiles(display_path, lines, tree))
    findings.extend(_check_weak_hash_usage(display_path, lines))
    findings.extend(_check_broad_exceptions(path, display_path, lines))
    findings.extend(_check_overwrite_style_evidence_writes(display_path, lines))
    findings.extend(_check_pii_logging(display_path, lines))
    return findings


def _parse_python_ast(text: str) -> ast.AST | None:
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _check_path_traversal(
    display_path: str,
    lines: list[str],
    tree: ast.AST | None,
) -> list[ScannerFinding]:
    if tree is None:
        return []

    findings: list[ScannerFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        arg = _path_sink_argument(node)
        if arg is None:
            continue
        candidate_names = _candidate_variable_names(arg)
        if not any(_looks_like_untrusted_path(name) for name in candidate_names):
            continue
        lineno = getattr(node, "lineno", None)
        if lineno is None or _has_safe_path_context(lines, lineno):
            continue
        findings.append(
            ScannerFinding(
                finding_id="AS-SCAN-001",
                category="path_traversal",
                severity="critical",
                title="Path-like input flows into file-system sink without normalization guard",
                description="A path/filename variable reaches a file-system sink without nearby normalization or boundary checks.",
                recommendation="Normalize with resolve()/relative_to() or an equivalent boundary check before using user-influenced paths.",
                file_path=display_path,
                line_start=lineno,
                line_end=lineno,
                evidence=_line_evidence(lines, lineno),
            )
        )
    return findings


def _check_command_execution(
    display_path: str,
    lines: list[str],
    tree: ast.AST | None,
) -> list[ScannerFinding]:
    if tree is None:
        return []

    findings: list[ScannerFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        if _is_subprocess_shell_true(node) or _is_os_system(node) or _is_nonliteral_eval_exec(node):
            findings.append(
                ScannerFinding(
                    finding_id="AS-SCAN-002",
                    category="command_execution",
                    severity="critical",
                    title="Command execution sink detected",
                    description="The file uses command execution primitives that can expand attacker-controlled input.",
                    recommendation="Remove shell execution, prefer argument lists, and avoid eval/exec on dynamic input.",
                    file_path=display_path,
                    line_start=lineno,
                    line_end=lineno,
                    evidence=_line_evidence(lines, lineno),
                )
            )
    return findings


def _check_missing_token_validation(
    path: Path,
    display_path: str,
    lines: list[str],
    text: str,
) -> list[ScannerFinding]:
    if path.suffix.lower() != ".py":
        return []

    lower_path = display_path.lower()
    if "authorization" not in text.lower():
        return []
    if "validate_token(" in text:
        return []
    if not any(fragment in lower_path for fragment in ("wrapper", "proxy")):
        return []

    evidence = []
    for index, line in enumerate(lines, start=1):
        if "authorization" in line.lower():
            evidence.extend(_line_evidence(lines, index))
            break
    return [
        ScannerFinding(
            finding_id="AS-SCAN-003",
            category="token_validation",
            severity="high",
            title="Authorization handling without validate_token()",
            description="Wrapper/proxy-like code references Authorization handling but does not appear to call validate_token().",
            recommendation="Call validate_token() before trusting Authorization-bearing requests.",
            file_path=display_path,
            line_start=_first_matching_line(lines, "authorization"),
            line_end=_first_matching_line(lines, "authorization"),
            evidence=evidence or ["Authorization handling detected without validate_token()"],
        )
    ]


def _check_hardcoded_secrets(display_path: str, lines: list[str]) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    patterns = (
        re.compile(r"sk-[A-Za-z0-9]{10,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(
            r'(?i)\b[\w"\'.-]*(?:secret|api_key|access_key|private_key)\b["\']?\s*[:=]\s*["\']([A-Za-z0-9_/\-+=]{12,})["\']'
        ),
    )
    for line_number, line in enumerate(lines, start=1):
        matches = [match for pattern in patterns for match in pattern.finditer(line)]
        if not matches:
            continue
        redacted_line = line
        for match in matches:
            redacted_line = redacted_line.replace(match.group(0), _redact_secret(match.group(0)))
        findings.append(
            ScannerFinding(
                finding_id="AS-SCAN-004",
                category="hardcoded_secret",
                severity="high",
                title="Possible hardcoded secret detected",
                description="The file contains text that looks like an embedded secret or private key material.",
                recommendation="Remove hardcoded secrets, rotate exposed credentials, and load them from environment or secret storage.",
                file_path=display_path,
                line_start=line_number,
                line_end=line_number,
                evidence=[redacted_line.strip()],
            )
        )
    return findings


def _check_wildcard_allowlists(path: Path, display_path: str, lines: list[str]) -> list[ScannerFinding]:
    if path.suffix.lower() not in {".json", ".yaml", ".yml", ".toml"}:
        return []

    findings: list[ScannerFinding] = []
    for index, line in enumerate(lines, start=1):
        if "allowed_tools" not in line and "egress_allowlist" not in line:
            continue
        block = "\n".join(lines[index - 1 : min(len(lines), index + 4)])
        if re.search(r'["\']\*["\']', block) or re.search(r"=\s*\[[^\]]*\*[^\]]*\]", block):
            findings.append(
                ScannerFinding(
                    finding_id="AS-SCAN-005",
                    category="wildcard_allowlist",
                    severity="high",
                    title="Wildcard allowlist entry detected",
                    description="The configuration uses '*' in an allowlist field, which widens access beyond a bounded policy.",
                    recommendation="Replace wildcard allowlists with explicit tool names or explicit egress hosts.",
                    file_path=display_path,
                    line_start=index,
                    line_end=index,
                    evidence=[line.strip()],
                )
            )
    return findings


def _check_unsafe_yaml_load(
    display_path: str,
    lines: list[str],
    tree: ast.AST | None,
) -> list[ScannerFinding]:
    if tree is None:
        return []

    findings: list[ScannerFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_yaml_load(node):
            continue
        if any(keyword.arg == "Loader" and _expr_mentions_safe_loader(keyword.value) for keyword in node.keywords):
            continue
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        findings.append(
            ScannerFinding(
                finding_id="AS-SCAN-006",
                category="unsafe_yaml",
                severity="medium",
                title="yaml.load() without SafeLoader",
                description="yaml.load() is used without SafeLoader, which can deserialize unsafe objects.",
                recommendation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
                file_path=display_path,
                line_start=lineno,
                line_end=lineno,
                evidence=_line_evidence(lines, lineno),
            )
        )
    return findings


def _check_insecure_tempfiles(
    display_path: str,
    lines: list[str],
    tree: ast.AST | None,
) -> list[ScannerFinding]:
    if tree is None:
        return []

    findings: list[ScannerFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        if _is_tempfile_mktemp(node):
            findings.append(
                ScannerFinding(
                    finding_id="AS-SCAN-007",
                    category="tempfile",
                    severity="medium",
                    title="tempfile.mktemp() detected",
                    description="tempfile.mktemp() creates predictable temporary paths and is unsafe.",
                    recommendation="Use NamedTemporaryFile or mkstemp with explicit permissions and cleanup.",
                    file_path=display_path,
                    line_start=lineno,
                    line_end=lineno,
                    evidence=_line_evidence(lines, lineno),
                )
            )
            continue
        if _is_named_temporary_file_delete_false(node) and not _has_cleanup_context(lines, lineno):
            findings.append(
                ScannerFinding(
                    finding_id="AS-SCAN-007",
                    category="tempfile",
                    severity="medium",
                    title="NamedTemporaryFile(delete=False) without nearby cleanup",
                    description="A temporary file is left on disk without nearby cleanup or permission handling cues.",
                    recommendation="Document cleanup, remove the file explicitly, or avoid delete=False where possible.",
                    file_path=display_path,
                    line_start=lineno,
                    line_end=lineno,
                    evidence=_line_evidence(lines, lineno),
                )
            )
    return findings


def _check_weak_hash_usage(display_path: str, lines: list[str]) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    pattern = re.compile(r"\b(?:hashlib\.)?(md5|sha1)\s*\(")
    for line_number, line in enumerate(lines, start=1):
        match = pattern.search(line)
        if match is None:
            continue
        lower_line = line.lower()
        severity: Severity = "medium"
        if any(token in lower_line for token in ("identifier", "cache", "etag", "fingerprint", "_id", "id =")):
            severity = "low"
        findings.append(
            ScannerFinding(
                finding_id="AS-SCAN-008",
                category="weak_hash",
                severity=severity,
                title="Weak hash algorithm detected",
                description="md5/sha1 appears in code. These hashes should not be used for integrity or security decisions.",
                recommendation="Prefer sha256 or a stronger modern hash unless the use is explicitly non-security and documented.",
                file_path=display_path,
                line_start=line_number,
                line_end=line_number,
                evidence=[line.strip()],
            )
        )
    return findings


def _check_broad_exceptions(path: Path, display_path: str, lines: list[str]) -> list[ScannerFinding]:
    normalized_path = display_path.replace("\\", "/")
    if not any(fragment in normalized_path for fragment in _SECURITY_SENSITIVE_PATHS):
        return []

    findings: list[ScannerFinding] = []
    for line_number, line in enumerate(lines, start=1):
        if not re.match(r"^\s*except\s+Exception(?:\s+as\s+\w+)?\s*:", line):
            continue
        block = "\n".join(lines[line_number : min(len(lines), line_number + 3)])
        if "raise" in block or "logger." in block or "logging." in block:
            continue
        findings.append(
            ScannerFinding(
                finding_id="AS-SCAN-009",
                category="broad_exception",
                severity="low",
                title="Broad exception handler without nearby raise/log context",
                description="Security-sensitive code catches Exception without obvious re-raise or log context nearby.",
                recommendation="Catch narrower exceptions or add structured logging / re-raise context.",
                file_path=display_path,
                line_start=line_number,
                line_end=line_number,
                evidence=[line.strip()],
            )
        )
    return findings


def _check_overwrite_style_evidence_writes(display_path: str, lines: list[str]) -> list[ScannerFinding]:
    if not display_path.endswith(".py"):
        return []

    findings: list[ScannerFinding] = []
    for artifact in _EVIDENCE_ARTIFACTS:
        for index, line in enumerate(lines, start=1):
            window = "\n".join(lines[max(0, index - 3) : min(len(lines), index + 2)])
            if artifact not in window:
                continue
            if not any(helper in window for helper in _WRITE_HELPERS):
                continue
            if "os.replace" in window or "atomic" in window:
                continue
            findings.append(
                ScannerFinding(
                    finding_id="AS-SCAN-010",
                    category="evidence_write",
                    severity="low",
                    title="Advisory overwrite-style write for evidence artifact",
                    description="Evidence artifact handling appears to rely on overwrite-style writes instead of temp-file plus atomic replace.",
                    recommendation="For stronger durability guarantees, write evidence artifacts via temp files and atomic replace.",
                    file_path=display_path,
                    line_start=index,
                    line_end=index,
                    evidence=[line.strip()],
                )
            )
            break
    return findings


def _check_pii_logging(display_path: str, lines: list[str]) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        if ("logger." not in lowered and "logging." not in lowered) or not any(
            token in lowered for token in ("authorization", "inputs", "raw_request")
        ):
            continue
        findings.append(
            ScannerFinding(
                finding_id="AS-SCAN-011",
                category="logging",
                severity="info",
                title="Potential PII or credential logging",
                description="A logging statement references Authorization data, inputs, or raw request content.",
                recommendation="Avoid logging sensitive headers or raw request bodies. Log bounded metadata instead.",
                file_path=display_path,
                line_start=line_number,
                line_end=line_number,
                evidence=[line.strip()],
            )
        )
    return findings


def _path_sink_argument(node: ast.Call) -> ast.AST | None:
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open" and node.args:
        return node.args[0]
    if isinstance(func, ast.Attribute):
        if (
            isinstance(func.value, ast.Call)
            and _is_path_constructor(func.value)
            and func.attr in {"read_text", "write_text", "unlink", "open"}
            and func.value.args
        ):
            return func.value.args[0]
        if isinstance(func.value, ast.Name) and func.value.id == "os" and func.attr in {"remove", "unlink"} and node.args:
            return node.args[0]
        if (
            isinstance(func.value, ast.Name)
            and func.value.id == "shutil"
            and func.attr in {"rmtree", "copy", "copy2", "copyfile"}
            and node.args
        ):
            return node.args[0]
    return None


def _candidate_variable_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Attribute):
        names.extend(_candidate_variable_names(node.value))
        names.append(node.attr)
    elif isinstance(node, ast.Call):
        for arg in node.args:
            names.extend(_candidate_variable_names(arg))
        for keyword in node.keywords:
            names.extend(_candidate_variable_names(keyword.value))
    elif isinstance(node, ast.BinOp):
        names.extend(_candidate_variable_names(node.left))
        names.extend(_candidate_variable_names(node.right))
    elif isinstance(node, ast.Subscript):
        names.extend(_candidate_variable_names(node.value))
        names.extend(_candidate_variable_names(node.slice))
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            names.extend(_candidate_variable_names(value))
    elif isinstance(node, ast.FormattedValue):
        names.extend(_candidate_variable_names(node.value))
    elif isinstance(node, ast.Tuple | ast.List | ast.Set):
        for item in node.elts:
            names.extend(_candidate_variable_names(item))
    return names


def _looks_like_untrusted_path(name: str) -> bool:
    lowered = name.lower()
    return "path" in lowered or "filename" in lowered


def _has_safe_path_context(lines: list[str], lineno: int) -> bool:
    start = max(0, lineno - 4)
    end = min(len(lines), lineno + 1)
    block = "\n".join(lines[start:end])
    return any(token in block for token in _SAFE_PATH_TOKENS)


def _is_path_constructor(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id == "Path"
    if isinstance(node.func, ast.Attribute):
        return node.func.attr == "Path"
    return False


def _is_subprocess_shell_true(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if not isinstance(node.func.value, ast.Name) or node.func.value.id != "subprocess":
        return False
    return any(keyword.arg == "shell" and _keyword_is_true(keyword.value) for keyword in node.keywords)


def _is_os_system(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "system"
    )


def _is_nonliteral_eval_exec(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Name) or node.func.id not in {"eval", "exec"} or not node.args:
        return False
    return not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str))


def _is_yaml_load(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "yaml"
        and node.func.attr == "load"
    )


def _expr_mentions_safe_loader(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr == "SafeLoader" or _expr_mentions_safe_loader(node.value)
    if isinstance(node, ast.Name):
        return node.id == "SafeLoader"
    return False


def _is_tempfile_mktemp(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "tempfile"
        and node.func.attr == "mktemp"
    )


def _is_named_temporary_file_delete_false(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        name = node.func.attr
    else:
        return False
    if name != "NamedTemporaryFile":
        return False
    return any(keyword.arg == "delete" and _keyword_is_false(keyword.value) for keyword in node.keywords)


def _has_cleanup_context(lines: list[str], lineno: int) -> bool:
    block = "\n".join(lines[lineno - 1 : min(len(lines), lineno + 5)])
    return any(token in block for token in ("unlink(", "cleanup", "os.remove(", "chmod(", "remove("))


def _keyword_is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _keyword_is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _redact_secret(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}...{value[-4:]}"


def _line_evidence(lines: list[str], line_number: int) -> list[str]:
    if line_number < 1 or line_number > len(lines):
        return []
    return [lines[line_number - 1].strip()]


def _first_matching_line(lines: list[str], substring: str) -> int | None:
    for index, line in enumerate(lines, start=1):
        if substring.lower() in line.lower():
            return index
    return None


def _build_summary(findings: list[ScannerFinding]) -> dict[str, int]:
    summary: dict[str, int] = {severity: 0 for severity in _SUMMARY_ORDER}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def _display_path(path: Path, target: Path, root_dir: Path) -> str:
    if target.is_dir():
        return str(path.relative_to(root_dir)).replace("\\", "/")
    return path.name


def _finding_sort_key(finding: ScannerFinding) -> tuple[str, int, str]:
    line_start = finding.line_start if finding.line_start is not None else 10**9
    return (finding.file_path, line_start, finding.finding_id)
