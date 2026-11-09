import re
from pathlib import Path

from repo_auditor.models import AuditReport, Finding, Severity

JS_SUSPICIOUS_PATTERNS = [
    (
        r"child_process\.(?:exec|execSync|spawn|spawnSync)\(",
        "Spawning system shell/process",
        Severity.HIGH,
    ),
    (r"\beval\(|new\s+Function\(", "Dynamic code evaluation (eval / Function)", Severity.HIGH),
    (r"Buffer\.from\(.+,\s*['\"]base64['\"]\)", "Base64 payload decoding", Severity.MEDIUM),
    (
        r"https?://(?:discord\.com/api/webhooks|api\.telegram\.org|webhook\.site|pastebin\.com|ngrok\.io)",
        "Known data exfiltration endpoint",
        Severity.CRITICAL,
    ),
    (
        r"process\.env\.(?:NPM_TOKEN|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN)",
        "Access to sensitive environment token",
        Severity.HIGH,
    ),
    (r"/bin/(?:bash|sh)\s+-i", "Interactive reverse shell invocation", Severity.CRITICAL),
]


def audit_javascript_files(repo_path: Path, report: AuditReport) -> None:
    js_extensions = {".js", ".mjs", ".cjs", ".ts", ".tsx"}
    files = [
        f
        for f in repo_path.rglob("*")
        if f.suffix in js_extensions
        and not any(p in f.parts for p in ["node_modules", "dist", "build", ".next", ".git"])
    ]

    for file in files:
        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line_idx, line in enumerate(lines, 1):
                for pattern, desc, severity in JS_SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line):
                        report.add(
                            Finding(
                                category="JS/TS Code Heuristic",
                                severity=severity,
                                title=desc,
                                description=f"Suspicious pattern found: {desc}",
                                file_path=file,
                                line_number=line_idx,
                                snippet=line.strip()[:100],
                            )
                        )
        except Exception:
            continue
