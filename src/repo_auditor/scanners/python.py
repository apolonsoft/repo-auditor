import ast
import re
from pathlib import Path

from repo_auditor.models import AuditReport, Finding, Severity
from repo_auditor.scanners.osv import audit_dependencies_osv

PY_SUSPICIOUS_REGEX = [
    (r"base64\.b64decode\(.+\)\.(?:decode|read|exec)", "Base64 payload execution", Severity.HIGH),
    (
        r"subprocess\.(?:Popen|call|run|check_output)\(.*(?:curl|wget|bash|sh|powershell)",
        "Process execution invoking network fetch or shell",
        Severity.CRITICAL,
    ),
    (r"socket\.socket\(.*\)\.connect\(", "Raw outbound TCP socket connection", Severity.HIGH),
    (r"getattr\(.*__builtins__", "Dynamic builtin resolution / sandbox escape", Severity.HIGH),
    (
        r"(?:discord\.com/api/webhooks|api\.telegram\.org|webhook\.site|pastebin\.com)",
        "Known data exfiltration endpoint",
        Severity.CRITICAL,
    ),
    (
        r"os\.environ\[['\"](?:AWS_SECRET|GITHUB_TOKEN|SLACK_TOKEN)",
        "Sensitive token access",
        Severity.HIGH,
    ),
]


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, report: AuditReport):
        self.file_path = file_path
        self.report = report

    def visit_Call(self, node: ast.Call) -> None:
        # Check eval() or exec()
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.report.add(
                Finding(
                    category="Python Code Heuristic",
                    severity=Severity.HIGH,
                    title=f"Dynamic Code Execution (`{node.func.id}`)",
                    description=f"Direct call to `{node.func.id}()` allows arbitrary execution if input is tainted.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                )
            )

        # Check __import__ with dynamic arguments
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            self.report.add(
                Finding(
                    category="Python Code Heuristic",
                    severity=Severity.MEDIUM,
                    title="Dynamic `__import__` Invocation",
                    description="Dynamic module importing used often to bypass static scanners.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                )
            )

        self.generic_visit(node)


def audit_requirements_file(req_path: Path, report: AuditReport) -> None:
    packages: list[tuple[str, str | None]] = []
    try:
        lines = req_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Flag direct URLs / git in requirements.txt
            if any(prefix in line for prefix in ["git+", "http://", "https://", "svn+"]):
                report.add(
                    Finding(
                        category="Python Dependency Source",
                        severity=Severity.HIGH,
                        title="Remote URL in requirements.txt",
                        description=f"Direct package install from remote URL: {line}",
                        file_path=req_path,
                        snippet=line,
                    )
                )
                continue

            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:==([a-zA-Z0-9_\-\.]+))?", line)
            if match:
                pkg, ver = match.groups()
                packages.append((pkg, ver))
    except Exception:
        pass

    audit_dependencies_osv(packages, "PyPI", report, req_path.name)


def audit_python_files(repo_path: Path, report: AuditReport) -> None:
    py_files = list(repo_path.rglob("*.py"))
    # Exclude virtual environments
    py_files = [
        f
        for f in py_files
        if not any(p in f.parts for p in [".venv", "venv", ".git", "site-packages"])
    ]

    for file in py_files:
        try:
            content = file.read_text(encoding="utf-8", errors="ignore")

            # Check setup.py specifically for dangerous calls
            if file.name.lower() == "setup.py":
                if any(
                    tool in content for tool in ["subprocess", "os.system", "requests", "urllib"]
                ):
                    report.add(
                        Finding(
                            category="Python Setup Script",
                            severity=Severity.HIGH,
                            title="Command Execution / Network in setup.py",
                            description="`setup.py` executes system commands or network requests during `pip install`.",
                            file_path=file,
                        )
                    )

            # Regex scanning
            for pattern, desc, severity in PY_SUSPICIOUS_REGEX:
                for line_idx, line in enumerate(content.splitlines(), 1):
                    if re.search(pattern, line):
                        report.add(
                            Finding(
                                category="Python Code Heuristic",
                                severity=severity,
                                title=desc,
                                description=f"Suspicious pattern detected: {desc}",
                                file_path=file,
                                line_number=line_idx,
                                snippet=line.strip()[:100],
                            )
                        )

            # AST scanning
            tree = ast.parse(content, filename=str(file))
            visitor = PythonSecurityVisitor(file, report)
            visitor.visit(tree)

        except SyntaxError:
            continue
        except Exception:
            continue


def scan_python_ecosystem(repo_path: Path, report: AuditReport) -> None:
    for req_file in repo_path.rglob("*requirements*.txt"):
        if not any(p in req_file.parts for p in [".venv", "venv", "site-packages"]):
            audit_requirements_file(req_file, report)

    audit_python_files(repo_path, report)
