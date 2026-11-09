import json
import re
from pathlib import Path

from repo_auditor.models import AuditReport, Finding, Severity
from repo_auditor.scanners.osv import audit_dependencies_osv

OFFICIAL_NPM_REGISTRIES = [
    "https://registry.npmjs.org",
    "https://registry.npmjs.org/",
    "https://registry.yarnpkg.com",
    "https://registry.yarnpkg.com/",
]

LIFECYCLE_HOOKS = [
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
    "prepare",
    "postpack",
]

DANGEROUS_HOOK_PATTERNS = [
    (r"\b(curl|wget|fetch|axios)\b", "Downloads external remote payload", Severity.CRITICAL),
    (r"\b(powershell|cmd\.exe|bash|sh|zsh)\b", "Directly invokes system shell", Severity.HIGH),
    (r"node\s+-e\s+['\"].*['\"]", "Executes inline Node.js script", Severity.HIGH),
    (r"python(?:\d)?\s+-c\s+['\"].*['\"]", "Executes inline Python script", Severity.HIGH),
    (r"\b(base64|Buffer\.from|atob)\b", "Possible obfuscated payload", Severity.HIGH),
    (r"\.(sh|bat|cmd|exe|ps1|vbs)\b", "Executes downloaded script or binary", Severity.HIGH),
    (
        r"(token|secret|password|id_rsa|\.env|\.npmrc)",
        "Targets credentials or private keys",
        Severity.HIGH,
    ),
    (
        r"(discord\.com/api/webhooks|api\.telegram\.org|webhook\.site|pastebin\.com|ngrok)",
        "Known data exfiltration endpoint",
        Severity.CRITICAL,
    ),
]


def audit_npmrc(repo_path: Path, report: AuditReport) -> None:
    npmrc_files = list(repo_path.rglob(".npmrc"))
    # Exclude files inside node_modules
    npmrc_files = [f for f in npmrc_files if "node_modules" not in f.parts]

    for npmrc in npmrc_files:
        try:
            lines = npmrc.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line_no, raw_line in enumerate(lines, 1):
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                # Check registry definitions
                match = re.search(r"^(?:@[\w\-.]+:)?registry\s*=\s*(.+)$", line)
                if match:
                    reg_url = match.group(1).strip().strip("'\"")
                    if reg_url.startswith("http://"):
                        report.add(
                            Finding(
                                category="npmrc Security",
                                severity=Severity.CRITICAL,
                                title="Insecure HTTP Registry",
                                description=f"The registry uses unencrypted HTTP ({reg_url}), vulnerable to MitM attacks.",
                                file_path=npmrc,
                                line_number=line_no,
                                snippet=line,
                            )
                        )
                    else:
                        normalized = reg_url.rstrip("/") + "/"
                        is_official = any(
                            normalized == off.rstrip("/") + "/" for off in OFFICIAL_NPM_REGISTRIES
                        )
                        if not is_official:
                            report.add(
                                Finding(
                                    category="npmrc Security",
                                    severity=Severity.HIGH,
                                    title="Unofficial npm Registry",
                                    description=(
                                        f"Package registry points to an unofficial endpoint: {reg_url}. "
                                        "Verify this is an authorized internal registry to prevent dependency hijacking."
                                    ),
                                    file_path=npmrc,
                                    line_number=line_no,
                                    snippet=line,
                                )
                            )

                # Check for leaked tokens in .npmrc
                if any(k in line for k in ["_authToken", "_auth", "always-auth"]):
                    report.add(
                        Finding(
                            category="npmrc Security",
                            severity=Severity.CRITICAL,
                            title="Hardcoded npm Auth Token",
                            description="Sensitive npm credentials or auth token committed to repository.",
                            file_path=npmrc,
                            line_number=line_no,
                            snippet="[REDACTED AUTH TOKEN]",
                        )
                    )
        except Exception as e:
            report.add(
                Finding(
                    category="npmrc Security",
                    severity=Severity.LOW,
                    title="Could not read .npmrc",
                    description=str(e),
                    file_path=npmrc,
                )
            )


def audit_package_json(pkg_json_path: Path, report: AuditReport) -> None:
    try:
        data = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        report.add(
            Finding(
                category="npm Package Manifest",
                severity=Severity.LOW,
                title="Invalid package.json",
                description=f"Could not parse JSON: {e}",
                file_path=pkg_json_path,
            )
        )
        return

    # 1. Audit lifecycle hooks
    scripts = data.get("scripts", {})
    for hook in LIFECYCLE_HOOKS:
        if hook in scripts:
            cmd = str(scripts[hook]).strip()
            hook_matched = False
            for pattern, desc, severity in DANGEROUS_HOOK_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    report.add(
                        Finding(
                            category="npm Lifecycle Hook",
                            severity=severity,
                            title=f"Suspicious `{hook}` Hook: {desc}",
                            description=f"Automated installation script `{hook}` contains dangerous pattern: {desc}",
                            file_path=pkg_json_path,
                            snippet=f'"{hook}": "{cmd}"',
                        )
                    )
                    hook_matched = True

            if not hook_matched:
                report.add(
                    Finding(
                        category="npm Lifecycle Hook",
                        severity=Severity.MEDIUM,
                        title=f"Custom `{hook}` Lifecycle Script Present",
                        description=f"Script runs automatically on install/build: `{cmd}`. Verify its integrity.",
                        file_path=pkg_json_path,
                        snippet=f'"{hook}": "{cmd}"',
                    )
                )

    # 2. Check for non-registry dependency sources
    deps = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))

    osv_candidates: list[tuple[str, str | None]] = []

    for name, spec in deps.items():
        spec_str = str(spec).strip()
        if any(
            prefix in spec_str for prefix in ["http://", "https://", "git+", "git://", "github:"]
        ):
            report.add(
                Finding(
                    category="npm Dependency Source",
                    severity=Severity.HIGH,
                    title=f"External Direct URL Dependency: {name}",
                    description=f"Package bypasses registry and installs directly from: {spec_str}",
                    file_path=pkg_json_path,
                    snippet=f'"{name}": "{spec_str}"',
                )
            )
        elif spec_str.startswith("file:"):
            report.add(
                Finding(
                    category="npm Dependency Source",
                    severity=Severity.LOW,
                    title=f"Local Path Dependency: {name}",
                    description=f"Installs from local filesystem: {spec_str}",
                    file_path=pkg_json_path,
                    snippet=f'"{name}": "{spec_str}"',
                )
            )
        else:
            osv_candidates.append((name, spec_str))

    # 3. Query OSV for npm dependencies
    audit_dependencies_osv(osv_candidates, "npm", report, str(pkg_json_path.name))


def audit_package_lock(lock_path: Path, report: AuditReport) -> None:
    """Check package-lock.json resolved URLs for non-official hostnames or unencrypted HTTP."""
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return

    packages = data.get("packages", {})
    for pkg_key, pkg_info in packages.items():
        resolved = pkg_info.get("resolved", "")
        if not resolved:
            continue
        if resolved.startswith("http://"):
            report.add(
                Finding(
                    category="npm Lockfile Security",
                    severity=Severity.CRITICAL,
                    title=f"Lockfile Insecure Download: {pkg_key or 'root'}",
                    description=f"Package resolved URL uses unencrypted HTTP: {resolved}",
                    file_path=lock_path,
                    snippet=resolved,
                )
            )
        elif not any(resolved.startswith(off) for off in OFFICIAL_NPM_REGISTRIES):
            # Check if it's GitHub or another common trusted host
            if not any(trusted in resolved for trusted in ["github.com", "npm.pkg.github.com"]):
                report.add(
                    Finding(
                        category="npm Lockfile Security",
                        severity=Severity.HIGH,
                        title=f"Lockfile External Resolved Host: {pkg_key or 'root'}",
                        description=f"Resolved URL does not point to official npm registry: {resolved}",
                        file_path=lock_path,
                        snippet=resolved,
                    )
                )


def scan_npm_ecosystem(repo_path: Path, report: AuditReport) -> None:
    audit_npmrc(repo_path, report)

    # Audit package.json files (excluding node_modules)
    for pkg_json in repo_path.rglob("package.json"):
        if "node_modules" not in pkg_json.parts:
            audit_package_json(pkg_json, report)

    # Audit package-lock.json files
    for lock in repo_path.rglob("package-lock.json"):
        if "node_modules" not in lock.parts:
            audit_package_lock(lock, report)
