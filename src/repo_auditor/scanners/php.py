import json
import re
from pathlib import Path

from repo_auditor.models import AuditReport, Finding, Severity
from repo_auditor.scanners.osv import audit_dependencies_osv

OFFICIAL_PACKAGIST_URL = "https://repo.packagist.org"

COMPOSER_LIFECYCLE_HOOKS = [
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "pre-autoload-dump",
    "post-autoload-dump",
    "post-root-package-install",
    "post-create-project-cmd",
    "pre-package-install",
    "post-package-install",
]

DANGEROUS_COMPOSER_PATTERNS = [
    (r"\b(curl|wget|fetch)\b", "Downloads external remote payload", Severity.CRITICAL),
    (r"\b(powershell|cmd\.exe|bash|sh|zsh)\b", "Directly invokes system shell", Severity.HIGH),
    (r"php\s+-r\s+['\"].*['\"]", "Executes inline PHP code", Severity.HIGH),
    (r"\b(base64_decode|gzinflate|str_rot13)\b", "Obfuscated payload decoding", Severity.HIGH),
    (
        r"(discord\.com/api/webhooks|api\.telegram\.org|webhook\.site|pastebin\.com|ngrok)",
        "Known data exfiltration endpoint",
        Severity.CRITICAL,
    ),
    (
        r"\b(passthru|shell_exec|exec|system|proc_open|popen)\b",
        "Command execution function in script",
        Severity.HIGH,
    ),
]

PHP_MALWARE_PATTERNS = [
    (
        r"(?:eval|assert|passthru|shell_exec|system|exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
        "Webshell backdoor: direct execution of user input",
        Severity.CRITICAL,
    ),
    (
        r"preg_replace\s*\(\s*['\"].*\/e['\"]",
        "Deprecated preg_replace /e arbitrary code evaluation",
        Severity.HIGH,
    ),
    (
        r"base64_decode\s*\(\s*(?:gzinflate|gzuncompress|str_rot13)\s*\(",
        "Multi-layered obfuscated code execution",
        Severity.CRITICAL,
    ),
    (
        r"\b(fsockopen|pfsockopen|stream_socket_client)\s*\(",
        "Raw outbound socket connection",
        Severity.HIGH,
    ),
    (
        r"/bin/(?:bash|sh)\s+-i",
        "Interactive reverse shell command",
        Severity.CRITICAL,
    ),
    (
        r"https?://(?:discord\.com/api/webhooks|api\.telegram\.org|webhook\.site|pastebin\.com|ngrok\.io)",
        "Known data exfiltration endpoint",
        Severity.CRITICAL,
    ),
]


def audit_composer_json(composer_path: Path, report: AuditReport) -> None:
    try:
        data = json.loads(composer_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        report.add(
            Finding(
                category="Composer Manifest",
                severity=Severity.LOW,
                title="Invalid composer.json",
                description=f"Could not parse JSON: {e}",
                file_path=composer_path,
            )
        )
        return

    # 1. Audit custom repositories (Dependency Confusion / Hijacking risk)
    repositories = data.get("repositories", [])
    if isinstance(repositories, dict):
        repo_items = repositories.values()
    elif isinstance(repositories, list):
        repo_items = repositories
    else:
        repo_items = []

    for repo_entry in repo_items:
        if isinstance(repo_entry, dict):
            repo_url = repo_entry.get("url", "")
            if repo_url:
                if repo_url.startswith("http://"):
                    report.add(
                        Finding(
                            category="Composer Repository Security",
                            severity=Severity.CRITICAL,
                            title="Insecure HTTP Composer Repository",
                            description=f"Repository URL uses unencrypted HTTP ({repo_url}), vulnerable to MitM attacks.",
                            file_path=composer_path,
                            snippet=f'"url": "{repo_url}"',
                        )
                    )
                elif not repo_url.startswith(OFFICIAL_PACKAGIST_URL):
                    report.add(
                        Finding(
                            category="Composer Repository Security",
                            severity=Severity.HIGH,
                            title="Custom Third-Party Composer Repository",
                            description=(
                                f"Custom repository configured: {repo_url}. "
                                "Ensure this endpoint is trusted to prevent dependency confusion."
                            ),
                            file_path=composer_path,
                            snippet=f'"url": "{repo_url}"',
                        )
                    )

    # 2. Audit scripts and lifecycle hooks
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for hook, commands in scripts.items():
            cmd_list = commands if isinstance(commands, list) else [commands]
            for cmd in cmd_list:
                cmd_str = str(cmd).strip()
                is_lifecycle = hook in COMPOSER_LIFECYCLE_HOOKS
                hook_matched = False

                for pattern, desc, severity in DANGEROUS_COMPOSER_PATTERNS:
                    if re.search(pattern, cmd_str, re.IGNORECASE):
                        report.add(
                            Finding(
                                category="Composer Script Hook",
                                severity=severity,
                                title=f"Suspicious `{hook}` Hook: {desc}",
                                description=f"Script `{hook}` contains dangerous pattern: {desc}",
                                file_path=composer_path,
                                snippet=f'"{hook}": "{cmd_str}"',
                            )
                        )
                        hook_matched = True

                if (
                    is_lifecycle
                    and not hook_matched
                    and any(w in cmd_str for w in ["@", "bash", "sh", "php"])
                ):
                    report.add(
                        Finding(
                            category="Composer Script Hook",
                            severity=Severity.LOW,
                            title=f"Custom `{hook}` Lifecycle Script Present",
                            description=f"Executes automatically on composer install/update: `{cmd_str}`",
                            file_path=composer_path,
                            snippet=f'"{hook}": "{cmd_str}"',
                        )
                    )

    # 3. Query OSV for Packagist dependencies
    deps: dict = {}
    deps.update(data.get("require", {}))
    deps.update(data.get("require-dev", {}))

    osv_candidates: list[tuple[str, str | None]] = []
    for name, version in deps.items():
        # Skip php version constraints or extensions like ext-json
        if name.lower() == "php" or name.startswith("ext-"):
            continue
        osv_candidates.append((name, str(version)))

    audit_dependencies_osv(osv_candidates, "Packagist", report, str(composer_path.name))


def audit_composer_lock(lock_path: Path, report: AuditReport) -> None:
    """Check composer.lock download URLs for unencrypted HTTP."""
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return

    packages = data.get("packages", []) + data.get("packages-dev", [])
    for pkg in packages:
        if isinstance(pkg, dict):
            pkg_name = pkg.get("name", "unknown")
            dist = pkg.get("dist", {})
            dist_url = dist.get("url", "")
            if dist_url.startswith("http://"):
                report.add(
                    Finding(
                        category="Composer Lockfile Security",
                        severity=Severity.CRITICAL,
                        title=f"Composer Insecure Download URL: {pkg_name}",
                        description=f"Package download URL uses unencrypted HTTP: {dist_url}",
                        file_path=lock_path,
                        snippet=dist_url,
                    )
                )


def audit_php_files(repo_path: Path, report: AuditReport) -> None:
    php_files = [
        f
        for f in repo_path.rglob("*.php")
        if not any(p in f.parts for p in ["vendor", ".git", "storage", "cache"])
    ]

    for file in php_files:
        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line_idx, line in enumerate(lines, 1):
                for pattern, desc, severity in PHP_MALWARE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        report.add(
                            Finding(
                                category="PHP Code Heuristic",
                                severity=severity,
                                title=desc,
                                description=f"Suspicious PHP pattern found: {desc}",
                                file_path=file,
                                line_number=line_idx,
                                snippet=line.strip()[:100],
                            )
                        )
        except Exception:
            continue


def scan_php_ecosystem(repo_path: Path, report: AuditReport) -> None:
    # 1. Audit composer.json files (excluding vendor)
    for composer_json in repo_path.rglob("composer.json"):
        if "vendor" not in composer_json.parts:
            audit_composer_json(composer_json, report)

    # 2. Audit composer.lock files
    for composer_lock in repo_path.rglob("composer.lock"):
        if "vendor" not in composer_lock.parts:
            audit_composer_lock(composer_lock, report)

    # 3. Audit PHP source code heuristics
    audit_php_files(repo_path, report)
