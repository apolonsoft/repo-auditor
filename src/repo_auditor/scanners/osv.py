import re

import httpx

from repo_auditor.models import AuditReport, Finding, Severity

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def clean_version(version_str: str | None) -> str | None:
    if not version_str:
        return None
    # Strip npm semver specifiers like ^, ~, >=, ==, <=, etc.
    cleaned = re.sub(r"^[^\d]*", "", version_str.strip())
    # Take the primary version part if there's a range (e.g., '1.0.0 - 2.0.0')
    cleaned = cleaned.split()[0] if cleaned else None
    return cleaned if cleaned else None


def check_package_osv(
    client: httpx.Client,
    package_name: str,
    version: str | None,
    ecosystem: str,
) -> list[dict]:
    """Query OSV API for a single package and ecosystem."""
    payload: dict = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        }
    }
    ver = clean_version(version)
    if ver:
        payload["version"] = ver

    try:
        resp = client.post(OSV_QUERY_URL, json=payload, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except Exception:
        pass
    return []


def audit_dependencies_osv(
    dependencies: list[tuple[str, str | None]],
    ecosystem: str,
    report: AuditReport,
    source_file: str,
) -> None:
    """Audit a list of (package_name, version) against OSV."""
    if not dependencies:
        return

    with httpx.Client() as client:
        for pkg_name, version in dependencies:
            vulns = check_package_osv(client, pkg_name, version, ecosystem)
            for vuln in vulns:
                vuln_id = vuln.get("id", "VULN-UNKNOWN")
                summary = vuln.get("summary") or vuln.get("details") or "Known vulnerability"
                summary = summary.split("\n")[0][:120]

                # Check if it's marked as malicious package
                is_malware = "malicious" in summary.lower() or any(
                    "malicious" in str(tag).lower()
                    for tag in vuln.get("database_specific", {}).values()
                )
                severity = Severity.CRITICAL if is_malware else Severity.HIGH

                report.add(
                    Finding(
                        category="Dependency Advisory (OSV)",
                        severity=severity,
                        title=f"{pkg_name} ({version or 'any'}) - {vuln_id}",
                        description=f"{'[MALWARE] ' if is_malware else ''}{summary}",
                        snippet=f"Ecosystem: {ecosystem} | Source: {source_file}",
                    )
                )
