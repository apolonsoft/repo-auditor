import io
import re
import tempfile
import zipfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import httpx

GITHUB_URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+?)(?:\.git)?(?:/.*)?$"
)
SHORTHAND_PATTERN = re.compile(r"^([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)$")


def parse_github_target(target: str) -> tuple[str, str] | None:
    target = target.strip()
    match = GITHUB_URL_PATTERN.match(target)
    if match:
        return match.group(1), match.group(2)
    match_short = SHORTHAND_PATTERN.match(target)
    if match_short:
        return match_short.group(1), match_short.group(2)
    return None


@contextmanager
def fetch_remote_repo_in_memory(
    owner: str,
    repo: str,
    token: str | None = None,
) -> Generator[Path, None, None]:
    """
    Downloads repository archive directly into memory as a zip stream,
    extracts into an ephemeral temporary directory, and yields the Path.
    Does not run `git clone` and automatically deletes everything on exit.
    """
    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "repo-auditor-scanner",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        resp = client.get(zip_url, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to fetch remote repository {owner}/{repo}: HTTP {resp.status_code} ({resp.text[:100]})"
            )

        zip_bytes = io.BytesIO(resp.content)

        with tempfile.TemporaryDirectory(prefix=f"audit_{owner}_{repo}_") as temp_dir:
            temp_path = Path(temp_dir)
            with zipfile.ZipFile(zip_bytes) as z:
                z.extractall(temp_path)

            # GitHub zipballs wrap contents in a single top-level directory: owner-repo-sha/
            extracted_roots = [p for p in temp_path.iterdir() if p.is_dir()]
            target_path = extracted_roots[0] if extracted_roots else temp_path

            yield target_path
