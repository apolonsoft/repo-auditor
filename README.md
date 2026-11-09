# repo-auditor 🛡️

**repo-auditor** is a fast, automated security auditor designed to detect malware, software supply chain attacks, compromised package registries, dangerous lifecycle hooks, and vulnerable dependencies in both local and remote GitHub repositories.

Built with **Python 3.10+**, **Typer**, **Rich**, and managed with **uv** and **Ruff**.

---

## 🌟 Key Features

### 1. In-Memory Remote GitHub Scanning (Zero `git clone`)
- **No Disk Footprint / Safe Execution:** Test any public or private GitHub repository without cloning its git history or saving code locally.
- **Archive Streaming:** Streams repository archives directly into memory via GitHub's API, runs the security audit inside an ephemeral isolated sandbox, and purges all traces immediately upon completion.
- **Shorthand Support:** Accepts full URLs (`https://github.com/owner/repo`) or shorthand (`owner/repo`).

### 2. PHP & Composer Security Auditing
- **Composer Repository Auditing:**
  - Detects unencrypted `http://` custom repositories in `composer.json`.
  - Flags non-official third-party repositories that could expose the build to dependency confusion attacks.
- **Composer Script & Lifecycle Hooks:**
  - Audits `pre-install-cmd`, `post-install-cmd`, `pre-update-cmd`, `post-autoload-dump`, etc.
  - Flags dangerous operations in hooks: `curl`, `wget`, inline `php -r`, shell execution (`passthru`, `exec`, `shell_exec`), and webhook exfiltration.
- **Lockfile URL Auditing:**
  - Checks `composer.lock` for insecure package `dist.url` or `source.url` using unencrypted HTTP.
- **PHP Webshell & Malware Heuristics:**
  - Flags direct user-input execution backdoors: `eval($_POST)`, `assert($_GET)`, `system($_REQUEST)`.
  - Flags deprecated `/e` modifier regex execution (`preg_replace('/.../e', ...)`).
  - Detects multi-layer obfuscation (`base64_decode(gzinflate(...))`) and raw outbound socket connections (`fsockopen()`, reverse shells).
- **Packagist Dependency Vulnerabilities:**
  - Queries OSV for all Composer `require` and `require-dev` packages under the **Packagist** ecosystem.

### 3. npm & JavaScript/TypeScript Security
- **`.npmrc` Integrity Verification:**
  - Flags unencrypted `http://` registries vulnerable to Machine-in-the-Middle (MitM) attacks.
  - Detects non-official / rogue registries (protects against dependency confusion and internal scope hijacking).
  - Flags committed npm credentials and auth tokens (`_authToken`, `_auth`).
- **`package.json` Lifecycle Hook Auditing:**
  - Audits automated installation hooks (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, etc.).
  - Alerts on malicious command patterns:
    - **Remote payload downloaders:** `curl`, `wget`, `fetch`, `Invoke-WebRequest`
    - **Shell invocations:** `bash`, `sh`, `cmd.exe`, `powershell`, `node -e`, `python -c`
    - **Obfuscated execution:** `base64`, `Buffer.from`, `atob`
    - **Data exfiltration endpoints:** Discord webhooks, Telegram bots, `webhook.site`, `pastebin`
    - **Credential harvesting:** references to `.env`, `.npmrc`, `id_rsa`, `process.env.NPM_TOKEN`
- **Lockfile & Source Integrity:**
  - Scans `package-lock.json` to detect tampered `"resolved"` hosts or unencrypted download URLs.
  - Flags packages configured to install directly from external URLs, raw tarballs, or git links instead of verified registries.
- **JS/TS Static Heuristics:**
  - Flags interactive reverse shells, `child_process` execution, and sensitive environment variable exfiltration.

### 4. Python Security & Static AST Analysis
- **`setup.py` Execution Check:**
  - Inspects `setup.py` for arbitrary process execution (`subprocess`, `os.system`) or network requests triggered during `pip install`.
- **Abstract Syntax Tree (AST) & Code Heuristics:**
  - Detects dynamic code evaluation (`eval()`, `exec()`, dynamic `__import__`).
  - Detects base64 payload decoding, raw outbound TCP sockets, and sandbox escape attempts (`getattr(__builtins__)`).
- **Dependency Source Checking:**
  - Audits `requirements.txt` for remote URL installations or direct git dependencies.

### 5. Live Vulnerability & Malware Lookup (OSV.dev)
- Seamlessly queries Google's **Open Source Vulnerabilities (OSV) API** across **Packagist**, **npm**, and **PyPI** ecosystems.
- Matches against the **GitHub Advisory Database (GHSA)** to flag known CVEs and confirmed malicious/typosquatting packages.

---

## 🚀 Quickstart

### Prerequisites

- [uv](https://github.com/astral-sh/uv) (fast Python package manager)
- [make](https://www.gnu.org/software/make/) (standard build utility)

### 1. Install & Sync Dependencies

```bash
cd /home/ahmad/projects/repo-auditor

# Sync virtualenv and dependencies
make sync
```

---

## 🛠️ Usage via `make`

The repository includes a dedicated `Makefile` so you don't have to type `uv run`:

```bash
# 1. Scan the current project directory
make scan

# 2. Scan a local folder
make scan TARGET=/path/to/local-repo

# 3. Scan a remote GitHub repo in-memory (no git clone)
make scan TARGET=pallets/click
make scan TARGET=https://github.com/expressjs/express

# 4. Strict Mode (fails with exit code 1 if Critical or High issues exist)
make scan TARGET=pallets/click STRICT=1

# 5. Lint and format code with Ruff
make lint
make format

# 6. View all make commands
make help
```

---

## 💻 CLI Usage via `uv run`

You can also use the `repo-auditor` CLI directly:

```bash
# Basic scan
uv run repo-auditor .

# Remote scan with GitHub personal access token (for private repos or rate-limits)
uv run repo-auditor owner/private-repo --token ghp_yourTokenHere

# Strict CI/CD mode
uv run repo-auditor . --strict
```

### CLI Options

| Option | Short | Description |
| :--- | :--- | :--- |
| `target` | - | Directory path or remote GitHub URL / `owner/repo` shorthand. (Default: `.`) |
| `--strict` | `-s` | Return non-zero exit code (1) if Critical or High severity findings are found. |
| `--token` | `-t` | Optional GitHub Personal Access Token (can also be read from `GITHUB_TOKEN` env var). |
| `--help` | - | Show help message and exit. |

---

## 📊 Sample Output

```
╭───────────────────────────────────────────╮
│ Repo Auditor Security Report              │
│ Target: github.com/pallets/click          │
╰───────────────────────────────────────────╯

Detected Security Findings:
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Severity ┃ Category             ┃ Finding                                ┃ Location   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ MEDIUM   │ Python Code Heuristic│ Dynamic __import__ Invocation          │ cli.py:42  │
└──────────┴──────────────────────┴────────────────────────────────────────┴────────────┘

╭─ Summary ─╮
│ Critical: 0│
│ High:     0│
│ Medium:   1│
│ Low:      0│
╰───────────╯
```

---

## 🧪 Development & Code Quality

Code style, linting, and formatting are powered by **Ruff**:

```bash
# Check for issues
make lint

# Auto-format and fix
make format
```

---

## 📄 License

MIT License. Designed for security teams, developers, and automated CI pipelines.
