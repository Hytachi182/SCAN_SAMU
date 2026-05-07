#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import html
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BANNER = r"""'######:::::'###::::'##::::'##:'##::::'##:
'##... ##:::'## ##::: ###::'###: ##:::: ##:
 ##:::..:::'##:. ##:: ####'####: ##:::: ##:
. ######::'##:::. ##: ## ### ##: ##:::: ##:
:..... ##: #########: ##. #: ##: ##:::: ##:
'##::: ##: ##.... ##: ##:.:: ##: ##:::: ##:
. ######:: ##:::: ##: ##:::: ##:. #######::
:......:::..:::::..::..:::::..:::.......:::"""


def log(level: str, message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}][{level}] {message}", file=sys.stderr)


def die(message: str, code: int = 1) -> None:
    log("ERROR", message)
    raise SystemExit(code)


def load_key_values(path: Path) -> dict[str, str]:
    if not path.exists():
        die(f"Fichier de configuration introuvable: {path}")

    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip("'\"")
    return data


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def safe_relative_repo_path(namespace: str) -> Path:
    parts = []
    for part in namespace.replace("\\", "/").split("/"):
        parts.append(re.sub(r'[<>:"\\|?*]', "_", part).strip() or "_")
    return Path(*parts)


def safe_raw_name(namespace: str) -> str:
    return namespace.replace("\\", "__").replace("/", "__")


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def docker_mount_path(path: Path) -> str:
    # Docker Desktop accepts absolute Windows paths and POSIX paths on Linux/macOS.
    return str(path.resolve())


@dataclass
class Context:
    root: Path
    config: dict[str, str]
    workspace: Path
    repos: Path
    raw: Path
    reports: Path
    hooks: Path

    @property
    def gitlab_base_url(self) -> str:
        return self.config["GITLAB_BASE_URL"].rstrip("/")

    @property
    def gitlab_group_path(self) -> str:
        return self.config["GITLAB_GROUP_PATH"]

    @property
    def gitlab_token(self) -> str:
        return self.config["GITLAB_TOKEN"]


def init_context(secrets_file: Path) -> Context:
    root = Path(__file__).resolve().parents[1]
    config = load_key_values(secrets_file)

    for key in ("GITLAB_BASE_URL", "GITLAB_GROUP_PATH", "GITLAB_TOKEN"):
        if not config.get(key):
            die(f"Cle obligatoire absente dans {secrets_file}: {key}")
    if not config["GITLAB_BASE_URL"].startswith("https://"):
        die("GITLAB_BASE_URL doit utiliser HTTPS")

    config.setdefault("DEFAULT_FALLBACK_BRANCH", "main")
    config.setdefault("WORKSPACE_DIR", "./data")
    config.setdefault("DETECT_SECRETS_IMAGE", "scan-secrets/detect-secrets:local")
    config.setdefault("GITLEAKS_IMAGES", "ghcr.io/gitleaks/gitleaks:latest,zricethezav/gitleaks:latest")
    config.setdefault("TRUFFLEHOG_IMAGES", "trufflesecurity/trufflehog:latest")
    config.setdefault("SEMGREP_IMAGES", "semgrep/semgrep:latest")
    config.setdefault("SEMGREP_CONFIGS", "/rules/semgrep-secrets.yml,p/secrets")
    config.setdefault("GITLAB_CURL_SSL_NO_REVOKE", "false")

    workspace = Path(config["WORKSPACE_DIR"])
    if not workspace.is_absolute():
        workspace = root / workspace
    workspace = workspace.resolve()

    ctx = Context(
        root=root,
        config=config,
        workspace=workspace,
        repos=workspace / "repos",
        raw=workspace / "raw",
        reports=workspace / "reports",
        hooks=workspace / "empty-hooks",
    )
    for path in (ctx.repos, ctx.raw, ctx.reports, ctx.hooks):
        path.mkdir(parents=True, exist_ok=True)
    (ctx.hooks / ".keep").write_text("", encoding="utf-8")
    return ctx


def require_tools(*tools: str) -> None:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        die(f"Outils requis introuvables: {', '.join(missing)}")


def run_process(
    args: list[str],
    *,
    cwd: Path | None = None,
    stdout: Path | None = None,
    capture: bool = False,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    if stdout:
        with stdout.open("w", encoding="utf-8") as handle:
            proc = subprocess.run(args, cwd=cwd, env=full_env, text=True, stdout=handle)
    else:
        proc = subprocess.run(
            args,
            cwd=cwd,
            env=full_env,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )

    if check and proc.returncode != 0:
        stderr = proc.stderr.strip() if proc.stderr else ""
        die(f"Commande en echec ({proc.returncode}): {' '.join(args)}\n{stderr}")
    return proc


def gitlab_api_get(ctx: Context, relative_path: str) -> Any:
    url = f"{ctx.gitlab_base_url}/api/v4/{relative_path.lstrip('/')}"
    headers = {"PRIVATE-TOKEN": ctx.gitlab_token}

    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            request = urllib.request.Request(url, headers={"Authorization": f"Bearer {ctx.gitlab_token}"})
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as second:
                if second.code == 401:
                    die("Authentification GitLab refusee. Verifie le token et ses scopes read_api/api.")
                raise
        body = exc.read().decode("utf-8", errors="replace")[:300]
        die(f"Erreur GitLab HTTP {exc.code} sur {url}: {body}")
    except urllib.error.URLError as exc:
        die(f"Erreur reseau GitLab sur {url}: {exc.reason}")


def get_gitlab_projects(ctx: Context) -> list[dict[str, Any]]:
    encoded_group = urllib.parse.quote(ctx.gitlab_group_path, safe="")
    group = gitlab_api_get(ctx, f"groups/{encoded_group}")
    group_id = group["id"]

    projects: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = gitlab_api_get(
            ctx,
            f"groups/{group_id}/projects?include_subgroups=true&per_page=100&page={page}&archived=false&simple=false",
        )
        if not batch:
            break
        projects.extend(batch)
        page += 1
    return sorted(projects, key=lambda item: item.get("path_with_namespace", ""))


def sync_project(ctx: Context, project: dict[str, Any]) -> dict[str, Any]:
    namespace = project["path_with_namespace"]
    clone_url = project["http_url_to_repo"].strip()
    branch = project.get("default_branch") or ctx.config["DEFAULT_FALLBACK_BRANCH"]

    expected_host = urllib.parse.urlparse(ctx.gitlab_base_url).hostname
    clone_host = urllib.parse.urlparse(clone_url).hostname
    if clone_host != expected_host:
        raise RuntimeError(f"Host inattendu pour {namespace}: {clone_host}")
    if not clone_url.startswith("https://") or not clone_url.endswith(".git"):
        raise RuntimeError(f"URL de clone invalide pour {namespace}: {clone_url}")

    target = ctx.repos / safe_relative_repo_path(namespace)
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)

    log("INFO", f"Clone {namespace} ({branch})")
    git_args = [
        "git",
        "-c",
        f"http.extraHeader=PRIVATE-TOKEN: {ctx.gitlab_token}",
        "-c",
        f"core.hooksPath={ctx.hooks}",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "transfer.fsckObjects=true",
    ]
    if is_windows():
        git_args += ["-c", "http.sslBackend=schannel", "-c", "http.schannelCheckRevoke=false"]
    git_args += [
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--branch",
        branch,
        clone_url,
        str(target),
    ]
    run_process(git_args)
    return {"repo": namespace, "status": "cloned", "path": str(target)}


def sync(ctx: Context) -> None:
    require_tools("git")
    projects = get_gitlab_projects(ctx)
    errors = []
    count = 0
    for project in projects:
        try:
            sync_project(ctx, project)
            count += 1
        except Exception as exc:  # keep sync resilient per repo
            errors.append({"repo": project.get("path_with_namespace", ""), "error": str(exc)})
            log("ERROR", f"{project.get('path_with_namespace', '')}: {exc}")
    (ctx.raw / "sync-errors.json").write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding="utf-8")
    log("INFO", f"Synchronisation terminee: {count} repos clones, {len(errors)} erreurs")


def local_repos(ctx: Context) -> list[Path]:
    return sorted(path.parent for path in ctx.repos.rglob(".git") if path.is_dir())


def resolve_repo_filter(ctx: Context, value: str) -> Path:
    candidate = Path(value)
    if candidate.exists():
        repo_dir = candidate.resolve()
    else:
        repo_dir = (ctx.repos / safe_relative_repo_path(value)).resolve()

    if not (repo_dir / ".git").is_dir():
        die(f"Repo local introuvable ou invalide: {value}")
    return repo_dir


def repo_name(ctx: Context, repo_dir: Path) -> str:
    try:
        return repo_dir.relative_to(ctx.repos).as_posix()
    except ValueError:
        drive = repo_dir.drive.rstrip(":").lower()
        parts = [part for part in repo_dir.parts if part not in (repo_dir.anchor, repo_dir.drive)]
        prefix = f"external/{drive}" if drive else "external"
        return "/".join([prefix, *parts])


def raw_dir(ctx: Context, name: str) -> Path:
    path = ctx.raw / safe_raw_name(name)
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_manifest(repo_dir: Path, name: str, output: Path) -> list[dict[str, Any]]:
    files = []
    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file():
            continue
        if ".git" in path.relative_to(repo_dir).parts:
            continue
        rel = path.relative_to(repo_dir).as_posix()
        files.append({"path": rel, "size": path.stat().st_size})
    output.write_text(
        json.dumps(
            {
                "repo": name,
                "scope": "working-tree-without-git-metadata",
                "totalFiles": len(files),
                "files": files,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return files


def build_detect_secrets(ctx: Context) -> None:
    require_tools("docker")
    log("INFO", f"Build de l'image detect-secrets locale: {ctx.config['DETECT_SECRETS_IMAGE']}")
    run_process(
        [
            "docker",
            "build",
            "-f",
            str(ctx.root / "docker" / "detect-secrets.Dockerfile"),
            "-t",
            ctx.config["DETECT_SECRETS_IMAGE"],
            str(ctx.root),
        ]
    )


def run_first_success(commands: list[tuple[str, list[str]]], scanner: str) -> None:
    last_error = ""
    for image, command in commands:
        log("INFO", f"{scanner} image: {image}")
        proc = run_process(command, env={"MSYS_NO_PATHCONV": "1"}, capture=True, check=False)
        if proc.returncode == 0:
            return
        last_error = proc.stderr or proc.stdout or ""
        log("WARN", f"Echec {scanner} avec l'image {image}")
    raise RuntimeError(f"{scanner} a echoue avec toutes les images configurees: {last_error[:500]}")


def run_gitleaks(ctx: Context, repo_dir: Path, output: Path) -> None:
    commands = []
    for image in split_csv(ctx.config["GITLEAKS_IMAGES"]):
        commands.append(
            (
                image,
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{docker_mount_path(repo_dir)}:/repo:ro",
                    "-v",
                    f"{docker_mount_path(output.parent)}:/out",
                    image,
                    "dir",
                    "/repo",
                    "--no-banner",
                    "--redact",
                    "--exit-code",
                    "0",
                    "--report-format",
                    "json",
                    "--report-path",
                    f"/out/{output.name}",
                ],
            )
        )
    run_first_success(commands, "Gitleaks")
    if not output.exists():
        output.write_text("[]\n", encoding="utf-8")


def run_trufflehog(ctx: Context, repo_dir: Path, output: Path) -> None:
    for image in split_csv(ctx.config["TRUFFLEHOG_IMAGES"]):
        log("INFO", f"TruffleHog image: {image}")
        with output.open("w", encoding="utf-8") as handle:
            proc = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{docker_mount_path(repo_dir)}:/repo:ro",
                    image,
                    "filesystem",
                    "/repo",
                    "--json",
                    "--results=verified,unknown",
                ],
                env={**os.environ, "MSYS_NO_PATHCONV": "1"},
                text=True,
                stdout=handle,
            )
        if proc.returncode == 0:
            return
        log("WARN", f"Echec TruffleHog avec l'image {image}")
    raise RuntimeError("TruffleHog a echoue avec toutes les images configurees")


def run_detect_secrets(ctx: Context, repo_dir: Path, output: Path) -> None:
    with output.open("w", encoding="utf-8") as handle:
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{docker_mount_path(repo_dir)}:/repo:ro",
                ctx.config["DETECT_SECRETS_IMAGE"],
                "scan",
                "--all-files",
                "/repo",
            ],
            env={**os.environ, "MSYS_NO_PATHCONV": "1"},
            text=True,
            stdout=handle,
        )
    if proc.returncode != 0:
        raise RuntimeError("detect-secrets a echoue")


def run_semgrep(ctx: Context, repo_dir: Path, output: Path) -> None:
    configs: list[str] = []
    for config in split_csv(ctx.config["SEMGREP_CONFIGS"]):
        configs.extend(["--config", config])
    for image in split_csv(ctx.config["SEMGREP_IMAGES"]):
        log("INFO", f"Semgrep image: {image}")
        with output.open("w", encoding="utf-8") as handle:
            proc = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{docker_mount_path(repo_dir)}:/src:ro",
                    "-v",
                    f"{docker_mount_path(ctx.root / 'config')}:/rules:ro",
                    image,
                    "semgrep",
                    "scan",
                    "--json",
                    "--quiet",
                    *configs,
                    "/src",
                ],
                env={**os.environ, "MSYS_NO_PATHCONV": "1"},
                text=True,
                stdout=handle,
            )
        if proc.returncode == 0:
            return
        log("WARN", f"Echec Semgrep avec l'image {image}")
    raise RuntimeError("Semgrep a echoue avec toutes les images configurees")


HEURISTIC_RE = re.compile(
    r"(?i)(^|[^A-Za-z0-9_])(password|passwd|pwd|secret|token|api[_-]?key|apikey)[A-Za-z0-9_-]*\s*[:=]\s*([^\s#]+)"
)


def run_heuristic(repo_dir: Path, name: str, files: list[dict[str, Any]], output: Path) -> None:
    findings = []
    for item in files:
        rel = item["path"]
        path = repo_dir / rel
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            match = HEURISTIC_RE.search(line)
            if not match:
                continue
            value = match.group(3).strip().strip("\"'")
            if not value or value.startswith("$") or re.fullmatch(r"<[^>]+>|\{\{.*\}\}", value):
                continue
            low = value.lower()
            rule = "placeholder-secret" if low in {
                "password",
                "passwd",
                "changeme",
                "changeit",
                "secret",
                "token",
                "your_token_here",
                "your_password_here",
                "example",
                "sample",
            } else "suspicious-assignment"
            findings.append(
                {
                    "repo": name,
                    "scanner": "heuristic",
                    "rule": rule,
                    "description": "Placeholder or default secret value"
                    if rule == "placeholder-secret"
                    else "Suspicious hardcoded secret-like assignment",
                "file": rel,
                "line": number,
                "endLine": number,
                "lineText": line,
                "secret": redact(value),
                "fingerprint": f"{rule}:{rel}:{number}",
                "severity": "low" if rule == "placeholder-secret" else "medium",
                    "verified": False,
                    "source": "working-tree",
                }
            )
    with output.open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding, ensure_ascii=False, separators=(",", ":")) + "\n")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_source_line(repo_dir: Path | None, file_path: str, line_number: int) -> str:
    if not repo_dir or not file_path or line_number <= 0:
        return ""
    source = (repo_dir / file_path).resolve()
    try:
        source.relative_to(repo_dir.resolve())
    except ValueError:
        return ""
    if not source.exists() or not source.is_file():
        return ""
    try:
        return source.read_text(encoding="utf-8", errors="replace").splitlines()[line_number - 1]
    except IndexError:
        return ""


def normalize_findings(name: str, directory: Path, repo_dir: Path | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in read_json(directory / "gitleaks.json", []):
        file_path = re.sub(r"^/repo/?", "", item.get("File", ""))
        line_no = item.get("StartLine", 0) or 0
        findings.append(
            {
                "repo": name,
                "scanner": "gitleaks",
                "rule": item.get("RuleID", ""),
                "description": item.get("Description", ""),
                "file": file_path,
                "line": line_no,
                "endLine": item.get("EndLine", 0) or 0,
                "lineText": read_source_line(repo_dir, file_path, line_no),
                "secret": item.get("Redaction") or item.get("Secret") or "",
                "fingerprint": item.get("Fingerprint", ""),
                "severity": ", ".join(item.get("Tags") or []),
                "verified": False,
                "source": "working-tree",
            }
        )

    trufflehog = directory / "trufflehog.jsonl"
    if trufflehog.exists():
        for line in trufflehog.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("{"):
                continue
            item = json.loads(line)
            data = item.get("SourceMetadata", {}).get("Data", {})
            fs = data.get("Filesystem") or data.get("Git") or {}
            file_path = re.sub(r"^/repo/?", "", fs.get("file", ""))
            line_no = fs.get("line", 0) or 0
            findings.append(
                {
                    "repo": name,
                    "scanner": "trufflehog",
                    "rule": item.get("DetectorName", ""),
                    "description": "TruffleHog detection",
                    "file": file_path,
                    "line": line_no,
                    "endLine": line_no,
                    "lineText": read_source_line(repo_dir, file_path, line_no),
                    "secret": item.get("Redacted") or "",
                    "fingerprint": f"{item.get('DetectorName', '')}:{file_path}:{line_no}",
                    "severity": "verified" if item.get("Verified") else "unknown",
                    "verified": bool(item.get("Verified")),
                    "source": item.get("SourceName", ""),
                }
            )

    for file_path, entries in (read_json(directory / "detect-secrets.json", {}).get("results") or {}).items():
        clean = re.sub(r"^/repo/?", "", file_path)
        for entry in entries:
            line_no = entry.get("line_number", 0) or 0
            rule = "Inline Allowlist" if entry.get("is_secret") is False else entry.get("type", "detect-secrets")
            hashed = entry.get("hashed_secret")
            findings.append(
                {
                    "repo": name,
                    "scanner": "detect-secrets",
                    "rule": rule,
                    "description": "detect-secrets detection",
                    "file": clean,
                    "line": line_no,
                    "endLine": line_no,
                    "lineText": read_source_line(repo_dir, clean, line_no),
                    "secret": f"sha1:{hashed}" if hashed else "",
                    "fingerprint": f"{entry.get('type', 'detect-secrets')}:{clean}:{line_no}",
                    "severity": "",
                    "verified": False,
                    "source": "working-tree",
                }
            )

    for item in read_json(directory / "semgrep.json", {}).get("results", []) or []:
        extra = item.get("extra", {}) or {}
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}
        file_path = re.sub(r"^/src/?", "", item.get("path", ""))
        rule_id = item.get("check_id", "")
        line_no = start.get("line", 0) or 0
        findings.append(
            {
                "repo": name,
                "scanner": "semgrep",
                "rule": rule_id,
                "description": extra.get("message") or "Semgrep finding",
                "file": file_path,
                "line": line_no,
                "endLine": end.get("line", line_no) or 0,
                "lineText": read_source_line(repo_dir, file_path, line_no),
                "secret": "",
                "fingerprint": f"{rule_id}:{file_path}:{line_no}",
                "severity": extra.get("severity") or "",
                "verified": False,
                "source": "working-tree",
            }
        )

    heuristic = directory / "heuristic.jsonl"
    if heuristic.exists():
        for line in heuristic.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                findings.append(json.loads(line))
    return findings


def arr(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def matches_any(value: str, patterns: Any) -> bool:
    return any(re.search(pattern, value or "") for pattern in arr(patterns))


def whitelist_findings(findings: list[dict[str, Any]], whitelist_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    whitelist = read_json(whitelist_path, {})
    kept = []
    ignored = []
    for finding in findings:
        reason = None
        if matches_any(finding.get("file", ""), whitelist.get("paths")):
            reason = "path whitelist"
        elif matches_any(finding.get("secret", ""), whitelist.get("secrets")):
            reason = "secret whitelist"
        else:
            for rule in arr(whitelist.get("rules")):
                if rule.get("detectors") and finding.get("scanner") not in rule["detectors"]:
                    continue
                if rule.get("ruleIds") and finding.get("rule") not in rule["ruleIds"]:
                    continue
                if rule.get("repoPattern") and not re.search(rule["repoPattern"], finding.get("repo", "")):
                    continue
                if rule.get("filePattern") and not re.search(rule["filePattern"], finding.get("file", "")):
                    continue
                if rule.get("secretPattern") and not re.search(rule["secretPattern"], finding.get("secret", "")):
                    continue
                if rule.get("linePattern") and not re.search(rule["linePattern"], finding.get("lineText", "")):
                    continue
                reason = rule.get("reason") or "whitelist rule"
                break
        if reason:
            copy = dict(finding)
            copy["ignoredReason"] = reason
            ignored.append(copy)
        else:
            kept.append(finding)

    key = lambda item: (item.get("repo", ""), item.get("file", ""), item.get("line", 0), item.get("scanner", ""))
    return sorted(kept, key=key), sorted(ignored, key=key)


def html_report(report: dict[str, Any]) -> str:
    findings = report["findings"]
    ignored = report["ignored"]
    projects = report["projects"]
    scan_errors = report.get("scanErrors", [])
    logo_path = Path(__file__).resolve().parents[1] / "assets" / "img" / "samu.png"
    logo_src = ""
    if logo_path.exists():
        logo_src = "data:image/png;base64," + base64.b64encode(logo_path.read_bytes()).decode("ascii")

    scanner_counts: dict[str, int] = {}
    repo_counts: dict[str, int] = {}
    for finding in findings:
        scanner_counts[finding.get("scanner", "")] = scanner_counts.get(finding.get("scanner", ""), 0) + 1
        repo_counts[finding.get("repo", "")] = repo_counts.get(finding.get("repo", ""), 0) + 1

    workflow = [
        ("Sync", "GitLab clone"),
        ("Gitleaks", "Secrets rules"),
        ("TruffleHog", "Verified and unknown secrets"),
        ("detect-secrets", "Entropy and token detectors"),
        ("Semgrep", "Local and registry rules"),
        ("Heuristic", "Password assignments"),
        ("Report", "HTML and JSON"),
    ]

    def badge(value: str) -> str:
        raw = (value or "unknown").strip()
        key = raw.lower()
        if key in {"error", "high", "critical", "verified"}:
            cls = "danger"
        elif key in {"warning", "warn", "medium"}:
            cls = "warning"
        elif key in {"info", "low"}:
            cls = "info"
        elif key in {"unknown", ""}:
            cls = "muted-badge"
        else:
            cls = "ok"
        return f'<span class="badge {cls}">{html.escape(raw or "unknown")}</span>'

    def scanner_rows() -> str:
        return "".join(
            f"<tr><td><span class=\"scanner-name\">{html.escape(scanner)}</span></td><td>{count}</td></tr>"
            for scanner, count in sorted(scanner_counts.items())
        )

    def project_rows() -> str:
        return "".join(
            f"<tr><td>{html.escape(project['path_with_namespace'])}</td><td>{project['file_count']}</td><td>{repo_counts.get(project['path_with_namespace'], 0)}</td></tr>"
            for project in projects
        )

    def finding_rows(items: list[dict[str, Any]]) -> str:
        return "".join(
            f"<tr><td>{html.escape(str(f.get('repo', '')))}</td><td>{html.escape(str(f.get('scanner', '')))}</td><td>{html.escape(str(f.get('rule', '')))}</td><td>{html.escape(str(f.get('file', '')))}</td><td>{f.get('line', 0)}</td><td>{html.escape(str(f.get('secret', '')))}</td><td>{badge(str(f.get('severity', '')))}</td><td>{badge('verified' if f.get('verified') else 'no')}</td><td>{html.escape(str(f.get('description', '')))}</td></tr>"
            for f in items
        )

    def ignored_rows() -> str:
        return "".join(
            f"<tr><td>{html.escape(str(f.get('repo', '')))}</td><td>{html.escape(str(f.get('scanner', '')))}</td><td>{html.escape(str(f.get('file', '')))}</td><td>{f.get('line', 0)}</td><td>{html.escape(str(f.get('ignoredReason', '')))}</td></tr>"
            for f in ignored
        )

    def workflow_steps() -> str:
        return "".join(
            f"<div class=\"step\"><span>{index}</span><strong>{html.escape(title)}</strong><em>{html.escape(text)}</em></div>"
            for index, (title, text) in enumerate(workflow, 1)
        )

    def error_rows() -> str:
        if not scan_errors:
            return '<tr><td colspan="3"><span class="badge ok">no scan errors</span></td></tr>'
        return "".join(
            f"<tr><td>{html.escape(str(item.get('repo', '')))}</td><td>{html.escape(str(item.get('scanner', '')))}</td><td>{html.escape(str(item.get('error', '')))}</td></tr>"
            for item in scan_errors
        )

    logo_html = f'<img class="logo" src="{logo_src}" alt="SAMU">' if logo_src else '<div class="logo-fallback">SAMU</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SAMU - Secrets Analysis & Monitoring Utility</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f3f6fb;color:#182033;margin:0;padding:28px}}
.shell{{max-width:1480px;margin:0 auto}}
.hero{{display:flex;align-items:center;gap:20px;background:linear-gradient(135deg,#ffffff,#e9f1ff);border:1px solid #d7e1f2;border-radius:14px;padding:22px 24px;margin-bottom:22px;box-shadow:0 12px 32px rgba(28,45,80,.10)}}
.logo{{width:86px;height:86px;object-fit:contain}}.logo-fallback{{width:86px;height:86px;border-radius:12px;background:#10233f;color:#fff;display:grid;place-items:center;font-weight:800}}
h1{{margin:0;font-size:30px;color:#10233f}}h2{{margin:0 0 14px;color:#10233f}}.subtitle{{margin:6px 0 0;color:#5e6b80}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:22px}}
.card,.panel{{background:#fff;border:1px solid #d7e1f2;border-radius:10px;padding:16px;margin-bottom:20px;box-shadow:0 8px 24px rgba(28,45,80,.07)}}
.label{{color:#68758a;font-size:13px;text-transform:uppercase;letter-spacing:.04em}}.value{{font-size:30px;font-weight:800;margin-top:6px;color:#10233f}}
.workflow{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}.step{{border:1px solid #d7e1f2;border-radius:10px;padding:12px;background:#f8fbff}}
.step span{{display:inline-grid;place-items:center;width:24px;height:24px;border-radius:50%;background:#1d4ed8;color:white;font-weight:700;margin-right:8px}}.step strong{{display:block;margin-top:8px;color:#10233f}}.step em{{display:block;color:#68758a;font-style:normal;font-size:13px;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}td,th{{border-bottom:1px solid #e3eaf5;padding:9px;text-align:left;vertical-align:top}}th{{background:#eef4ff;color:#334155;position:sticky;top:0}}.scroll{{overflow:auto;max-height:560px}}
.badge{{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700;white-space:nowrap}}.danger{{background:#fee2e2;color:#991b1b}}.warning{{background:#fef3c7;color:#92400e}}.info{{background:#dbeafe;color:#1e40af}}.ok{{background:#dcfce7;color:#166534}}.muted-badge{{background:#e5e7eb;color:#374151}}.scanner-name{{font-weight:700;color:#10233f}}
</style></head><body>
<main class="shell">
<section class="hero">{logo_html}<div><h1>SAMU - Secrets Analysis & Monitoring Utility</h1><p class="subtitle">Group / target: {html.escape(report['groupPath'])}<br>Scan generated at {html.escape(report['generatedAt'])}</p></div></section>
<div class="cards"><div class="card"><div class="label">Repositories scanned</div><div class="value">{report['repoCount']}</div></div><div class="card"><div class="label">Files scanned</div><div class="value">{report['fileCount']}</div></div><div class="card"><div class="label">Findings kept</div><div class="value">{len(findings)}</div></div><div class="card"><div class="label">Whitelisted findings</div><div class="value">{len(ignored)}</div></div><div class="card"><div class="label">Scan errors</div><div class="value">{len(scan_errors)}</div></div></div>
<div class="panel"><h2>Scan Workflow</h2><div class="workflow">{workflow_steps()}</div></div>
<div class="panel"><h2>Summary By Scanner</h2><table><thead><tr><th>Scanner</th><th>Findings</th></tr></thead><tbody>{scanner_rows()}</tbody></table></div>
<div class="panel"><h2>Summary By Repository</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Files</th><th>Findings</th></tr></thead><tbody>{project_rows()}</tbody></table></div></div>
<div class="panel"><h2>Finding Details</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Scanner</th><th>Rule</th><th>File</th><th>Line</th><th>Secret</th><th>Status</th><th>Verified</th><th>Description</th></tr></thead><tbody>{finding_rows(findings)}</tbody></table></div></div>
<div class="panel"><h2>Whitelisted Findings</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Scanner</th><th>File</th><th>Line</th><th>Reason</th></tr></thead><tbody>{ignored_rows()}</tbody></table></div></div>
<div class="panel"><h2>Scan Errors</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Scanner</th><th>Error</th></tr></thead><tbody>{error_rows()}</tbody></table></div></div>
</main></body></html>
"""


def analyze(ctx: Context, whitelist: Path, skip_build: bool = False, repo_filter: str | None = None) -> None:
    require_tools("docker", "git")
    if not whitelist.exists():
        die(f"Whitelist introuvable: {whitelist}")
    if not skip_build:
        build_detect_secrets(ctx)

    repos = [resolve_repo_filter(ctx, repo_filter)] if repo_filter else local_repos(ctx)
    if not repos:
        die(f"Aucun repo local detecte dans {ctx.repos}. Lance d'abord sync.")

    all_findings: list[dict[str, Any]] = []
    projects = []
    scan_errors = []

    for repo_dir in repos:
        name = repo_name(ctx, repo_dir)
        directory = raw_dir(ctx, name)
        manifest = directory / "files-manifest.json"
        files = create_manifest(repo_dir, name, manifest)
        projects.append({"path_with_namespace": name, "file_count": len(files)})
        log("INFO", f"Inventaire fichiers: {name} ({len(files)} fichiers)")

        scanner_steps = [
            ("Gitleaks", lambda: run_gitleaks(ctx, repo_dir, directory / "gitleaks.json")),
            ("TruffleHog", lambda: run_trufflehog(ctx, repo_dir, directory / "trufflehog.jsonl")),
            ("detect-secrets", lambda: run_detect_secrets(ctx, repo_dir, directory / "detect-secrets.json")),
            ("Semgrep", lambda: run_semgrep(ctx, repo_dir, directory / "semgrep.json")),
            ("heuristique", lambda: run_heuristic(repo_dir, name, files, directory / "heuristic.jsonl")),
        ]
        for scanner, func in scanner_steps:
            try:
                log("INFO", f"Scan {scanner}: {name}")
                func()
            except Exception as exc:
                scan_errors.append({"repo": name, "scanner": scanner, "error": str(exc)})
                log("ERROR", f"{name} / {scanner}: {exc}")
        repo_findings = normalize_findings(name, directory, repo_dir)
        (directory / "findings.jsonl").write_text(
            "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in repo_findings),
            encoding="utf-8",
        )
        all_findings.extend(repo_findings)

    kept, ignored = whitelist_findings(all_findings, whitelist)
    report = {
        "generatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "groupPath": ctx.gitlab_group_path,
        "repoCount": len(projects),
        "fileCount": sum(project["file_count"] for project in projects),
        "projects": projects,
        "findings": kept,
        "ignored": ignored,
        "scanErrors": scan_errors,
    }
    (ctx.raw / "projects.json").write_text(json.dumps(projects, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.raw / "scan-errors.json").write_text(json.dumps(scan_errors, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.raw / "all-findings.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in all_findings),
        encoding="utf-8",
    )
    (ctx.reports / "findings.kept.json").write_text(json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.reports / "findings.ignored.json").write_text(json.dumps(ignored, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.reports / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.reports / "report.html").write_text(html_report(report), encoding="utf-8")
    log("INFO", f"Report JSON: {ctx.reports / 'report.json'}")
    log("INFO", f"Report HTML: {ctx.reports / 'report.html'}")
    log("INFO", f"Findings retenus: {len(kept)} | whitelistes: {len(ignored)} | erreurs scan: {len(scan_errors)}")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    items = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError as exc:
            die(f"JSONL invalide dans {path}:{line_number}: {exc}")
    return items


def report_raw_directories(ctx: Context, repo_filter: str | None = None) -> list[Path]:
    if repo_filter:
        repo_dir = resolve_repo_filter(ctx, repo_filter)
        directory = raw_dir(ctx, repo_name(ctx, repo_dir))
        if not directory.exists():
            die(f"Aucune sortie brute pour ce repo: {repo_filter}. Lance d'abord analyze sur ce repo.")
        return [directory]
    return sorted(path for path in ctx.raw.iterdir() if path.is_dir() and (path / "findings.jsonl").exists())


def enrich_line_text(ctx: Context, finding: dict[str, Any]) -> dict[str, Any]:
    if finding.get("lineText"):
        return finding
    repo = str(finding.get("repo", ""))
    repo_dir = ctx.repos / safe_relative_repo_path(repo)
    line_text = read_source_line(repo_dir if repo_dir.exists() else None, str(finding.get("file", "")), int(finding.get("line") or 0))
    if line_text:
        copy = dict(finding)
        copy["lineText"] = line_text
        return copy
    return finding


def generate_report_only(ctx: Context, whitelist: Path, repo_filter: str | None = None) -> None:
    if not whitelist.exists():
        die(f"Whitelist introuvable: {whitelist}")

    directories = report_raw_directories(ctx, repo_filter)
    if not directories:
        die(f"Aucune sortie de scan detectee dans {ctx.raw}. Lance d'abord analyze ou scan.")

    all_findings: list[dict[str, Any]] = []
    projects = []
    for directory in directories:
        manifest_path = directory / "files-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
        findings = [enrich_line_text(ctx, item) for item in read_jsonl(directory / "findings.jsonl")]
        repo = manifest.get("repo") or (findings[0].get("repo") if findings else directory.name)
        projects.append({"path_with_namespace": repo, "file_count": int(manifest.get("totalFiles") or 0)})
        all_findings.extend(findings)

    scan_errors_path = ctx.raw / "scan-errors.json"
    scan_errors = json.loads(scan_errors_path.read_text(encoding="utf-8")) if scan_errors_path.exists() else []
    if repo_filter:
        repo_names = {project["path_with_namespace"] for project in projects}
        scan_errors = [error for error in scan_errors if error.get("repo") in repo_names]

    kept, ignored = whitelist_findings(all_findings, whitelist)
    report = {
        "generatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "groupPath": ctx.gitlab_group_path,
        "repoCount": len(projects),
        "fileCount": sum(project["file_count"] for project in projects),
        "projects": projects,
        "findings": kept,
        "ignored": ignored,
        "scanErrors": scan_errors,
    }
    (ctx.raw / "projects.json").write_text(json.dumps(projects, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.raw / "all-findings.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in all_findings),
        encoding="utf-8",
    )
    (ctx.reports / "findings.kept.json").write_text(json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.reports / "findings.ignored.json").write_text(json.dumps(ignored, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.reports / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (ctx.reports / "report.html").write_text(html_report(report), encoding="utf-8")
    log("INFO", f"Report regenere sans scan: {ctx.reports / 'report.html'}")
    log("INFO", f"Findings retenus: {len(kept)} | whitelistes: {len(ignored)} | erreurs scan: {len(scan_errors)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SAMU - Secrets Analysis & Monitoring Utility")
    parser.add_argument("command", choices=["sync", "analyze", "report", "scan", "scan-open"])
    parser.add_argument("--secrets-file", default=".secrets")
    parser.add_argument("--whitelist-file", default="config/whitelist.json")
    parser.add_argument("--skip-detect-secrets-build", action="store_true")
    parser.add_argument("--repo", help="Repo local a analyser: namespace GitLab ou chemin local quelconque")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    root = Path(__file__).resolve().parents[1]
    secrets = Path(args.secrets_file)
    if not secrets.is_absolute():
        secrets = root / secrets
    whitelist = Path(args.whitelist_file)
    if not whitelist.is_absolute():
        whitelist = root / whitelist

    ctx = init_context(secrets)
    if args.command == "sync":
        sync(ctx)
    elif args.command == "analyze":
        analyze(ctx, whitelist, args.skip_detect_secrets_build, args.repo)
    elif args.command == "report":
        generate_report_only(ctx, whitelist, args.repo)
    elif args.command == "scan":
        sync(ctx)
        analyze(ctx, whitelist, args.skip_detect_secrets_build, args.repo)
    elif args.command == "scan-open":
        sync(ctx)
        analyze(ctx, whitelist, args.skip_detect_secrets_build, args.repo)
        webbrowser.open((ctx.reports / "report.html").resolve().as_uri())


if __name__ == "__main__":
    main()
