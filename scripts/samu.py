#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import concurrent.futures
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


def force_rmtree(path: Path) -> None:
    """shutil.rmtree with a handler to remove read-only files on Windows."""
    if not path.exists():
        return

    def _on_error(_func: Any, _path: str, _exc_info: Any) -> None:
        try:
            os.chmod(_path, 0o777)
            os.remove(_path)
        except FileNotFoundError:
            pass

    shutil.rmtree(path, onerror=_on_error)


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
    config.setdefault("GGSHIELD_IMAGE", "gitguardian/ggshield:latest")
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
        force_rmtree(target)
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


def sync_project_deep(ctx: Context, project: dict[str, Any]) -> dict[str, Any]:
    namespace = project["path_with_namespace"]
    clone_url = project["http_url_to_repo"].strip()

    expected_host = urllib.parse.urlparse(ctx.gitlab_base_url).hostname
    clone_host = urllib.parse.urlparse(clone_url).hostname
    if clone_host != expected_host:
        raise RuntimeError(f"Host inattendu pour {namespace}: {clone_host}")
    if not clone_url.startswith("https://") or not clone_url.endswith(".git"):
        raise RuntimeError(f"URL de clone invalide pour {namespace}: {clone_url}")

    target = ctx.repos / safe_relative_repo_path(namespace)
    if target.exists():
        force_rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)

    log("INFO", f"Clone profond {namespace} (historique entier, toutes branches)")
    git_args = [
        "git",
        "-c", f"http.extraHeader=PRIVATE-TOKEN: {ctx.gitlab_token}",
        "-c", f"core.hooksPath={ctx.hooks}",
        "-c", "protocol.file.allow=never",
        "-c", "fetch.fsckObjects=true",
        "-c", "transfer.fsckObjects=true",
    ]
    if is_windows():
        git_args += ["-c", "http.sslBackend=schannel", "-c", "http.schannelCheckRevoke=false"]
    git_args += ["clone", "--no-tags", clone_url, str(target)]
    run_process(git_args)
    return {"repo": namespace, "status": "cloned-deep", "path": str(target)}


def sync_deep(ctx: Context) -> None:
    require_tools("git")
    projects = get_gitlab_projects(ctx)
    errors = []
    count = 0
    for project in projects:
        try:
            sync_project_deep(ctx, project)
            count += 1
        except Exception as exc:
            errors.append({"repo": project.get("path_with_namespace", ""), "error": str(exc)})
            log("ERROR", f"{project.get('path_with_namespace', '')}: {exc}")
    (ctx.raw / "sync-errors.json").write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding="utf-8")
    log("INFO", f"Synchronisation profonde terminee: {count} repos clones, {len(errors)} erreurs")


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


def run_gitleaks_git(ctx: Context, repo_dir: Path, output: Path) -> None:
    """Scan full git history with Gitleaks git subcommand."""
    commands = []
    for image in split_csv(ctx.config["GITLEAKS_IMAGES"]):
        commands.append(
            (
                image,
                [
                    "docker", "run", "--rm",
                    "-v", f"{docker_mount_path(repo_dir)}:/repo:ro",
                    "-v", f"{docker_mount_path(output.parent)}:/out",
                    image,
                    "git", "/repo",
                    "--no-banner",
                    "--redact",
                    "--exit-code", "0",
                    "--report-format", "json",
                    "--report-path", f"/out/{output.name}",
                ],
            )
        )
    run_first_success(commands, "Gitleaks-git")
    if not output.exists():
        output.write_text("[]\n", encoding="utf-8")


def run_trufflehog_git(ctx: Context, repo_dir: Path, output: Path) -> None:
    """Scan full git history with TruffleHog git source."""
    for image in split_csv(ctx.config["TRUFFLEHOG_IMAGES"]):
        log("INFO", f"TruffleHog-git image: {image}")
        with output.open("w", encoding="utf-8") as handle:
            proc = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{docker_mount_path(repo_dir)}:/repo:ro",
                    image,
                    "git", "file:///repo",
                    "--json",
                    "--results=verified,unknown",
                ],
                env={**os.environ, "MSYS_NO_PATHCONV": "1"},
                text=True,
                stdout=handle,
            )
        if proc.returncode == 0:
            return
        log("WARN", f"Echec TruffleHog-git avec l'image {image}")
    raise RuntimeError("TruffleHog-git a echoue avec toutes les images configurees")


def run_ggshield(ctx: Context, repo_dir: Path, output: Path) -> None:
    """Scan working tree with ggshield path scan. Silently skipped if no GITGUARDIAN_API_KEY."""
    api_key = ctx.config.get("GITGUARDIAN_API_KEY", "")
    if not api_key:
        return
    image = ctx.config["GGSHIELD_IMAGE"]
    log("INFO", f"ggshield image: {image}")
    with output.open("w", encoding="utf-8") as handle:
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", "GITGUARDIAN_API_KEY",
                "-v", f"{docker_mount_path(repo_dir)}:/repo:ro",
                image,
                "secret", "scan", "path",
                "--json",
                "-r",
                "/repo",
            ],
            env={**os.environ, "GITGUARDIAN_API_KEY": api_key, "MSYS_NO_PATHCONV": "1"},
            text=True,
            stdout=handle,
        )
    # exit 1 means secrets found (not an error); only other codes are real failures
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"ggshield a echoue (code {proc.returncode})")
    if not output.exists() or not output.read_text(encoding="utf-8").strip():
        output.write_text("{}", encoding="utf-8")


def run_ggshield_git(ctx: Context, repo_dir: Path, output: Path) -> None:
    """Scan full git history with ggshield repo scan. Silently skipped if no GITGUARDIAN_API_KEY."""
    api_key = ctx.config.get("GITGUARDIAN_API_KEY", "")
    if not api_key:
        return
    image = ctx.config["GGSHIELD_IMAGE"]
    log("INFO", f"ggshield-git image: {image}")
    with output.open("w", encoding="utf-8") as handle:
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", "GITGUARDIAN_API_KEY",
                "-v", f"{docker_mount_path(repo_dir)}:/repo:ro",
                image,
                "secret", "scan", "repo",
                "--json",
                "/repo",
            ],
            env={**os.environ, "GITGUARDIAN_API_KEY": api_key, "MSYS_NO_PATHCONV": "1"},
            text=True,
            stdout=handle,
        )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"ggshield-git a echoue (code {proc.returncode})")
    if not output.exists() or not output.read_text(encoding="utf-8").strip():
        output.write_text("{}", encoding="utf-8")


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


def run_semgrep(ctx: Context, repo_dir: Path, output: Path, git_aware: bool = True) -> None:
    configs: list[str] = []
    for config in split_csv(ctx.config["SEMGREP_CONFIGS"]):
        configs.extend(["--config", config])
    extra_args: list[str] = [] if git_aware else ["--no-git-ignore"]
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
                    *extra_args,
                    *configs,
                    "/src",
                ],
                env={**os.environ, "MSYS_NO_PATHCONV": "1"},
                text=True,
                stdout=handle,
            )
        if proc.returncode == 0:
            return
        # In non-git mode, accept results even if semgrep returned non-zero due to git errors
        if not git_aware and output.exists() and output.stat().st_size > 0:
            try:
                data = json.loads(output.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "results" in data:
                    log("WARN", f"Semgrep retourne {proc.returncode} mais des resultats ont ete produits, on continue")
                    return
            except json.JSONDecodeError:
                pass
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

    for entity in (read_json(directory / "ggshield.json", {}).get("entities_with_incidents") or []):
        file_path = re.sub(r"^/repo/?", "", entity.get("filename", ""))
        for incident in (entity.get("incidents") or []):
            detector = incident.get("detector") or {}
            rule_id = detector.get("detector_group_name") or detector.get("name") or ""
            for occ in (incident.get("occurrences") or []):
                line_no = occ.get("line_start", 0) or 0
                findings.append(
                    {
                        "repo": name,
                        "scanner": "ggshield",
                        "rule": rule_id,
                        "description": detector.get("display_name") or "ggshield detection",
                        "file": file_path,
                        "line": line_no,
                        "endLine": occ.get("line_end", line_no) or line_no,
                        "lineText": read_source_line(repo_dir, file_path, line_no),
                        "secret": occ.get("match") or "",
                        "fingerprint": f"ggshield:{file_path}:{line_no}:{rule_id}",
                        "severity": incident.get("severity") or "",
                        "verified": incident.get("validity") == "valid",
                        "source": "working-tree",
                    }
                )

    return findings


def normalize_git_findings(name: str, directory: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in read_json(directory / "gitleaks-git.json", []):
        file_path = re.sub(r"^/repo/?", "", item.get("File", ""))
        line_no = item.get("StartLine", 0) or 0
        commit = item.get("Commit", "")
        short_commit = commit[:8] if commit else "?"
        findings.append(
            {
                "repo": name,
                "scanner": "gitleaks-git",
                "rule": item.get("RuleID", ""),
                "description": item.get("Description", ""),
                "file": file_path,
                "line": line_no,
                "endLine": item.get("EndLine", 0) or 0,
                "lineText": f"[{short_commit}] {item.get('Author', '')} — {item.get('Date', '')}",
                "secret": item.get("Redaction") or item.get("Secret") or "",
                "fingerprint": item.get("Fingerprint", "") or f"gitleaks-git:{file_path}:{line_no}:{short_commit}",
                "severity": ", ".join(item.get("Tags") or []),
                "verified": False,
                "source": "git-history",
                "commit": commit,
            }
        )

    trufflehog_git = directory / "trufflehog-git.jsonl"
    if trufflehog_git.exists():
        for line in trufflehog_git.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("{"):
                continue
            item = json.loads(line)
            data = item.get("SourceMetadata", {}).get("Data", {})
            git_data = data.get("Git") or {}
            file_path = git_data.get("file", "")
            line_no = git_data.get("line", 0) or 0
            commit = git_data.get("commit", "")
            short_commit = commit[:8] if commit else "?"
            branch = git_data.get("branch", "")
            findings.append(
                {
                    "repo": name,
                    "scanner": "trufflehog-git",
                    "rule": item.get("DetectorName", ""),
                    "description": "TruffleHog git detection",
                    "file": file_path,
                    "line": line_no,
                    "endLine": line_no,
                    "lineText": f"[{short_commit}] branch: {branch}",
                    "secret": item.get("Redacted") or "",
                    "fingerprint": f"{item.get('DetectorName', '')}:{file_path}:{line_no}:{short_commit}",
                    "severity": "verified" if item.get("Verified") else "unknown",
                    "verified": bool(item.get("Verified")),
                    "source": "git-history",
                    "commit": commit,
                    "branch": branch,
                }
            )

    for entity in (read_json(directory / "ggshield-git.json", {}).get("entities_with_incidents") or []):
        file_path = entity.get("filename", "")
        commit = entity.get("commit", "")
        short_commit = commit[:8] if commit else "?"
        for incident in (entity.get("incidents") or []):
            detector = incident.get("detector") or {}
            rule_id = detector.get("detector_group_name") or detector.get("name") or ""
            for occ in (incident.get("occurrences") or []):
                line_no = occ.get("line_start", 0) or 0
                findings.append(
                    {
                        "repo": name,
                        "scanner": "ggshield-git",
                        "rule": rule_id,
                        "description": detector.get("display_name") or "ggshield git detection",
                        "file": file_path,
                        "line": line_no,
                        "endLine": occ.get("line_end", line_no) or line_no,
                        "lineText": f"[{short_commit}] {entity.get('author', '')} — {entity.get('date', '')}",
                        "secret": occ.get("match") or "",
                        "fingerprint": f"ggshield-git:{file_path}:{line_no}:{short_commit}",
                        "severity": incident.get("severity") or "",
                        "verified": incident.get("validity") == "valid",
                        "source": "git-history",
                        "commit": commit,
                    }
                )

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


def write_findings_csv(findings: list[dict[str, Any]], path: Path) -> None:
    import csv, io
    headers = ["Repository", "Scanner", "Rule", "File", "Line", "Line Content", "Secret", "Severity", "Verified", "Description"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(headers)
    for f in findings:
        w.writerow([
            f.get("repo", ""), f.get("scanner", ""), f.get("rule", ""),
            f.get("file", ""), f.get("line", ""),
            (f.get("lineText") or "").strip(),
            f.get("secret", ""), f.get("severity", ""),
            "verified" if f.get("verified") else "no",
            f.get("description", ""),
        ])
    path.write_text("\ufeff" + buf.getvalue(), encoding="utf-8")


def html_report(report: dict[str, Any], csv_name: str = "report.csv") -> str:
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
        ("ggshield", "GitGuardian secret detection"),
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
            f"<tr><td>{html.escape(str(f.get('repo', '')))}</td><td>{html.escape(str(f.get('scanner', '')))}</td><td>{html.escape(str(f.get('rule', '')))}</td><td>{html.escape(str(f.get('file', '')))}</td><td>{f.get('line', 0)}</td><td><code class=\"line-text\">{html.escape(str(f.get('lineText', '')).strip())}</code></td><td>{html.escape(str(f.get('secret', '')))}</td><td>{badge(str(f.get('severity', '')))}</td><td>{badge('verified' if f.get('verified') else 'no')}</td><td>{html.escape(str(f.get('description', '')))}</td></tr>"
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
.line-text{{font-family:Consolas,Courier New,monospace;font-size:12px;background:#f1f5f9;border-radius:4px;padding:2px 5px;white-space:pre;display:block;max-width:420px;overflow:auto;color:#1e293b}}
.export-btn{{display:inline-flex;align-items:center;gap:6px;margin-bottom:12px;padding:7px 16px;background:#1d4ed8;color:#fff;border:none;border-radius:7px;font-weight:700;cursor:pointer;font-size:13px;text-decoration:none}}.export-btn:hover{{background:#1e40af}}
</style></head><body>
<main class="shell">
<section class="hero">{logo_html}<div><h1>SAMU - Secrets Analysis & Monitoring Utility</h1><p class="subtitle">Group / target: {html.escape(report['groupPath'])}<br>Scan generated at {html.escape(report['generatedAt'])}</p></div></section>
<div class="cards"><div class="card"><div class="label">Repositories scanned</div><div class="value">{report['repoCount']}</div></div><div class="card"><div class="label">Files scanned</div><div class="value">{report['fileCount']}</div></div><div class="card"><div class="label">Findings kept</div><div class="value">{len(findings)}</div></div><div class="card"><div class="label">Whitelisted findings</div><div class="value">{len(ignored)}</div></div><div class="card"><div class="label">Scan errors</div><div class="value">{len(scan_errors)}</div></div></div>
<div class="panel"><h2>Scan Workflow</h2><div class="workflow">{workflow_steps()}</div></div>
<div class="panel"><h2>Scanner Coverage</h2><table><thead><tr><th>Scanner</th><th>Scope</th></tr></thead><tbody><tr><td><span class="scanner-name">Gitleaks-git</span></td><td>All commits across all branches &mdash; full git history</td></tr><tr><td><span class="scanner-name">TruffleHog-git</span></td><td>All commits across all branches &mdash; full git history</td></tr><tr><td><span class="scanner-name">ggshield-git</span></td><td>All commits across all branches &mdash; full git history (requires GITGUARDIAN_API_KEY)</td></tr><tr><td><span class="scanner-name">detect-secrets</span></td><td>Tip (latest state) of each branch</td></tr><tr><td><span class="scanner-name">Semgrep</span></td><td>Tip (latest state) of each branch</td></tr><tr><td><span class="scanner-name">ggshield</span></td><td>Tip (latest state) of each branch (requires GITGUARDIAN_API_KEY)</td></tr><tr><td><span class="scanner-name">Heuristic</span></td><td>Tip (latest state) of each branch</td></tr></tbody></table></div>
<div class="panel"><h2>Summary By Scanner</h2><table><thead><tr><th>Scanner</th><th>Findings</th></tr></thead><tbody>{scanner_rows()}</tbody></table></div>
<div class="panel"><h2>Summary By Repository</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Files</th><th>Findings</th></tr></thead><tbody>{project_rows()}</tbody></table></div></div>
<div class="panel"><h2>Finding Details</h2><a class="export-btn" href="{csv_name}">&#11015; Export Excel (CSV)</a><div class="scroll" id="findings-scroll"><table id="findings-table"><thead><tr><th>Repository</th><th>Scanner</th><th>Rule</th><th>File</th><th>Line</th><th>Line Content</th><th>Secret</th><th>Status</th><th>Verified</th><th>Description</th></tr></thead><tbody>{finding_rows(findings)}</tbody></table></div></div>
<div class="panel"><h2>Whitelisted Findings</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Scanner</th><th>File</th><th>Line</th><th>Reason</th></tr></thead><tbody>{ignored_rows()}</tbody></table></div></div>
<div class="panel"><h2>Scan Errors</h2><div class="scroll"><table><thead><tr><th>Repository</th><th>Scanner</th><th>Error</th></tr></thead><tbody>{error_rows()}</tbody></table></div></div>
</main>
<script>(function(){{
  var tbl=document.getElementById('findings-table');
  if(!tbl)return;
  var rows=[].slice.call(tbl.querySelector('tbody').querySelectorAll('tr'));
  var total=rows.length;var filtered=rows.slice();var page=1;var pageSize=0;
  var ctrl=document.createElement('div');
  ctrl.style='display:flex;gap:12px;align-items:center;margin-bottom:10px;flex-wrap:wrap';
  var search=document.createElement('input');search.type='search';search.placeholder='Filter findings...';
  search.style='flex:1;min-width:220px;padding:7px 10px;border:1px solid #d7e1f2;border-radius:6px;font-size:13px';
  var szLabel=document.createElement('label');szLabel.style='font-size:13px;color:#334155;display:flex;align-items:center;gap:5px';
  szLabel.appendChild(document.createTextNode('Show '));
  var szSel=document.createElement('select');szSel.style='padding:5px 8px;border:1px solid #d7e1f2;border-radius:6px;font-size:13px';
  [{{v:0,t:'All'}},{{v:50,t:'50'}},{{v:100,t:'100'}},{{v:250,t:'250'}}].forEach(function(o){{
    var opt=document.createElement('option');opt.value=o.v;opt.text=o.t;
    if(o.v===0)opt.selected=true;szSel.appendChild(opt);
  }});
  szLabel.appendChild(szSel);szLabel.appendChild(document.createTextNode(' entries'));
  var info=document.createElement('span');info.style='font-size:13px;color:#68758a;white-space:nowrap';
  ctrl.appendChild(search);ctrl.appendChild(szLabel);ctrl.appendChild(info);
  tbl.closest('.panel').insertBefore(ctrl,document.getElementById('findings-scroll'));
  function render(){{
    var ps=pageSize,start=ps?(page-1)*ps:0,end=ps?start+ps:filtered.length;
    rows.forEach(function(r){{r.style.display='none';}});
    filtered.slice(start,end).forEach(function(r){{r.style.display='';}});
    info.textContent='Showing '+(filtered.length?start+1:0)+'\u2013'+Math.min(end,filtered.length)+' of '+filtered.length+' (total '+total+')';
    renderPager(ps);
  }}
  function renderPager(ps){{
    var old=document.getElementById('findings-pager');if(old)old.remove();
    if(!ps||filtered.length<=ps)return;
    var pages=Math.ceil(filtered.length/ps);
    var nav=document.createElement('div');nav.id='findings-pager';
    nav.style='display:flex;gap:5px;margin-top:8px;flex-wrap:wrap';
    function btn(label,target,active,disabled){{
      var b=document.createElement('button');b.textContent=label;b.disabled=disabled;
      b.style='padding:4px 10px;border:1px solid #d7e1f2;border-radius:5px;cursor:pointer;font-size:13px;background:'+(active?'#1d4ed8':'#fff')+';color:'+(active?'#fff':'#334155');
      if(!disabled)b.onclick=function(){{page=target;render();}};return b;
    }}
    nav.appendChild(btn('\u00ab',1,false,page===1));nav.appendChild(btn('\u2039',page-1,false,page===1));
    var s=Math.max(1,page-2),e=Math.min(pages,s+4);
    for(var p=s;p<=e;p++)nav.appendChild(btn(p,p,p===page,false));
    nav.appendChild(btn('\u203a',page+1,false,page===pages));nav.appendChild(btn('\u00bb',pages,false,page===pages));
    document.getElementById('findings-scroll').appendChild(nav);
  }}
  var timer;
  search.addEventListener('input',function(){{
    clearTimeout(timer);timer=setTimeout(function(){{
      var q=search.value.toLowerCase();
      filtered=q?rows.filter(function(r){{return r.textContent.toLowerCase().indexOf(q)!==-1;}}):rows.slice();
      page=1;render();
    }},200);
  }});
  szSel.addEventListener('change',function(){{pageSize=parseInt(szSel.value);page=1;render();}});
  render();
}})();</script>
</body></html>
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
            ("ggshield", lambda: run_ggshield(ctx, repo_dir, directory / "ggshield.json")),
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
    write_findings_csv(kept, ctx.reports / "report.csv")
    (ctx.reports / "report.html").write_text(html_report(report, "report.csv"), encoding="utf-8")
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
    write_findings_csv(kept, ctx.reports / "report.csv")
    (ctx.reports / "report.html").write_text(html_report(report, "report.csv"), encoding="utf-8")
    log("INFO", f"Report regenere sans scan: {ctx.reports / 'report.html'}")
    log("INFO", f"Findings retenus: {len(kept)} | whitelistes: {len(ignored)} | erreurs scan: {len(scan_errors)}")


def safe_branch_name(branch: str) -> str:
    return re.sub(r'[<>:"/\\|?*]', "_", branch)


def list_remote_branches(repo_dir: Path) -> list[str]:
    proc = run_process(
        ["git", "-C", str(repo_dir), "branch", "-r"],
        capture=True,
    )
    branches = []
    for line in proc.stdout.splitlines():
        name = line.strip()
        if not name or "->" in name:
            continue
        if name.startswith("origin/"):
            name = name[len("origin/"):]
        branches.append(name)
    return sorted(set(branches))


def _scan_repo_deep(
    ctx: Context, repo_dir: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan one repo (git history + all branches). Returns (findings, projects, errors).

    Designed to run concurrently with other repos — all output is written to
    per-repo directories so there are no file-level conflicts between workers.
    """
    name = repo_name(ctx, repo_dir)
    findings: list[dict[str, Any]] = []
    projects: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    branches = list_remote_branches(repo_dir)
    if not branches:
        log("WARN", f"Aucune branche distante trouvee pour {name}, ignore")
        return findings, projects, errors
    log("INFO", f"{name}: {len(branches)} branche(s): {', '.join(branches)}")

    # Scan git history once per repo (Gitleaks git + TruffleHog git + ggshield git)
    git_dir = raw_dir(ctx, name)
    for scanner, func in [
        ("Gitleaks-git", lambda d=git_dir: run_gitleaks_git(ctx, repo_dir, d / "gitleaks-git.json")),
        ("TruffleHog-git", lambda d=git_dir: run_trufflehog_git(ctx, repo_dir, d / "trufflehog-git.jsonl")),
        ("ggshield-git", lambda d=git_dir: run_ggshield_git(ctx, repo_dir, d / "ggshield-git.json")),
    ]:
        try:
            log("INFO", f"Scan {scanner}: {name}")
            func()
        except Exception as exc:
            errors.append({"repo": name, "scanner": scanner, "error": str(exc)})
            log("ERROR", f"{name} / {scanner}: {exc}")

    git_findings = normalize_git_findings(name, git_dir)
    (git_dir / "findings-git.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in git_findings),
        encoding="utf-8",
    )
    findings.extend(git_findings)

    # Per-branch: detect-secrets, semgrep, heuristic on tip of each branch
    worktree_base = ctx.workspace / "worktrees" / safe_raw_name(name)
    worktree_base.mkdir(parents=True, exist_ok=True)
    try:
        for branch in branches:
            branch_label = f"{name}@{branch}"
            safe_b = safe_branch_name(branch)
            worktree_path = worktree_base / safe_b
            branch_dir = raw_dir(ctx, f"{name}@{branch}")

            if worktree_path.exists():
                run_process(["git", "-C", str(repo_dir), "worktree", "remove", "--force", str(worktree_path)], check=False)
                force_rmtree(worktree_path)

            wt_cmd = ["git", "-C", str(repo_dir), "worktree", "add", "--detach", str(worktree_path), f"origin/{branch}"]
            wt_result = run_process(wt_cmd, check=False)
            if wt_result.returncode != 0:
                err_msg = f"Commande en echec ({wt_result.returncode}): {' '.join(wt_cmd)}"
                errors.append({"repo": branch_label, "scanner": "worktree", "error": err_msg})
                log("ERROR", err_msg)
                run_process(["git", "-C", str(repo_dir), "worktree", "remove", "--force", str(worktree_path)], check=False)
                force_rmtree(worktree_path)
                continue

            # Remove the .git file (worktree link) so Docker scanners don't see a broken git path
            worktree_git = worktree_path / ".git"
            if worktree_git.exists():
                worktree_git.unlink(missing_ok=True)

            files = create_manifest(worktree_path, branch_label, branch_dir / "files-manifest.json")
            projects.append({"path_with_namespace": branch_label, "file_count": len(files)})

            for scanner, func in [
                ("detect-secrets", lambda wt=worktree_path, bd=branch_dir: run_detect_secrets(ctx, wt, bd / "detect-secrets.json")),
                ("Semgrep", lambda wt=worktree_path, bd=branch_dir: run_semgrep(ctx, wt, bd / "semgrep.json", git_aware=False)),
                ("heuristique", lambda wt=worktree_path, bl=branch_label, f=files, bd=branch_dir: run_heuristic(wt, bl, f, bd / "heuristic.jsonl")),
                ("ggshield", lambda wt=worktree_path, bd=branch_dir: run_ggshield(ctx, wt, bd / "ggshield.json")),
            ]:
                try:
                    log("INFO", f"Scan {scanner}: {branch_label}")
                    func()
                except Exception as exc:
                    errors.append({"repo": branch_label, "scanner": scanner, "error": str(exc)})
                    log("ERROR", f"{branch_label} / {scanner}: {exc}")

            branch_findings = normalize_findings(branch_label, branch_dir, worktree_path)
            (branch_dir / "findings.jsonl").write_text(
                "".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in branch_findings),
                encoding="utf-8",
            )
            findings.extend(branch_findings)

            # Clean up worktree: rmtree first, then prune (git worktree remove fails without .git file)
            force_rmtree(worktree_path)
    finally:
        run_process(["git", "-C", str(repo_dir), "worktree", "prune"], check=False)
        force_rmtree(worktree_base)

    return findings, projects, errors


def analyze_deep(
    ctx: Context,
    whitelist: Path,
    skip_build: bool = False,
    repo_filter: str | None = None,
    workers: int = 4,
) -> None:
    require_tools("docker", "git")
    if not whitelist.exists():
        die(f"Whitelist introuvable: {whitelist}")
    if not skip_build:
        build_detect_secrets(ctx)

    repos = [resolve_repo_filter(ctx, repo_filter)] if repo_filter else local_repos(ctx)
    if not repos:
        die(f"Aucun repo local detecte dans {ctx.repos}. Lance d'abord sync-deep.")

    all_findings: list[dict[str, Any]] = []
    projects: list[dict[str, Any]] = []
    scan_errors: list[dict[str, Any]] = []

    # When a single repo is targeted, no parallelism is needed.
    effective_workers = 1 if repo_filter else min(workers, len(repos))
    log("INFO", f"Scan de {len(repos)} repo(s) avec {effective_workers} worker(s) en parallele")

    with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures = {executor.submit(_scan_repo_deep, ctx, repo_dir): repo_dir for repo_dir in repos}
        for future in concurrent.futures.as_completed(futures):
            repo_dir = futures[future]
            try:
                repo_findings, repo_projects, repo_errors = future.result()
            except Exception as exc:
                name = repo_name(ctx, repo_dir)
                log("ERROR", f"Repo {name} a echoue avec une exception inattendue: {exc}")
                scan_errors.append({"repo": name, "scanner": "analyze_deep", "error": str(exc)})
            else:
                all_findings.extend(repo_findings)
                projects.extend(repo_projects)
                scan_errors.extend(repo_errors)

    kept, ignored = whitelist_findings(all_findings, whitelist)
    report = {
        "generatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "groupPath": ctx.gitlab_group_path,
        "repoCount": len(projects),
        "fileCount": sum(p["file_count"] for p in projects),
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
    write_findings_csv(kept, ctx.reports / "report.csv")
    (ctx.reports / "report.html").write_text(html_report(report, "report.csv"), encoding="utf-8")
    log("INFO", f"Report JSON: {ctx.reports / 'report.json'}")
    log("INFO", f"Report HTML: {ctx.reports / 'report.html'}")
    log("INFO", f"Findings retenus: {len(kept)} | whitelistes: {len(ignored)} | erreurs scan: {len(scan_errors)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SAMU - Secrets Analysis & Monitoring Utility")
    parser.add_argument("command", choices=[
        "sync", "analyze", "report",
        "scan", "scan-open",
        "sync-deep", "analyze-deep", "scan-deep", "scan-deep-open",
    ])
    parser.add_argument("--secrets-file", default=".secrets")
    parser.add_argument("--whitelist-file", default="config/whitelist.json")
    parser.add_argument("--skip-detect-secrets-build", action="store_true")
    parser.add_argument("--repo", help="Repo local a analyser: namespace GitLab ou chemin local quelconque")
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Nombre de repos scannés en parallèle pour analyze-deep (defaut: 4)",
    )
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
    elif args.command == "sync-deep":
        sync_deep(ctx)
    elif args.command == "analyze-deep":
        analyze_deep(ctx, whitelist, args.skip_detect_secrets_build, args.repo, args.workers)
    elif args.command == "scan-deep":
        sync_deep(ctx)
        analyze_deep(ctx, whitelist, args.skip_detect_secrets_build, args.repo, args.workers)
    elif args.command == "scan-deep-open":
        sync_deep(ctx)
        analyze_deep(ctx, whitelist, args.skip_detect_secrets_build, args.repo, args.workers)
        webbrowser.open((ctx.reports / "report.html").resolve().as_uri())


if __name__ == "__main__":
    main()
