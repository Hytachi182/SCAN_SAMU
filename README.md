# SAMU - Secrets Analysis & Monitoring Utility

> Scan de secrets GitLab en Python

```text
'######:::::'###::::'##::::'##:'##::::'##:
'##... ##:::'## ##::: ###::'###: ##:::: ##:
 ##:::..:::'##:. ##:: ####'####: ##:::: ##:
. ######::'##:::. ##: ## ### ##: ##:::: ##:
:..... ##: #########: ##. #: ##: ##:::: ##:
'##::: ##: ##.... ##: ##:.:: ##: ##:::: ##:
. ######:: ##:::: ##: ##:::: ##:. #######::
:......:::..:::::..::..:::::..:::.......:::
```

## Scanners

- `gitleaks`
- `trufflehog`
- `detect-secrets`
- `semgrep`
- `heuristic`, pour les assignations suspectes et placeholders comme `proxy_password: password`

## Prerequis

- `python`
- `git`
- `docker`

## Configuration

Renseigner `.secrets` a partir de [.secrets.example](./.secrets.example).

```env
GITLAB_BASE_URL=https://gitlab.example.com
GITLAB_GROUP_PATH=my-group/my-subgroup
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
DEFAULT_FALLBACK_BRANCH=main
WORKSPACE_DIR=./data
DETECT_SECRETS_IMAGE=scan-secrets/detect-secrets:local
GITLEAKS_IMAGES=ghcr.io/gitleaks/gitleaks:latest,zricethezav/gitleaks:latest
TRUFFLEHOG_IMAGES=trufflesecurity/trufflehog:latest
SEMGREP_IMAGES=semgrep/semgrep:latest
SEMGREP_CONFIGS=/rules/semgrep-secrets.yml,p/secrets
```

Si `ghcr.io` est refuse par Docker, force Docker Hub :

```env
GITLEAKS_IMAGES=zricethezav/gitleaks:latest
```

## Commandes

Synchroniser les repos :

```bash
python scripts/samu.py sync
```

Analyser les repos deja synchronises :

```bash
python scripts/samu.py analyze
```

Relancer l'analyse sans rebuilder l'image locale `detect-secrets` :

```bash
python scripts/samu.py analyze --skip-detect-secrets-build
```

Analyser un seul repo local :

```bash
python scripts/samu.py analyze --repo /path/to/repo --skip-detect-secrets-build
```

`--repo` accepte un chemin local quelconque ou un namespace deja clone sous `data/repos`.

Regenerer uniquement le rapport depuis les resultats existants, sans relancer les scanners :

```bash
python scripts/samu.py report
```

Regenerer uniquement le rapport pour un repo deja analyse :

```bash
python scripts/samu.py report --repo /path/to/repo
```

Pipeline complet :

```bash
python scripts/samu.py scan
```

Pipeline complet puis ouverture du rapport :

```bash
python scripts/samu.py scan-open
```

## Structure

- [scripts/samu.py](./scripts/samu.py) : moteur Python complet
- [config/whitelist.json](./config/whitelist.json) : whitelist commune
- [config/semgrep-secrets.yml](./config/semgrep-secrets.yml) : regles Semgrep locales pour secrets simples
- [docker/detect-secrets.Dockerfile](./docker/detect-secrets.Dockerfile) : image locale `detect-secrets`

## Sorties

Les fichiers generes sont recrees sous `data/` :

- `data/repos/` : repos clones
- `data/raw/<repo>/gitleaks.json`
- `data/raw/<repo>/trufflehog.jsonl`
- `data/raw/<repo>/detect-secrets.json`
- `data/raw/<repo>/semgrep.json`
- `data/raw/<repo>/heuristic.jsonl`
- `data/raw/<repo>/files-manifest.json`
- `data/raw/scan-errors.json`
- `data/reports/report.json`
- `data/reports/report.html`

`files-manifest.json` liste tous les fichiers du working tree pris en compte pour chaque repo, hors metadata `.git`.

## Whitelist

[config/whitelist.json](./config/whitelist.json) permet d'ignorer des findings par :

- chemin de fichier
- valeur de secret
- repo
- scanner
- rule id

## Securite

La synchronisation force :

- API GitLab en `HTTPS`
- verification du host GitLab avant clone
- clone `--depth 1`, sans tags
- hooks Git neutralises
- `protocol.file.allow=never`
- scans Docker en lecture seule sur les repos clones

