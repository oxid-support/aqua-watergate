# GateRunner

This image runs **Gate 0 + Gate 1**:
- **Gate 0 (README contract)**: README must contain machine-checkable instructions for
  - Compatibility (supported OXID eShop compilation version)
  - Installation (Composer)
  - Migration (only if migrations exist in the repo)
  - Activation (module activation command)
- **Gate 1 (Templates instrumented)**: Smarty/Twig templates must include `data-qa` attributes (if templates exist)

No runtime, no browser, no docker-compose.

## Installation
```bash
git clone https://github.com/oxid-support/aqua-watergate
cd aqua-watergate
```

## Build
```bash
docker build -t gate-runner:latest .
```

## Run (GitHub only)
Only GitHub repos are allowed.

```bash
mkdir -p out

docker run --rm \
  -v "$(pwd)/out:/out" \
  gate-runner:latest \
  --module-url "https://github.com/<org>/<repo>.git" \
  --module-ref "main"
```

## Gate rules

### Gate 0 – README contract

`README.md` must exist at repo root (`README.md`).

#### Compatibility
Accepted headings (examples):
- `Compatibility`
- `Branch compatibility`
- `Supported versions`
- `Requirements`

The section must allow extracting **at least one** supported OXID eShop compilation version, e.g.:
- `7.4.0`
- `7.4.x`

#### Installation
Accepted headings (examples):
- `Installation`
- `Install`

Must include at least one fenced code block (```bash ... ``` or plain ``` ... ```) containing:
- a line with `composer require ...`

Note: Gate 0 scans **all** matching headings and selects the first section that actually contains the required command in a fenced code block (avoids false positives like “Development installation”).

#### Migration (conditional)
Migration is only required **if the repository contains migrations**:
- directory `migration/` or `migrations/` exists AND
- it contains `migrations.yml` / `migration.yml` / `migrations.yaml` / `migration.yaml`

If migrations exist, README must contain a Migration section (accepted headings like `Migration`, `Migrations`, `Database migrations`, `Doctrine migrations`) with at least one fenced code block containing a migrations command, e.g.:
- `./vendor/bin/oe-eshop-doctrine_migration migrations:migrate ...`
- `./vendor/bin/oe-eshop-db_migrate migrations:migrate ...`
- `./vendor/bin/oe-console ... migrations:migrate ...`
- `oe:migrations:migrate ...`

Additionally, the migrations data folder must contain at least one `.php` migration file.

If no migrations exist in the repo, migration checks are skipped (no failure).

#### Activation
Accepted headings (examples):
- `Activation`
- `Activate`
- `Module activation`

Must include at least one fenced code block containing:
- `oe:module:activate` (typically via `./vendor/bin/oe-console oe:module:activate <module-id>`)

### Gate 1 – Templates instrumented (`data-qa`)
Templates are:
- Smarty: `.tpl`
- Twig: `.twig` (including `.html.twig`)

Rules:
- If **no** templates exist in the repo → **PASS** (Gate 1 skipped).
- If templates exist:
  - For each template that contains HTML markup, require at least one `data-qa="..."` or `data-qa='...'` attribute in that file.
  - Templates without any HTML markup (only includes/extends/wrappers) are ignored.

## Output
- `/out/gate-result.json`
