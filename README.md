# GateRunner (v5) – Gate 0 only (README contract)

This image runs **Gate 0 only**:
- README must contain actionable, machine-checkable instructions for:
  - **Installation** (Composer)
  - **Migration** (DB migrations command)
  - **Activation** (module activation command)

No runtime, no browser, no docker-compose.

## Build
```bash
docker build -t gate-runner:latest .
```

## Run (GitHub/Git URL)
```bash
mkdir -p out

docker run --rm \
  -v "$(pwd)/out:/out" \
  gate-runner:latest \
  --module-url "https://github.com/<org>/<repo>.git" \
  --module-ref "main"
```

## README requirements (English)

Your `README.md` must have these headings 

- `Installation`
- `Migration`
- `Activation`

Each section must include **at least one fenced code block** (```bash ... ``` or plain ``` ... ```) with commands:

### Installation
Must contain at least one line starting with `composer ` (e.g. `composer require ...`).

### Migration
Must contain at least one migration command, e.g.:
- `./vendor/bin/oe-eshop-doctrine_migration migrations:migrate ...`
- `./vendor/bin/oe-console ... migrations:migrate ...`

### Activation
Must contain at least one activation command, e.g.:
- `./vendor/bin/oe-console oe:module:activate <module-id>`

## Output
- `/out/gate-result.json`
