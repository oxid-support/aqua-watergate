#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Gate rules (English):
#
# Gate 0 (README contract):
# - README.md MUST exist at repo root (exact file name: README.md)
# - README.md must contain sections for:
#   - Compatibility: must allow extracting at least one supported OXID eShop compilation version (e.g. 7.4.0 or 7.4.x)
#   - Installation: MUST provide a fenced code block that contains a "composer require ..." command
#   - Activation: MUST provide a fenced code block that contains an "oe:module:activate" command
# - Migration is CONDITIONAL:
#   - If module migrations are detected by repository structure:
#       - migration/ (or migrations/) exists
#       - contains migrations.yml (or migration.yml / *.yaml)
#     then:
#       - README must provide a Migration(s) section with a fenced code block containing a migrations command
#         (migrations:migrate via oe-console or oe-eshop-doctrine_migration or oe-eshop-db_migrate)
#       - migration data folder (default: migration/data or derived from migrations_paths) must contain at least one .php file
#   - If no migrations exist: migration checks are skipped (do NOT fail)
#
# IMPORTANT: For Installation/Migration/Activation, Gate 0 does NOT simply pick the first heading match.
# It scans ALL matching headings and selects the first section that actually contains the required command
# inside a fenced code block. This avoids false positives like "Development installation".
#
# Gate 1 (Templates instrumented):
# - Templates are Smarty (.tpl) or Twig (.twig).
# - If NO templates exist in the repo => PASS.
# - If templates exist:
#   - For each template that contains HTML markup, require at least one `data-qa=...` attribute in that file.
#   - Templates without any HTML markup (e.g. only includes/extends) are ignored.
#
# Transport rule:
# - Only GitHub HTTPS repo URLs are allowed (no local paths).


@dataclass
class GateResult:
    status: str  # "pass" | "fail"
    details: List[str]


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 600) -> Tuple[int, str]:
    import subprocess

    try:
        cp = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return cp.returncode, cp.stdout
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") + "\n[TIMEOUT]\n"


def is_allowed_github_repo_url(url: str) -> bool:
    """
    Only allow GitHub HTTPS repo URLs.
    Accepted:
      - https://github.com/org/repo
      - https://github.com/org/repo.git
    Not accepted:
      - .../tree/branch (web URLs)
      - ssh URLs (git@github.com:...)
      - non-GitHub hosts
    """
    url = (url or "").strip()
    return re.match(r"^https://github\.com/[^/\s]+/[^/\s]+(?:\.git)?$", url) is not None


def clone_repo(url: str, ref: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="module_"))

    # Try shallow clone with branch/tag
    rc, _out = run_cmd(["git", "clone", "--depth", "1", "--branch", ref, url, str(tmp)], timeout=600)
    if rc == 0:
        return tmp

    # Fallback: full clone then checkout (supports commit hashes)
    shutil.rmtree(tmp, ignore_errors=True)
    tmp = Path(tempfile.mkdtemp(prefix="module_"))
    rc, out2 = run_cmd(["git", "clone", url, str(tmp)], timeout=600)
    if rc != 0:
        raise RuntimeError(f"git clone failed:\n{out2}")

    rc, out3 = run_cmd(["git", "checkout", ref], cwd=tmp, timeout=300)
    if rc != 0:
        raise RuntimeError(f"git checkout '{ref}' failed:\n{out3}")

    return tmp


# -----------------------------
# Markdown section extraction
# -----------------------------
def iter_headings(markdown: str) -> List[Tuple[int, str, int]]:
    """
    Return headings as tuples: (line_index, heading_text, level).
    Headings inside fenced code blocks are ignored.
    """
    lines = markdown.splitlines()
    heading_re = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*$")
    fence_re = re.compile(r"^\s*```")

    in_fence = False
    out: List[Tuple[int, str, int]] = []

    for i, line in enumerate(lines):
        if fence_re.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        m = heading_re.match(line)
        if not m:
            continue

        level = len(m.group(1))
        text = (m.group(2) or "").strip()
        out.append((i, text, level))

    return out


def extract_section_by_heading_index(markdown: str, heading_idx: int, heading_level: int) -> str:
    lines = markdown.splitlines()
    heading_re = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*$")

    end_idx = len(lines)
    for j in range(heading_idx + 1, len(lines)):
        m = heading_re.match(lines[j])
        if not m:
            continue
        lvl = len(m.group(1))
        if lvl <= heading_level:
            end_idx = j
            break

    return "\n".join(lines[heading_idx + 1 : end_idx]).strip() + "\n"


def extract_sections_all(markdown: str, title_regexes: List[str]) -> List[Tuple[str, str]]:
    """
    Return list of (heading_text, section_body) for ALL matching headings.
    """
    res: List[Tuple[str, str]] = []
    for idx, text, level in iter_headings(markdown):
        norm = re.sub(r"\s+", " ", text).strip()
        if any(re.search(rx, norm, flags=re.IGNORECASE) for rx in title_regexes):
            body = extract_section_by_heading_index(markdown, idx, level)
            res.append((norm, body))
    return res


def extract_fenced_code_blocks(section_md: str) -> List[str]:
    """
    Extract all fenced code block contents from a markdown fragment.
    Supports ```lang ... ``` and plain ``` ... ```.
    """
    blocks: List[str] = []
    pos = 0
    while True:
        m = re.search(r"```[a-zA-Z0-9_-]*\s*\n", section_md[pos:])
        if not m:
            break
        start = pos + m.end()
        end = section_md.find("```", start)
        if end == -1:
            break
        blocks.append(section_md[start:end].strip() + "\n")
        pos = end + 3
    return blocks


def pick_section_with_required_command(
    markdown: str,
    title_regexes: List[str],
    command_predicate,
) -> Tuple[str, Optional[str], List[str]]:
    """
    Pick the first matching section whose fenced code blocks satisfy command_predicate.
    Returns (section_body, matched_heading, candidate_headings).
    """
    candidates = extract_sections_all(markdown, title_regexes)
    candidate_headings = [h for h, _ in candidates]

    for heading, body in candidates:
        for block in extract_fenced_code_blocks(body):
            if command_predicate(block):
                return body, heading, candidate_headings

    return "", None, candidate_headings


def pick_section_with_compatibility(
    markdown: str, title_regexes: List[str]
) -> Tuple[str, Optional[str], List[str], List[str], Dict[str, str]]:
    """
    Pick the first matching section that allows extracting at least one compilation version.
    Returns (body, heading, candidates, versions, branch_map).
    """
    candidates = extract_sections_all(markdown, title_regexes)
    candidate_headings = [h for h, _ in candidates]

    for heading, body in candidates:
        versions, branch_map = parse_oxid_compilation_versions(body)
        if versions:
            return body, heading, candidate_headings, versions, branch_map

    return "", None, candidate_headings, [], {}


# -----------------------------
# Command detection
# -----------------------------
def has_composer_require_command(code: str) -> bool:
    # Allow optional prompt prefixes ($, >, #)
    for line in code.splitlines():
        if re.match(r"^\s*(?:[$>#]\s*)?composer\s+require\b", line):
            return True
    return False


def has_migration_command(code: str) -> bool:
    # Accept common OXID migration command forms
    patterns = [
        r"\boe-eshop-db_migrate\b.*\bmigrations:migrate\b",
        r"\boe-eshop-doctrine_migration\b.*\bmigrations:migrate\b",
        r"\boe-console\b.*\bmigrations:migrate\b",
        r"\boe:migrations:migrate\b",
    ]
    for line in code.splitlines():
        for pat in patterns:
            if re.search(pat, line):
                return True
    return False


def has_activation_command(code: str) -> bool:
    for line in code.splitlines():
        if re.search(r"\boe:module:activate\b", line):
            return True
    return False


# -----------------------------
# Compatibility parsing
# -----------------------------
def parse_oxid_compilation_versions(text: str) -> Tuple[List[str], Dict[str, str]]:
    """
    Extract supported OXID eShop compilation versions from a Compatibility-like section.

    Returns:
      - versions: list like ["7.4.0", "7.4.x"]
      - branch_map: mapping like {"b-7.4.x": "7.4.x"} when present
    """
    versions: set[str] = set()
    branch_map: Dict[str, str] = {}

    version_patterns = [
        r"(?i)\boxid\s+eshop\s+compilation\s+version\s+(\d+\.\d+\.(?:\d+|x))\b",
        r"(?i)\boxid\s+eshop\s+compilation\s+(\d+\.\d+\.(?:\d+|x))\b",
        r"(?i)\bcompilation\s+version\s+(\d+\.\d+\.(?:\d+|x))\b",
        r"(?i)\bcompilation\s+(\d+\.\d+\.(?:\d+|x))\b",
    ]
    for pat in version_patterns:
        for m in re.finditer(pat, text):
            versions.add(m.group(1))

    # Branch mapping: "b-7.4.x" -> "7.4.x"
    branch_re = re.compile(r"(?i)\b(b-\d+\.\d+\.(?:x|\d+))\b")
    line_version_re = re.compile(r"(?i)\b(\d+\.\d+\.(?:x|\d+))\b")
    for line in text.splitlines():
        bm = branch_re.search(line)
        if not bm:
            continue
        branch = bm.group(1)
        vm = line_version_re.search(line)
        if vm:
            v = vm.group(1)
            branch_map[branch] = v
            versions.add(v)
        else:
            derived = branch[2:]
            branch_map[branch] = derived
            versions.add(derived)

    def sort_key(v: str) -> Tuple[int, int, int, int]:
        parts = v.split(".")
        major = int(parts[0]) if parts and parts[0].isdigit() else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        patch_part = parts[2] if len(parts) > 2 else "0"
        if patch_part.lower() == "x":
            patch = 999
            is_x = 1
        else:
            patch = int(patch_part) if patch_part.isdigit() else 0
            is_x = 0
        return (major, minor, patch, is_x)

    return sorted(versions, key=sort_key), branch_map


# -----------------------------
# Migration detection (repo structure)
# -----------------------------
def _extract_migration_data_dir_from_config(config_text: str) -> str:
    """
    Best-effort YAML parsing (without external deps):
    Look for:
      migrations_paths:
        'Some\\Namespace': data
    Return the first mapped value (e.g. "data"). Default: "data".
    """
    lines = config_text.splitlines()
    in_block = False

    for raw in lines:
        line = raw.rstrip("\n")
        if re.match(r"^\s*migrations_paths\s*:\s*$", line):
            in_block = True
            continue

        if not in_block:
            continue

        # End block on next top-level key (no indentation)
        if line and not line.startswith(" "):
            break

        m = re.match(r"^\s*['\"]?[^:'\"]+['\"]?\s*:\s*([^\s#]+)\s*$", line)
        if m:
            val = m.group(1).strip().strip("'\"")
            if val:
                return val

    return "data"


def detect_module_migrations(module_dir: Path) -> Dict[str, object]:
    """
    Detect OXID module migrations by structure:
      - migration/ (or migrations/) directory exists
      - contains migrations.yml (or migration.yml / *.yaml)
      - data folder (default: migration/data or derived from migrations_paths) contains at least one .php file
    """
    issues: List[str] = []

    migration_dir: Optional[Path] = None
    for candidate in (module_dir / "migration", module_dir / "migrations"):
        if candidate.is_dir():
            migration_dir = candidate
            break

    meta: Dict[str, object] = {
        "hasMigrationDir": migration_dir is not None,
        "migrationDir": str(migration_dir) if migration_dir else None,
        "configFile": None,
        "dataDir": None,
        "phpFileCount": 0,
        "phpFilesSample": [],
        "migrationsDetected": False,
        "issues": issues,
    }

    if migration_dir is None:
        return meta

    config_candidates = ("migrations.yml", "migration.yml", "migrations.yaml", "migration.yaml")
    config_path: Optional[Path] = None
    for name in config_candidates:
        p = migration_dir / name
        if p.is_file():
            config_path = p
            break

    # Treat as "has migrations" only if config exists
    if config_path is None:
        return meta

    meta["configFile"] = str(config_path)
    meta["migrationsDetected"] = True

    config_text = read_text(config_path)
    data_subdir = _extract_migration_data_dir_from_config(config_text)
    data_dir = migration_dir / data_subdir
    meta["dataDir"] = str(data_dir)

    if not data_dir.is_dir():
        issues.append(f"Migration config found but data folder is missing: {data_dir}")
        return meta

    php_files = sorted(p for p in data_dir.rglob("*.php") if p.is_file())
    meta["phpFileCount"] = len(php_files)
    meta["phpFilesSample"] = [str(p.relative_to(module_dir)) for p in php_files[:10]]

    if len(php_files) == 0:
        issues.append(f"Migration config found but no .php migration files found under: {data_dir}")

    return meta


# -----------------------------
# Gate 0
# -----------------------------
def gate0_readme_contract(module_dir: Path) -> Tuple[GateResult, Dict[str, object]]:
    readme_path = module_dir / "README.md"
    if not readme_path.exists():
        return GateResult("fail", ["README.md is missing"]), {"matchedHeadings": {}}

    md = read_text(readme_path)

    mig_meta = detect_module_migrations(module_dir)
    migrations_required = bool(mig_meta.get("migrationsDetected", False))

    heading_rules: Dict[str, List[str]] = {
        "Compatibility": [
            r"\bcompatibility\b",
            r"\bbranch\s+compatibility\b",
            r"\bsupported\s+versions\b",
            r"\brequirements\b",
        ],
        "Installation": [
            r"\binstallation\b",
            r"\binstall\b",
        ],
        "Migration": [
            r"\bmigration\b",
            r"\bmigrations\b",
            r"\bdatabase\s+migrations?\b",
            r"\bdoctrine\s+migrations?\b",
        ],
        "Activation": [
            r"\bactivation\b",
            r"\bactivate\b",
            r"\bmodule\s+activation\b",
        ],
    }

    details: List[str] = []
    meta: Dict[str, object] = {"matchedHeadings": {}, "migration": mig_meta}

    # Compatibility: pick a section that yields compilation versions
    compat_body, compat_heading, compat_candidates, compat_versions, compat_branch_map = pick_section_with_compatibility(
        md, heading_rules["Compatibility"]
    )
    if not compat_body.strip():
        details.append(
            "Compatibility: no section found that allows extracting an OXID eShop compilation version "
            "(expected patterns like 'Compilation version 7.4.0' or 'compilation 7.4.x'). "
            f"Matched compatibility headings: {', '.join(compat_candidates) if compat_candidates else '(none)'}"
        )
    else:
        meta["matchedHeadings"]["Compatibility"] = compat_heading or ""
        meta["compatibility"] = {"oxidCompilation": compat_versions, "branchMap": compat_branch_map}

    # Installation: pick section that actually contains composer require
    install_body, install_heading, install_candidates = pick_section_with_required_command(
        md, heading_rules["Installation"], has_composer_require_command
    )
    if not install_body.strip():
        details.append(
            "Installation: no section found that contains a fenced code block with 'composer require'. "
            f"Matched installation headings: {', '.join(install_candidates) if install_candidates else '(none)'}"
        )
    else:
        meta["matchedHeadings"]["Installation"] = install_heading or ""

    # Activation: pick section that actually contains oe:module:activate
    act_body, act_heading, act_candidates = pick_section_with_required_command(
        md, heading_rules["Activation"], has_activation_command
    )
    if not act_body.strip():
        details.append(
            "Activation: no section found that contains a fenced code block with 'oe:module:activate'. "
            f"Matched activation headings: {', '.join(act_candidates) if act_candidates else '(none)'}"
        )
    else:
        meta["matchedHeadings"]["Activation"] = act_heading or ""

    # Migration: only required if migrations are detected by structure
    if migrations_required:
        mig_body, mig_heading, mig_candidates = pick_section_with_required_command(
            md, heading_rules["Migration"], has_migration_command
        )
        if not mig_body.strip():
            details.append(
                "Migration: migrations detected in repo, but no section found that contains a fenced code block "
                "with a migrations command (migrations:migrate). "
                f"Matched migration headings: {', '.join(mig_candidates) if mig_candidates else '(none)'}"
            )
        else:
            meta["matchedHeadings"]["Migration"] = mig_heading or ""

        mig_issues = mig_meta.get("issues", [])
        if isinstance(mig_issues, list) and mig_issues:
            details.extend([f"Migration structure: {msg}" for msg in mig_issues])

    if details:
        return GateResult("fail", details), meta

    # If no migrations are required, include an informational note
    if not migrations_required:
        return GateResult("pass", ["No module migrations detected (Migration check skipped)"]), meta

    return GateResult("pass", []), meta


# -----------------------------
# Gate 1
# -----------------------------
def is_template_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tpl") or name.endswith(".twig")


def should_skip_path(path: Path) -> bool:
    # Skip common dependency and VCS dirs
    skip_parts = {".git", "vendor", "node_modules", ".idea", ".cache", ".github"}
    return any(part in skip_parts for part in path.parts)


def find_template_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if should_skip_path(p):
            continue
        if is_template_file(p):
            files.append(p)
    return sorted(files)


_HTML_TAG_RE = re.compile(r"<\s*[a-zA-Z][^>]*>")


def has_html_markup(text: str) -> bool:
    return _HTML_TAG_RE.search(text) is not None


def has_data_qa(text: str) -> bool:
    # Require quoted value: data-qa="..." or data-qa='...'
    return re.search(r"\bdata-qa\s*=\s*(['\"]).+?\1", text) is not None


def gate1_templates_data_qa(module_dir: Path) -> Tuple[GateResult, Dict[str, object]]:
    templates = find_template_files(module_dir)
    meta: Dict[str, object] = {
        "templateCount": len(templates),
        "templatesChecked": [],
        "templatesIgnoredNoMarkup": [],
    }

    if len(templates) == 0:
        return GateResult("pass", ["No Smarty/Twig templates found (Gate 1 skipped)"]), meta

    missing: List[str] = []
    checked = 0
    ignored = 0

    for t in templates:
        rel = str(t.relative_to(module_dir))
        text = read_text(t)

        if not has_html_markup(text):
            ignored += 1
            meta["templatesIgnoredNoMarkup"].append(rel)
            continue

        checked += 1
        meta["templatesChecked"].append(rel)

        if not has_data_qa(text):
            missing.append(f"Template missing any data-qa attribute: {rel}")

    meta["templatesWithMarkupChecked"] = checked
    meta["templatesIgnoredNoMarkupCount"] = ignored

    if checked == 0:
        return GateResult("pass", ["Templates found, but none contained HTML markup (nothing to instrument)"]), meta

    if missing:
        return GateResult("fail", missing), meta

    return GateResult(
        "pass",
        [f"All templates with HTML markup contain at least one data-qa attribute ({checked} checked)"],
    ), meta


# -----------------------------
# Main
# -----------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="GateRunner – Gate 0 (README) + Gate 1 (templates) static checks (GitHub only)")
    parser.add_argument("--module-url", required=True, help="GitHub repo URL (e.g. https://github.com/org/repo.git)")
    parser.add_argument("--module-ref", default="main", help="Branch/tag/commit (default: main)")
    parser.add_argument("--out", default=os.environ.get("OUT_DIR", "/out"), help="Output directory (default: /out)")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    module_url = (args.module_url or "").strip()
    if not is_allowed_github_repo_url(module_url):
        write_text(
            out_dir / "gate-result.json",
            json.dumps(
                {
                    "error": "Only GitHub HTTPS repo URLs are allowed",
                    "expected": "https://github.com/<org>/<repo> or https://github.com/<org>/<repo>.git",
                    "got": module_url,
                },
                indent=2,
            ),
        )
        return 2

    temp_dir: Optional[Path] = None
    try:
        temp_dir = clone_repo(module_url, args.module_ref)
        module_dir = temp_dir
    except Exception as e:
        write_text(out_dir / "gate-result.json", json.dumps({"error": f"clone failed: {e!r}"}, indent=2))
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return 2

    result: Dict[str, object] = {
        "moduleUrl": module_url,
        "moduleRef": args.module_ref,
        "modulePath": str(module_dir),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gates": {},
    }

    failed = False

    # Gate 0 (always attempt) + explicit README existence check
    readme_path = module_dir / "README.md"
    if not readme_path.exists():
        result["gates"]["gate0"] = {"status": "fail", "details": ["README.md is missing (required file at repo root)"]}
        result["gate0Meta"] = {"matchedHeadings": {}}
        failed = True
    else:
        try:
            g0, g0meta = gate0_readme_contract(module_dir)
            result["gates"]["gate0"] = {"status": g0.status, "details": g0.details}
            result["gate0Meta"] = g0meta
            if g0.status != "pass":
                failed = True
        except Exception as e:
            result["gates"]["gate0"] = {"status": "fail", "details": [f"Gate 0 crashed: {e!r}"]}
            failed = True

    # Gate 1 (always run, even if Gate 0 failed)
    try:
        g1, g1meta = gate1_templates_data_qa(module_dir)
        result["gates"]["gate1"] = {"status": g1.status, "details": g1.details}
        result["gate1Meta"] = g1meta
        if g1.status != "pass":
            failed = True
    except Exception as e:
        result["gates"]["gate1"] = {"status": "fail", "details": [f"Gate 1 crashed: {e!r}"]}
        failed = True

    write_text(out_dir / "gate-result.json", json.dumps(result, indent=2))

    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
