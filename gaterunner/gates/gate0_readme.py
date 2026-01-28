"""
Gate 0: README Contract

README.md must exist at repo root and contain sections for:
- Compatibility: must allow extracting at least one supported OXID eShop compilation version
- Installation: must provide a fenced code block with 'composer require ...'
- Activation: must provide a fenced code block with 'oe:module:activate'
- Migration (conditional): only required if module has migrations
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..utils import read_text
from .base import GateResult


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
    """Extract section content below a heading."""
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
    """Return list of (heading_text, section_body) for ALL matching headings."""
    res: List[Tuple[str, str]] = []
    for idx, text, level in iter_headings(markdown):
        norm = re.sub(r"\s+", " ", text).strip()
        if any(re.search(rx, norm, flags=re.IGNORECASE) for rx in title_regexes):
            body = extract_section_by_heading_index(markdown, idx, level)
            res.append((norm, body))
    return res


def extract_fenced_code_blocks(section_md: str) -> List[str]:
    """Extract all fenced code block contents from a markdown fragment."""
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
    """Check if code contains a composer require command."""
    for line in code.splitlines():
        if re.match(r"^\s*(?:[$>#]\s*)?composer\s+require\b", line):
            return True
    return False


def has_migration_command(code: str) -> bool:
    """Check if code contains an OXID migration command."""
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
    """Check if code contains an oe:module:activate command."""
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
# Migration detection
# -----------------------------
def _extract_migration_data_dir_from_config(config_text: str) -> str:
    """
    Best-effort YAML parsing: Look for migrations_paths and return the mapped value.
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
    Detect OXID module migrations by structure.
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
# Gate 0 main function
# -----------------------------
def gate0_readme_contract(module_dir: Path) -> Tuple[GateResult, Dict[str, object]]:
    """
    Check Gate 0: README contract.

    Returns (GateResult, metadata).
    """
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

    # Compatibility
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

    # Installation
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

    # Activation
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

    # Migration (conditional)
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

    if not migrations_required:
        return GateResult("pass", ["No module migrations detected (Migration check skipped)"]), meta

    return GateResult("pass", []), meta
