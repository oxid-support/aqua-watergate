"""
Gate 1: Templates Instrumented (data-qa)

Templates are Smarty (.tpl) or Twig (.twig).
- If NO templates exist => PASS
- If templates exist: each template with HTML markup must have at least one data-qa attribute
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

from ..utils import read_text
from .base import GateResult


def is_template_file(path: Path) -> bool:
    """Check if file is a Smarty or Twig template."""
    name = path.name.lower()
    return name.endswith(".tpl") or name.endswith(".twig")


def should_skip_path(path: Path) -> bool:
    """Check if path should be skipped (vendor, .git, etc.)."""
    skip_parts = {".git", "vendor", "node_modules", ".idea", ".cache", ".github"}
    return any(part in skip_parts for part in path.parts)


def find_template_files(root: Path) -> List[Path]:
    """Find all template files in directory."""
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
    """Check if text contains HTML markup."""
    return _HTML_TAG_RE.search(text) is not None


def has_data_qa(text: str) -> bool:
    """Check if text contains a data-qa attribute with quoted value."""
    return re.search(r"\bdata-qa\s*=\s*(['\"]).+?\1", text) is not None


def gate1_templates_data_qa(module_dir: Path) -> Tuple[GateResult, Dict[str, object]]:
    """
    Check Gate 1: Templates must have data-qa attributes.

    Returns (GateResult, metadata).
    """
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
