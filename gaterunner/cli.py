"""Command-line interface for GateRunner."""

import argparse
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Dict, Optional

from .gates import gate0_readme_contract, gate1_templates_data_qa
from .utils import clone_repo, is_allowed_github_repo_url, sanitize_url, write_text


def main() -> int:
    """Main entry point for GateRunner CLI."""
    parser = argparse.ArgumentParser(
        description="GateRunner – Static gate checks for OXID modules (GitHub only)"
    )
    parser.add_argument(
        "--module-url",
        required=True,
        help="GitHub repo URL (e.g. https://github.com/org/repo.git)",
    )
    parser.add_argument(
        "--module-ref",
        default="main",
        help="Branch/tag/commit (default: main)",
    )
    parser.add_argument(
        "--out",
        default=os.environ.get("OUT_DIR", "/out"),
        help="Output directory (default: /out)",
    )
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
                    "got": sanitize_url(module_url),
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
        error_msg = str(e)
        # Sanitize any credentials from error message
        error_msg = re.sub(r"https://[^@\s]+@github\.com", "https://github.com", error_msg)
        write_text(
            out_dir / "gate-result.json",
            json.dumps({"error": f"clone failed: {error_msg}"}, indent=2),
        )
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return 2

    result: Dict[str, object] = {
        "moduleUrl": sanitize_url(module_url),
        "moduleRef": args.module_ref,
        "modulePath": str(module_dir),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gates": {},
    }

    failed = False

    # Gate 0: README contract
    readme_path = module_dir / "README.md"
    if not readme_path.exists():
        result["gates"]["gate0"] = {
            "status": "fail",
            "details": ["README.md is missing (required file at repo root)"],
        }
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

    # Gate 1: Templates data-qa
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
