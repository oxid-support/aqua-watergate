"""Shared utility functions."""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple


def write_text(path: Path, text: str) -> None:
    """Write text to a file, creating parent directories if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_text(path: Path) -> str:
    """Read text from a file."""
    return path.read_text(encoding="utf-8", errors="ignore")


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 600) -> Tuple[int, str]:
    """Run a command and return (exit_code, output)."""
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


def sanitize_url(url: str) -> str:
    """Remove credentials from URL for safe logging/output."""
    return re.sub(r"https://[^@]+@github\.com", "https://github.com", url)


def is_allowed_github_repo_url(url: str) -> bool:
    """
    Only allow GitHub HTTPS repo URLs.
    Accepted:
      - https://github.com/org/repo
      - https://github.com/org/repo.git
      - https://user:token@github.com/org/repo
      - https://token@github.com/org/repo
    Not accepted:
      - .../tree/branch (web URLs)
      - ssh URLs (git@github.com:...)
      - non-GitHub hosts
    """
    url = (url or "").strip()
    return re.match(r"^https://(?:[^@\s]+@)?github\.com/[^/\s]+/[^/\s]+(?:\.git)?$", url) is not None


def clone_repo(url: str, ref: str) -> Path:
    """Clone a git repository and checkout the specified ref."""
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
