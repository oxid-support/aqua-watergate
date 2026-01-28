"""Base classes for gates."""

from dataclasses import dataclass
from typing import List


@dataclass
class GateResult:
    """Result of a gate check."""
    status: str  # "pass" | "fail"
    details: List[str]
