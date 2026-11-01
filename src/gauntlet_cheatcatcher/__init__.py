"""gauntlet-cheatcatcher: spot AI coding agents that game their tests instead of fixing the code."""

from .diff import FileDiff, parse_patch
from .models import Finding, Report
from .rules import RULES, rule
from .scan import scan

__all__ = ["RULES", "FileDiff", "Finding", "Report", "parse_patch", "rule", "scan"]
__version__ = "0.1.0"
