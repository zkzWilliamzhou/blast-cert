"""blast: offline, filesystem-grounded pre-execution impact certificates."""
from .api import analyze, analyze_with_defaults
from .model import SCHEMA_VERSION, TOOL_VERSION

__version__ = TOOL_VERSION
__all__ = ["analyze", "analyze_with_defaults", "TOOL_VERSION", "SCHEMA_VERSION"]
