"""logredact: strip secrets and personal data from logs before you share them.

>>> from logredact import Redactor
>>> Redactor(key=b"0123456789abcdef").redact("password=hunter22").text
'password=[REDACTED:assigned-secret]'
"""

from logredact.detectors import BUILTIN_DETECTORS, Action, Category, Detector
from logredact.redactor import Finding, RedactionResult, Redactor

__version__ = "0.1.0"

__all__ = [
    "BUILTIN_DETECTORS",
    "Action",
    "Category",
    "Detector",
    "Finding",
    "RedactionResult",
    "Redactor",
    "__version__",
]
