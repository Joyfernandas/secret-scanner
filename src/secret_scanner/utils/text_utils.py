"""Text processing utilities."""

import re
from typing import Tuple
from ..core.config import I18N_SUFFIXES


def get_line_col_from_index(text: str, index: int) -> Tuple[int, int]:
    """Get line and column numbers from string index."""
    before = text[:index]
    line = before.count("\n") + 1
    col = index - before.rfind("\n") if "\n" in before else index + 1
    return line, col


def looks_like_i18n_key(s: str) -> bool:
    """Check if string looks like an internationalization key."""
    if any(s.endswith(suffix) for suffix in I18N_SUFFIXES):
        return True
    if s.count("_") >= 3 and re.fullmatch(r"[A-Za-z0-9_]+", s):
        return True
    return False


def is_suspicious_token(s: str, min_len: int = 40) -> bool:
    """Determine if a string is a suspicious token using heuristics."""
    if not s or len(s) < min_len:
        return False
    
    ss = s.strip("\"'` ")
    if looks_like_i18n_key(ss):
        return False
    
    # Require digits or base64 characters, plus letters, or mixed-case + digits
    if (re.search(r"[0-9]", ss) or re.search(r"[+/=]", ss)) and re.search(r"[A-Za-z]", ss):
        return True
    if re.search(r"[A-Z]", ss) and re.search(r"[a-z]", ss) and re.search(r"[0-9]", ss):
        return True
    
    return False


def extract_context(text: str, start: int, end: int, context_size: int = 80) -> str:
    """Extract context around a position in text."""
    context_start = max(0, start - context_size)
    context_end = min(len(text), end + context_size)
    return text[context_start:context_end].replace("\n", " ")


def truncate_string(s: str, max_length: int = 50) -> str:
    """Truncate string with ellipsis if too long."""
    if len(s) > max_length:
        return s[:max_length] + "..."
    return s