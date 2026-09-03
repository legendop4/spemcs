"""RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

Conforms strictly to RFC 8785:
- UTF-8 output without BOM
- No whitespace outside strings
- Object keys sorted by UTF-16 code units (Section 3.2.3)
- Strict string escaping: only quotation mark ("), reverse solidus (\\),
  and control chars U+0000..U+001F are escaped (Section 3.2.2.2). All other Unicode unescaped.
- Strict numeric formatting conforming to ECMAScript 7.1.12.1 (Section 3.2.2.3)
- Deterministic array and object serialization
"""

import math
from typing import Any


def utf16_sort_key(s: str) -> bytes:
    """Sort keys by UTF-16 code units as required by RFC 8785 Section 3.2.3."""
    return s.encode("utf-16-be")


def canonicalize_string(s: str) -> str:
    """Serializes a string according to RFC 8785 Section 3.2.2.2.
    
    Only quotation mark, reverse solidus, and control characters U+0000 through U+001F
    are escaped. Control chars U+0000..U+001F that lack specific 2-char escape sequences
    (\\b, \\t, \\n, \\f, \\r) are escaped as \\u00xx in lowercase hexadecimal.
    All other characters (including U+007F..U+10FFFF and '/') MUST NOT be escaped.
    """
    out = ['"']
    for char in s:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == '\\':
            out.append('\\\\')
        elif char == '\b':
            out.append('\\b')
        elif char == '\f':
            out.append('\\f')
        elif char == '\n':
            out.append('\\n')
        elif char == '\r':
            out.append('\\r')
        elif char == '\t':
            out.append('\\t')
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def canonicalize_number(n: int | float) -> str:
    """Serializes a number according to RFC 8785 Section 3.2.2.3 and ECMAScript 7.1.12.1."""
    if isinstance(n, bool):
        raise TypeError("Boolean passed to canonicalize_number")
    if isinstance(n, int):
        return str(n)
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise ValueError(f"Invalid non-finite JSON float value: {n}")
        if n == 0.0:
            return "0"  # Handles negative zero (-0.0) -> "0"
        if n.is_integer() and -9007199254740991 <= int(n) <= 9007199254740991:
            return str(int(n))
        # Format float via Python repr (which conforms to modern ECMAScript shortest-roundtrip float format)
        s = repr(n)
        if "e" in s:
            parts = s.split("e")
            mantissa = parts[0]
            exp = int(parts[1])
            s = f"{mantissa}e{'+' if exp > 0 else ''}{exp}"
        return s
    raise TypeError(f"Unsupported numeric type: {type(n)}")


def canonicalize(obj: Any) -> str:
    """Recursively serialize a Python object to its canonical JSON string (RFC 8785)."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return canonicalize_number(obj)
    if isinstance(obj, str):
        return canonicalize_string(obj)
    if isinstance(obj, (list, tuple)):
        items = [canonicalize(item) for item in obj]
        return "[" + ",".join(items) + "]"
    if isinstance(obj, dict):
        # Keys MUST be strings and sorted by UTF-16 code units
        sorted_keys = sorted(obj.keys(), key=utf16_sort_key)
        parts = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise TypeError(f"Dictionary keys must be strings, got {type(k).__name__}")
            canonical_k = canonicalize_string(k)
            canonical_v = canonicalize(obj[k])
            parts.append(f"{canonical_k}:{canonical_v}")
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable under RFC 8785")


def canonicalize_to_bytes(obj: Any) -> bytes:
    """Returns canonical JSON bytes encoded as UTF-8 without BOM."""
    return canonicalize(obj).encode("utf-8")
