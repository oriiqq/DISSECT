"""
ps_classifier — deobfuscation engine

Iteratively unwraps PowerShell obfuscation layers.
Runs BEFORE classification — rules operate on decoded_text, not raw_text.

Layers handled:
  - Base64 ([Convert]::FromBase64String / -EncodedCommand)
  - Char-code concatenation ([char]65+[char]66...)
  - Format string reordering ("{0}{2}{1}" -f "po","hell","wers")
  - String replace chains (.Replace('X',''))
  - Backtick insertion (pow`ersh`ell)
  - Join operator (('p','o','w') -join '')
  - Hex string literals (0x70 0x6f 0x77...)
  - Reversed strings ([string] reversed via -join '')
  - SecureString / PSCredential extraction
"""

from __future__ import annotations
import base64
import re
import binascii
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

MAX_PASSES   = 12
MAX_DEPTH    = 8   # prevent infinite recursion on polyglot encoders


# ── Transform functions ───────────────────────────────────────────────────────

def _unwrap_base64(text: str) -> str:
    """Decode [Convert]::FromBase64String('...') and -EncodedCommand blobs."""
    # Pattern 1: explicit FromBase64String call
    pat1 = re.compile(
        r'\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*[\'"]([A-Za-z0-9+/=\s]+)[\'"]\s*\)',
        re.IGNORECASE
    )
    for m in pat1.finditer(text):
        raw = m.group(1).replace('\n', '').replace('\r', '').strip()
        try:
            decoded = base64.b64decode(raw + '==').decode('utf-16-le').strip('\x00')
            if decoded and decoded.isprintable():
                text = text.replace(m.group(0), decoded)
        except Exception:
            pass

    # Pattern 2: bare large base64 blobs likely from -EncodedCommand
    pat2 = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/])')
    for m in pat2.finditer(text):
        raw = m.group(1)
        for encoding in ('utf-16-le', 'utf-8'):
            try:
                decoded = base64.b64decode(raw + '==').decode(encoding).strip('\x00')
                if len(decoded) > 10 and _looks_like_ps(decoded):
                    text = text.replace(m.group(0), decoded)
                    break
            except Exception:
                pass
    return text


def _unwrap_char_concat(text: str) -> str:
    """Resolve [char]65+[char]66 style concatenation."""
    pat = re.compile(r'\[char\]\s*(\d+)', re.IGNORECASE)
    def replace_char(m):
        try:
            return chr(int(m.group(1)))
        except (ValueError, OverflowError):
            return m.group(0)
    result = pat.sub(replace_char, text)

    # Also handle 0x hex char codes: [char]0x70
    pat_hex = re.compile(r'\[char\]\s*0x([0-9a-fA-F]+)', re.IGNORECASE)
    def replace_hex_char(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return pat_hex.sub(replace_hex_char, result)


def _unwrap_format_string(text: str) -> str:
    """Resolve "{0}{2}{1}" -f "po","hell","wers" → "powersh"."""
    pat = re.compile(
        r'["\'](\{[\d\s,:-]+\}(?:\{[\d\s,:-]+\})*)["\']'
        r'\s*-f\s*((?:["\'][^"\']*["\'](?:\s*,\s*)?)+)',
        re.IGNORECASE
    )
    for m in pat.finditer(text):
        fmt   = m.group(1)
        parts_raw = re.findall(r'["\']([^"\']*)["\']', m.group(2))
        try:
            slot_indices = [int(x) for x in re.findall(r'\{(\d+)\}', fmt)]
            result = ''.join(parts_raw[i] for i in slot_indices if i < len(parts_raw))
            if result:
                text = text.replace(m.group(0), result, 1)
        except Exception:
            pass
    return text


def _unwrap_replace_chains(text: str) -> str:
    """Unwrap .Replace('needle','') obfuscation patterns."""
    pat = re.compile(r'\.Replace\s*\(\s*[\'"]([^\'"]*)[\'"]'
                     r'\s*,\s*[\'"]([^\'"]*)[\'"\s]*\)', re.IGNORECASE)
    for _ in range(5):  # up to 5 chained replaces
        new_text = pat.sub(lambda m: '', text)  # simplified: remove the .Replace() call
        if new_text == text:
            break
        text = new_text
    return text


def _unwrap_backtick(text: str) -> str:
    """Remove PowerShell backtick escapes used for obfuscation."""
    # Backtick before ordinary letters = obfuscation (not a real escape)
    return re.sub(r'`([A-Za-z])', r'\1', text)


def _unwrap_join(text: str) -> str:
    """Resolve ('p','o','w','e','r') -join '' → 'power'."""
    pat = re.compile(
        r'\(\s*((?:["\'][^"\']*["\'](?:\s*,\s*)?)+)\)\s*-join\s*["\']["\']',
        re.IGNORECASE
    )
    def join_parts(m):
        parts = re.findall(r'["\']([^"\']*)["\']', m.group(1))
        return ''.join(parts)
    return pat.sub(join_parts, text)


def _unwrap_hex_strings(text: str) -> str:
    """Decode 0x70,0x6f,0x77... hex byte arrays."""
    pat = re.compile(r'(?:0x[0-9a-fA-F]{2}\s*,\s*){3,}0x[0-9a-fA-F]{2}')
    for m in pat.finditer(text):
        try:
            hexvals = re.findall(r'0x([0-9a-fA-F]{2})', m.group(0))
            decoded = bytes(int(h, 16) for h in hexvals).decode('utf-8', errors='replace')
            if _looks_like_ps(decoded):
                text = text.replace(m.group(0), f'"{decoded}"')
        except Exception:
            pass
    return text


def _unwrap_env_vars(text: str) -> str:
    """
    Resolve $env:ComSpec[14,15,35]-join'' style environment variable slicing.
    e.g. $env:ComSpec[14,15,35]-join'' → 'iex'
    """
    # Common well-known $env: variable character slicing patterns
    env_known = {
        "comspec":   r"C:\Windows\System32\cmd.exe",
        "windir":    r"C:\Windows",
        "systemroot": r"C:\Windows",
        "temp":      r"C:\Users\TEMP\AppData\Local\Temp",
        "programfiles": r"C:\Program Files",
    }
    pat = re.compile(
        r'\$env:(\w+)\s*\[\s*([\d,\s]+)\s*\]\s*-join\s*[\'"][\'"]',
        re.IGNORECASE
    )
    def resolve_env_slice(m):
        var_name = m.group(1).lower()
        base = env_known.get(var_name)
        if not base:
            return m.group(0)
        try:
            indices = [int(i.strip()) for i in m.group(2).split(",")]
            result = "".join(base[i] for i in indices if i < len(base))
            return result if result else m.group(0)
        except Exception:
            return m.group(0)
    return pat.sub(resolve_env_slice, text)


def _unwrap_securestring(text: str) -> str:
    """
    Extract plaintext from ConvertTo-SecureString / PSCredential patterns.
    e.g. ConvertTo-SecureString "password" -AsPlainText -Force
    """
    # Pattern 1: ConvertTo-SecureString "plaintext" -AsPlainText
    pat1 = re.compile(
        r'ConvertTo-SecureString\s+[\'"]([^\'"]+)[\'"]\s+-AsPlainText',
        re.IGNORECASE
    )
    text = pat1.sub(lambda m: f'"[PLAINTEXT_CRED:{m.group(1)}]"', text)

    # Pattern 2: System.Net.NetworkCredential construction with plaintext
    pat2 = re.compile(
        r'Net\.NetworkCredential\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
        re.IGNORECASE
    )
    text = pat2.sub(lambda m: f'"[CREDENTIAL:{m.group(1)}:{m.group(2)}]"', text)

    return text


def _unwrap_reversed(text: str) -> str:
    """Detect and reverse strings that are reversed for obfuscation."""
    # Pattern: [string::Join('', <array>)] where result looks reversed
    # Simple heuristic: if we see llehsrewop or tpircsrevop, reverse the whole token
    reversed_markers = ['llehsrewop', 'tpircsevrop', 'exe.tpircs', 'enilbaes']
    for marker in reversed_markers:
        if marker in text.lower():
            # Find the containing string literal and reverse it
            for quote in ('"', "'"):
                idx = text.lower().find(marker)
                start = text.rfind(quote, 0, idx)
                end   = text.find(quote, idx)
                if start != -1 and end != -1 and end > start:
                    inner = text[start+1:end]
                    text  = text[:start+1] + inner[::-1] + text[end:]
    return text


# ── Helpers ───────────────────────────────────────────────────────────────────

def _looks_like_ps(text: str) -> bool:
    """Heuristic: does this decoded string look like PowerShell?"""
    if len(text) < 5:
        return False
    ps_indicators = [
        'invoke', 'iex', 'powershell', 'cmdlet', 'param(', 'function ',
        'write-', 'get-', 'set-', 'new-', '$', 'webclient', 'downloadstring',
        'bypass', 'hidden', '-nop', 'amsi',
    ]
    lower = text.lower()
    return any(ind in lower for ind in ps_indicators) or text.count('$') > 2


# ── Public API ────────────────────────────────────────────────────────────────

@dataclass
class DeobfuscationResult:
    original:     str
    decoded:      str
    passes_run:   int
    transforms_applied: list[str]

    @property
    def changed(self) -> bool:
        return self.original != self.decoded


def deobfuscate(text: str, max_passes: int = MAX_PASSES) -> DeobfuscationResult:
    """
    Iteratively apply all deobfuscation transforms until stable or max_passes reached.
    Returns a DeobfuscationResult with the final decoded text and audit trail.
    """
    original  = text
    applied   = []
    passes    = 0

    transforms = [
        ('backtick',      _unwrap_backtick),
        ('join',          _unwrap_join),
        ('char_concat',   _unwrap_char_concat),
        ('hex_strings',   _unwrap_hex_strings),
        ('base64',        _unwrap_base64),
        ('format_string', _unwrap_format_string),
        ('replace_chain', _unwrap_replace_chains),
        ('reversed',      _unwrap_reversed),
        ('env_vars',      _unwrap_env_vars),
        ('securestring',  _unwrap_securestring),
    ]

    for _ in range(max_passes):
        snapshot = text
        for name, fn in transforms:
            before = text
            try:
                text = fn(text)
            except Exception as exc:
                log.debug("Transform %s failed: %s", name, exc)
            if text != before and name not in applied:
                applied.append(name)
        passes += 1
        if text == snapshot:
            break  # stable — no transform fired this pass

    return DeobfuscationResult(
        original=original,
        decoded=text,
        passes_run=passes,
        transforms_applied=applied,
    )
