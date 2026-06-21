"""Content-discovery scanner.

Heuristics that flag the things modders and dataminers hunt for: developer
rooms, test maps, debug menus, leftover/unused content, cheat and god-mode
switches, and placeholder assets.  It scores candidates from filenames, strings
pulled out of binaries, and text assets, so it works equally on a raw binary or
an unpacked game directory.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Patterns match against a *normalised* form of the text, where every run of
# non-alphanumeric characters (``_ - / . space`` …) becomes a single space.
# This makes word boundaries behave the same in ``dev_room``, ``dev-room``,
# ``DevRoom`` (when separated) and ``dev room``.  ``\b`` then works reliably.
_PATTERNS = {
    "dev_room": (5, r"\b(dev ?room|developer room|debug room|sandbox|"
                    r"test room|hidden room)\b"),
    "test_map": (5, r"\b((test|debug) (map|level|scene|stage|area|world|zone|room)|"
                    r"\w+ test|map test|playground|gr[ae]ybox|whitebox)\b"),
    "debug": (4, r"\b(debug menu|debug mode|debug draw|dbg|show fps|wireframe|"
                 r"developer console|gm debug|debug build)\b"),
    "unused": (4, r"\b(unused|deprecated|obsolete|leftover|backup|legacy|"
                  r"cut content|scrapped|removed|do not use|old version)\b"),
    "cheat": (3, r"\b(god ?mode|noclip|infinite (ammo|health|money)|cheat|"
                 r"invincib\w*|all items|unlock all|give item|fly mode)\b"),
    "placeholder": (3, r"\b(placeholder|dummy|temp|temporary|wip|tbd|todo|fixme|"
                       r"missing (texture|model)|null asset|notexture|errortex|donotuse)\b"),
    "beta": (3, r"\b(beta|alpha|prototype|proto|early access|preview|"
                r"internal build|staging)\b"),
    "secret": (2, r"\b(secret|easter egg|hidden|unlockable|bonus (level|room))\b"),
}

_COMPILED = {cat: (w, re.compile(rx, re.IGNORECASE)) for cat, (w, rx) in _PATTERNS.items()}


def _normalize(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", " ", text).strip()


@dataclass
class Finding:
    category: str
    score: int
    text: str
    source: str          # where it came from ("string", "filename", "asset:<n>")
    matched: str = ""    # the token that triggered it


@dataclass
class DiscoveryReport:
    findings: list = field(default_factory=list)

    def by_category(self):
        out: dict[str, list] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def summary(self):
        out = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out


def _scan_text(text: str, source: str):
    found = []
    norm = _normalize(text)
    if not norm:
        return found
    for cat, (weight, rx) in _COMPILED.items():
        m = rx.search(norm)
        if m:
            found.append(Finding(category=cat, score=weight, text=text[:200],
                                 source=source, matched=m.group(0)))
    return found


def scan_strings(strings, source="string"):
    out = []
    for s in strings:
        val = s if isinstance(s, str) else getattr(s, "value", str(s))
        out += _scan_text(val, source)
    return out


def scan_names(names):
    out = []
    for n in names:
        out += _scan_text(n, "filename")
    return out


def scan_directory(path: str, max_files: int = 20000):
    out, count = [], 0
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            count += 1
            if count > max_files:
                break
            rel = os.path.relpath(os.path.join(root, name), path)
            out += _scan_text(rel, "filename")
        if count > max_files:
            break
    return out


def report(findings) -> DiscoveryReport:
    # de-duplicate identical (category, text) and keep the highest score first
    seen = set()
    uniq = []
    for f in sorted(findings, key=lambda f: -f.score):
        key = (f.category, f.text, f.source)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return DiscoveryReport(findings=uniq)
