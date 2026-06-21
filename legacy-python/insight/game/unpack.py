"""Asset/script ingestion: route a detected target to the right extractor.

For formats with a usable Python library (e.g. UnityPy for Unity bundles) the
extraction runs in-process.  For formats whose best tooling is an external
application, Insight reports the recommended open-source tool and how to invoke
it rather than pretending to do the extraction itself.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field

from . import engines


@dataclass
class Asset:
    name: str
    type: str
    size: int = 0
    text: str | None = None      # populated for text-like assets


@dataclass
class Ingestion:
    engine_id: str
    assets: list = field(default_factory=list)
    scripts: list = field(default_factory=list)   # script/class names
    notes: list = field(default_factory=list)
    handled_by: str = ""

    @property
    def texts(self):
        return [a.text for a in self.assets if a.text]


def tool_status(engine_id: str) -> list[dict]:
    """Report recommended tools and whether each Python lib is importable."""
    eng = engines.get(engine_id)
    if not eng:
        return []
    rows = []
    for t in eng.tools:
        installed = None
        if t.pip:
            try:
                importlib.import_module(t.pip)
                installed = True
            except Exception:
                installed = False
        rows.append({"name": t.name, "url": t.url, "purpose": t.purpose,
                     "python": bool(t.pip), "installed": installed})
    return rows


def ingest(path: str, engine_id: str) -> Ingestion:
    if engine_id == "unity":
        return _ingest_unity(path)
    return _ingest_generic(path, engine_id)


# ---- Unity (via UnityPy) --------------------------------------------------
def _ingest_unity(path: str) -> Ingestion:
    ing = Ingestion(engine_id="unity", handled_by="UnityPy")
    try:
        UnityPy = importlib.import_module("UnityPy")
    except Exception:
        ing.notes.append("UnityPy not installed (pip install UnityPy) — "
                         "showing tool recommendations only")
        return ing

    targets = []
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in files:
                if f.endswith((".assets", ".bundle", ".unity3d")) or \
                        f in ("globalgamemanagers",) or "_Data" in root:
                    targets.append(os.path.join(root, f))
        targets = targets[:64]
    else:
        targets = [path]

    seen_scripts = set()
    for t in targets:
        try:
            env = UnityPy.load(t)
        except Exception:
            continue
        for obj in env.objects:
            tname = obj.type.name
            try:
                data = obj.read()
            except Exception:
                ing.assets.append(Asset(name="<unreadable>", type=tname))
                continue
            name = getattr(data, "m_Name", "") or getattr(data, "name", "") or ""
            if tname in ("MonoScript",):
                cls = getattr(data, "m_ClassName", name) or name
                if cls and cls not in seen_scripts:
                    seen_scripts.add(cls)
                    ing.scripts.append(cls)
            elif tname == "TextAsset":
                txt = getattr(data, "m_Script", None) or getattr(data, "text", None)
                if isinstance(txt, (bytes, bytearray)):
                    txt = txt.decode("utf-8", "replace")
                ing.assets.append(Asset(name=name or "TextAsset", type=tname,
                                        size=len(txt or ""), text=txt))
            else:
                ing.assets.append(Asset(name=name or tname, type=tname))
    if not ing.assets and not ing.scripts:
        ing.notes.append("no readable Unity objects found at this path")
    return ing


def _ingest_generic(path: str, engine_id: str) -> Ingestion:
    ing = Ingestion(engine_id=engine_id)
    eng = engines.get(engine_id)
    if eng:
        ing.notes.append(
            f"{eng.name}: extraction best handled by " +
            ", ".join(t.name for t in eng.tools) if eng.tools else
            f"{eng.name}: content is already in readable form")
    return ing
