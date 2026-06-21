"""High-level facade for a game target (a file or an install directory).

Ties together engine detection, the tool registry, asset/script ingestion, and
the content-discovery scanner, and tells the caller exactly how Insight will
decompile that engine's logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import detect, unpack, discovery, engines
from ..frontends import registry as frontends
from ..analysis.strings import find_strings


@dataclass
class GameReport:
    path: str
    detections: list = field(default_factory=list)
    tools: list = field(default_factory=list)
    frontend: object = None
    ingestion: object = None
    discovery: object = None

    @property
    def best(self):
        return self.detections[0] if self.detections else None


class GameTarget:
    def __init__(self, path: str):
        self.path = path
        self.is_dir = os.path.isdir(path)
        self.detections = detect.detect_path(path)

    @property
    def engine_id(self):
        return self.detections[0].engine_id if self.detections else None

    def engine(self):
        eid = self.engine_id
        return engines.get(eid) if eid else None

    def analyze(self, do_ingest=True, do_discovery=True) -> GameReport:
        rep = GameReport(path=self.path, detections=self.detections)
        eid = self.engine_id
        if not eid:
            return rep
        rep.tools = unpack.tool_status(eid)
        rep.frontend = frontends.for_engine(eid)

        findings = []
        if do_ingest:
            try:
                rep.ingestion = unpack.ingest(self.path, eid)
                findings += discovery.scan_names(
                    [a.name for a in rep.ingestion.assets] + rep.ingestion.scripts)
                for a in rep.ingestion.assets:
                    if a.text:
                        findings += discovery.scan_strings([a.text],
                                                           source=f"asset:{a.name}")
            except Exception:
                pass

        if do_discovery:
            if self.is_dir:
                findings += discovery.scan_directory(self.path)
            else:
                # binary/file: pull strings and scan them + the filename
                try:
                    from ..core import binary as binmod
                    view = binmod.load_path(self.path)
                    findings += discovery.scan_strings(find_strings(view))
                except Exception:
                    pass
                findings += discovery.scan_names([os.path.basename(self.path)])
            rep.discovery = discovery.report(findings)
        return rep
