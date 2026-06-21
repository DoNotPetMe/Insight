"""Tests for the Project facade and the web API."""

import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from insight.project import Project
from insight.web.app import create_app
from samples.build_samples import build_module


def _demo_bytes():
    return build_module().to_bytes()


def test_project_detects_script():
    proj = Project(_demo_bytes(), name="demo.gsv")
    assert proj.kind == "script"
    assert proj.arch == "gamescript-vm"
    assert len(proj.functions()) == 4


def test_project_pseudocode_and_disasm():
    proj = Project(_demo_bytes())
    funcs = {f.name: f.key for f in proj.functions()}
    code = proj.pseudocode(funcs["sum_to"])
    assert "while (" in code
    rows = proj.disassembly(funcs["sum_to"])
    assert rows and "text" in rows[0]


def test_web_api_roundtrip():
    app = create_app(Project(_demo_bytes(), name="demo.gsv"))
    c = app.test_client()
    assert c.get("/").status_code == 200
    assert c.get("/api/info").get_json()["loaded"] is True
    fns = c.get("/api/functions").get_json()
    assert len(fns) == 4
    code = c.get(f"/api/pseudocode/{fns[0]['key']}").get_json()["code"]
    assert code.startswith("function ")


def test_web_upload_replaces_project():
    app = create_app(None)
    c = app.test_client()
    assert c.get("/api/info").get_json()["loaded"] is False
    r = c.post("/api/upload",
               data={"file": (io.BytesIO(_demo_bytes()), "demo.gsv")},
               content_type="multipart/form-data")
    assert r.get_json()["ok"] is True
    assert len(c.get("/api/functions").get_json()) == 4
