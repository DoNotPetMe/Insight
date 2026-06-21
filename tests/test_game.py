"""Tests for engine detection, tool registry, and content discovery."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from insight.game import detect, discovery, unpack, engines
from insight.frontends import registry


def test_detect_magic_bytes():
    assert detect.detect_bytes(b"GSV1....", "x.gsv")[0].engine_id == "gamescript"
    assert detect.detect_bytes(b"GDPC\x01\x00", "x.pck")[0].engine_id == "godot"
    assert detect.detect_bytes(b"FORM\x00\x00", "data.win")[0].engine_id == "gamemaker"


def test_detect_unreal_pak_footer():
    data = b"\x00" * 300 + b"\xE1\x12\x6F\x5A" + b"\x00" * 40
    dets = detect.detect_bytes(data, "pakchunk0.pak")
    assert any(d.engine_id == "unreal" for d in dets)


def test_detect_unity_directory(tmp_path):
    d = tmp_path / "game"
    managed = d / "Game_Data" / "Managed"
    managed.mkdir(parents=True)
    (d / "UnityPlayer.dll").write_bytes(b"")
    (managed / "Assembly-CSharp.dll").write_bytes(b"")
    dets = detect.detect_path(str(d))
    assert dets and dets[0].engine_id == "unity"
    assert dets[0].variant == "Mono"


def test_detect_unity_il2cpp_variant(tmp_path):
    d = tmp_path / "game"
    meta = d / "Game_Data" / "il2cpp_data" / "Metadata"
    meta.mkdir(parents=True)
    (meta / "global-metadata.dat").write_bytes(b"\xAF\x1B\xB1\xFA")
    (d / "GameAssembly.dll").write_bytes(b"")
    (d / "Game_Data").mkdir(exist_ok=True)
    dets = detect.detect_path(str(d))
    assert dets[0].engine_id == "unity"
    assert dets[0].variant == "IL2CPP"


def test_discovery_categories():
    names = ["test_map_arena", "DEV_ROOM", "unused_enemy_OLD",
             "god_mode_toggle", "placeholder_tex", "beta_weapon",
             "main_menu", "player"]
    rep = discovery.report(discovery.scan_names(names))
    cats = rep.summary()
    for expected in ("test_map", "dev_room", "unused", "cheat", "placeholder", "beta"):
        assert expected in cats, f"missing {expected} in {cats}"


def test_discovery_ignores_ordinary_text():
    rep = discovery.report(discovery.scan_strings(["hello world", "PlayerHealth", "render_frame"]))
    assert rep.findings == []


def test_tool_status_reports_python_libs():
    rows = unpack.tool_status("unity")
    unitypy = next(r for r in rows if r["name"] == "UnityPy")
    assert unitypy["python"] is True
    assert unitypy["installed"] is True   # installed in this environment


def test_every_engine_has_a_frontend():
    for eid in engines.ENGINES:
        assert registry.for_engine(eid) is not None, f"no frontend for {eid}"
