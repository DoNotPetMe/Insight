"""Flask web UI for interactive exploration.

Serves a single-page app: a function list on the left, and disassembly /
pseudocode / strings views on the right.  A file can be supplied up front
(``insight serve FILE``) or uploaded through the browser.
"""

from __future__ import annotations

import io

from flask import Flask, jsonify, render_template, request

from ..project import Project


def create_app(project: Project | None = None) -> Flask:
    app = Flask(__name__)
    state = {"project": project}

    def current() -> Project | None:
        return state["project"]

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/info")
    def api_info():
        proj = current()
        if proj is None:
            return jsonify({"loaded": False})
        info = proj.info()
        info["loaded"] = True
        return jsonify(info)

    @app.route("/api/functions")
    def api_functions():
        proj = current()
        if proj is None:
            return jsonify([])
        return jsonify([
            {"key": f.key, "name": f.name, "addr": f"{f.addr:#x}",
             "size": f.size, "kind": f.kind}
            for f in proj.functions()])

    @app.route("/api/disasm/<key>")
    def api_disasm(key):
        proj = current()
        if proj is None:
            return jsonify({"error": "no file loaded"}), 400
        return jsonify({"rows": proj.disassembly(key)})

    @app.route("/api/pseudocode/<key>")
    def api_pseudo(key):
        proj = current()
        if proj is None:
            return jsonify({"error": "no file loaded"}), 400
        return jsonify({"code": proj.pseudocode(key)})

    @app.route("/api/strings")
    def api_strings():
        proj = current()
        if proj is None:
            return jsonify([])
        return jsonify(proj.strings())

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "no file"}), 400
        data = f.read()
        try:
            state["project"] = Project(data, name=f.filename or "uploaded")
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ok": True, "name": f.filename})

    return app
