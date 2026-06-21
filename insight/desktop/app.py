"""Insight desktop application (PySide6/Qt).

A native, professional UI over the same engine as the CLI and web app:

* **Overview**  — engine detection, runtime, recommended tools, decompiler path.
* **Code**      — function list with disassembly / pseudocode views.
* **Discovery** — flagged dev rooms, test maps, unused/debug content.
* **Live**      — attach to a running process and scan its memory.

Packaged to a standalone ``.exe`` by the PyInstaller build (see
``packaging/`` and the GitHub Actions workflow).
"""

from __future__ import annotations

import os
import sys

try:
    from PySide6 import QtWidgets, QtGui, QtCore
except Exception as exc:  # pragma: no cover - import guard
    raise SystemExit(
        "PySide6 is required for the desktop app: pip install PySide6-Essentials\n"
        f"({exc})")

from ..project import Project
from ..game.target import GameTarget
from ..game import engines, unpack
from ..frontends import registry
from ..live import memscan


DARK_QSS = """
* { font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #0d1117; color: #c9d1d9; }
QTabWidget::pane { border: 1px solid #2a3340; }
QTabBar::tab { background: #161b22; color: #7d8794; padding: 7px 16px; }
QTabBar::tab:selected { background: #0d1117; color: #c9d1d9; border-bottom: 2px solid #58a6ff; }
QListWidget, QTreeWidget, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox {
    background: #161b22; color: #c9d1d9; border: 1px solid #2a3340; border-radius: 6px;
}
QPlainTextEdit { font-family: 'Consolas','SF Mono',monospace; }
QPushButton { background: #238636; color: #fff; border: none; padding: 7px 14px; border-radius: 6px; }
QPushButton:hover { background: #2ea043; }
QPushButton:disabled { background: #30363d; color: #7d8794; }
QHeaderView::section { background: #161b22; color: #7d8794; border: none; padding: 4px; }
QLabel#title { color: #58a6ff; font-size: 16px; font-weight: bold; }
QLabel#hint { color: #7d8794; }
"""


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Insight — game analysis & decompilation")
        self.resize(1180, 760)
        self.project: Project | None = None

        self._build_menu()
        self.tabs = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_overview()
        self._build_code()
        self._build_discovery()
        self._build_live()
        self.statusBar().showMessage("Open a game file or folder to begin.")

    # -- chrome ---------------------------------------------------------
    def _build_menu(self):
        bar = self.menuBar()
        m = bar.addMenu("&File")
        a_open = m.addAction("Open file…")
        a_open.triggered.connect(self.open_file)
        a_dir = m.addAction("Open game folder…")
        a_dir.triggered.connect(self.open_folder)
        m.addSeparator()
        m.addAction("Quit", self.close)

    # -- Overview tab ---------------------------------------------------
    def _build_overview(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)
        self.ov_title = QtWidgets.QLabel("No target loaded")
        self.ov_title.setObjectName("title")
        lay.addWidget(self.ov_title)
        self.ov_text = QtWidgets.QPlainTextEdit()
        self.ov_text.setReadOnly(True)
        lay.addWidget(self.ov_text)
        self.tabs.addTab(w, "Overview")

    # -- Code tab -------------------------------------------------------
    def _build_code(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QHBoxLayout(w)
        left = QtWidgets.QVBoxLayout()
        self.func_filter = QtWidgets.QLineEdit()
        self.func_filter.setPlaceholderText("filter functions…")
        self.func_filter.textChanged.connect(self._refilter_funcs)
        left.addWidget(self.func_filter)
        self.func_list = QtWidgets.QListWidget()
        self.func_list.currentItemChanged.connect(self._show_function)
        left.addWidget(self.func_list)
        lw = QtWidgets.QWidget(); lw.setLayout(left); lw.setMaximumWidth(320)
        lay.addWidget(lw)

        self.code_tabs = QtWidgets.QTabWidget()
        self.pseudo_view = QtWidgets.QPlainTextEdit(); self.pseudo_view.setReadOnly(True)
        self.disasm_view = QtWidgets.QPlainTextEdit(); self.disasm_view.setReadOnly(True)
        self.code_tabs.addTab(self.pseudo_view, "Pseudocode")
        self.code_tabs.addTab(self.disasm_view, "Disassembly")
        lay.addWidget(self.code_tabs, 1)
        self.tabs.addTab(w, "Code")

    # -- Discovery tab --------------------------------------------------
    def _build_discovery(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)
        row = QtWidgets.QHBoxLayout()
        self.disc_btn = QtWidgets.QPushButton("Scan for dev rooms / test maps / unused content")
        self.disc_btn.clicked.connect(self.run_discovery)
        row.addWidget(self.disc_btn); row.addStretch(1)
        lay.addLayout(row)
        self.disc_tree = QtWidgets.QTreeWidget()
        self.disc_tree.setHeaderLabels(["Category", "Match", "Source", "Context"])
        self.disc_tree.setColumnWidth(0, 120)
        lay.addWidget(self.disc_tree)
        self.tabs.addTab(w, "Discovery")

    # -- Live tab -------------------------------------------------------
    def _build_live(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)
        warn = QtWidgets.QLabel("Only scan processes you own or are authorised to inspect.")
        warn.setObjectName("hint")
        lay.addWidget(warn)
        row = QtWidgets.QHBoxLayout()
        self.proc_combo = QtWidgets.QComboBox()
        refresh = QtWidgets.QPushButton("Refresh"); refresh.clicked.connect(self._load_procs)
        row.addWidget(QtWidgets.QLabel("Process:")); row.addWidget(self.proc_combo, 1)
        row.addWidget(refresh)
        lay.addLayout(row)
        row2 = QtWidgets.QHBoxLayout()
        self.scan_value = QtWidgets.QLineEdit(); self.scan_value.setPlaceholderText("value to scan for")
        self.scan_kind = QtWidgets.QComboBox(); self.scan_kind.addItems(["string", "int32"])
        self.scan_auth = QtWidgets.QCheckBox("I'm authorised")
        scan_btn = QtWidgets.QPushButton("Scan"); scan_btn.clicked.connect(self.run_memscan)
        row2.addWidget(self.scan_kind); row2.addWidget(self.scan_value, 1)
        row2.addWidget(self.scan_auth); row2.addWidget(scan_btn)
        lay.addLayout(row2)
        self.scan_results = QtWidgets.QPlainTextEdit(); self.scan_results.setReadOnly(True)
        lay.addWidget(self.scan_results)
        self.tabs.addTab(w, "Live")
        self._load_procs()

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def open_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open game file")
        if path:
            self._load_path(path, is_dir=False)

    def open_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Open game folder")
        if path:
            self._load_path(path, is_dir=True)

    def _load_path(self, path, is_dir):
        self.current_path = path
        target = GameTarget(path)
        self._show_overview(target)
        # load decompilable single file into the Project facade
        self.project = None
        if not is_dir:
            try:
                self.project = Project.from_path(path)
            except Exception:
                self.project = None
        self._populate_funcs()
        self.statusBar().showMessage(f"Loaded {os.path.basename(path)}")

    def _show_overview(self, target: GameTarget):
        lines = []
        if target.detections:
            d = target.detections[0]
            eng = engines.get(d.engine_id)
            self.ov_title.setText(f"{eng.name if eng else d.engine_id}"
                                  f"{(' · ' + d.variant) if d.variant else ''}"
                                  f"   ({d.confidence*100:.0f}% confidence)")
            if eng:
                lines.append(f"Runtime   : {eng.runtime}")
                lines.append(f"Insight   : {eng.insight_support}")
            fe = registry.for_engine(d.engine_id)
            if fe:
                lines.append(f"Decompiler: {fe.strategy} ({fe.status}) — {fe.detail}")
            lines.append("\nEvidence:")
            lines += [f"  · {e}" for e in d.evidence]
            lines.append("\nRecommended open-source tools:")
            for t in unpack.tool_status(d.engine_id):
                mark = (" [installed]" if t["installed"]
                        else " [pip install]" if t["python"] else "")
                lines.append(f"  · {t['name']:<26} {t['purpose']:<8} {t['url']}{mark}")
        else:
            self.ov_title.setText("Unrecognised target")
            lines.append("No known engine signature matched.")
        self.ov_text.setPlainText("\n".join(lines))

    def _populate_funcs(self):
        self.func_list.clear()
        if not self.project:
            return
        for f in self.project.functions():
            it = QtWidgets.QListWidgetItem(f"{f.name}   ({f.addr:#x})")
            it.setData(QtCore.Qt.UserRole, f.key)
            it.setData(QtCore.Qt.UserRole + 1, f.name.lower())
            self.func_list.addItem(it)

    def _refilter_funcs(self, text):
        text = text.lower()
        for i in range(self.func_list.count()):
            it = self.func_list.item(i)
            it.setHidden(text not in (it.data(QtCore.Qt.UserRole + 1) or ""))

    def _show_function(self, cur, _prev=None):
        if not cur or not self.project:
            return
        key = cur.data(QtCore.Qt.UserRole)
        try:
            self.pseudo_view.setPlainText(self.project.pseudocode(key))
            rows = self.project.disassembly(key)
            self.disasm_view.setPlainText(
                "\n".join(f"{r['addr']:>10}  {r['text']}" for r in rows))
        except Exception as exc:
            self.pseudo_view.setPlainText(f"// error: {exc}")

    def run_discovery(self):
        if not getattr(self, "current_path", None):
            return
        self.disc_tree.clear()
        rep = GameTarget(self.current_path).analyze(do_ingest=True, do_discovery=True)
        disc = rep.discovery
        if not disc:
            return
        for f in disc.findings:
            QtWidgets.QTreeWidgetItem(
                self.disc_tree, [f.category, f.matched, f.source, f.text[:80]])
        self.statusBar().showMessage(f"Discovery: {disc.summary()}")

    def _load_procs(self):
        self.proc_combo.clear()
        for p in memscan.list_processes()[:4000]:
            self.proc_combo.addItem(f"{p.pid} — {p.name}", p.pid)

    def run_memscan(self):
        pid = self.proc_combo.currentData()
        if pid is None:
            return
        if not self.scan_auth.isChecked():
            self.scan_results.setPlainText("Tick “I'm authorised” to scan.")
            return
        try:
            with memscan.LiveSession(int(pid), authorized=True) as s:
                if self.scan_kind.currentText() == "string":
                    hits = s.scan_string(self.scan_value.text(), limit=200)
                else:
                    hits = s.scan_int(int(self.scan_value.text() or "0"), limit=200)
            self.scan_results.setPlainText(
                f"{len(hits)} hit(s):\n" + "\n".join(hex(h) for h in hits))
        except Exception as exc:
            self.scan_results.setPlainText(f"error: {exc}")


def main(argv=None):
    app = QtWidgets.QApplication(argv or sys.argv)
    app.setStyleSheet(DARK_QSS)
    win = MainWindow()
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        win._load_path(sys.argv[1], os.path.isdir(sys.argv[1]))
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
