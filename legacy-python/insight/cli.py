"""Insight command-line interface.

    insight info     FILE                 summarise a binary or script module
    insight list     FILE                 list discovered functions
    insight disasm   FILE [--func KEY]    show disassembly
    insight decompile FILE [--func KEY]   show recovered pseudocode
    insight strings  FILE                 dump recovered strings
    insight serve    FILE [--port N]      launch the interactive web UI
"""

from __future__ import annotations

import argparse
import sys

from .project import Project


def _load(args) -> Project:
    try:
        return Project.from_path(args.file)
    except Exception as exc:
        print(f"error: cannot load {args.file}: {exc}", file=sys.stderr)
        sys.exit(1)


def _pick_funcs(proj: Project, key):
    funcs = proj.functions()
    if key:
        funcs = [f for f in funcs if f.key == key or f.name == key]
        if not funcs:
            print(f"error: no function matching {key!r}", file=sys.stderr)
            sys.exit(1)
    return funcs


def cmd_info(args):
    proj = _load(args)
    info = proj.info()
    print(f"file     : {info['name']}")
    print(f"format   : {info['format']}")
    print(f"arch     : {info['arch']}")
    print(f"functions: {info['functions']}")
    if "entry" in info:
        print(f"entry    : {info['entry']}")
        for s in info.get("segments", []):
            flag = "x" if s["exec"] else "-"
            print(f"  segment {s['name']:<12} {s['addr']}  {s['size']:>8} bytes  [{flag}]")
    if "strings" in info:
        print(f"strings  : {info['strings']}")


def cmd_list(args):
    proj = _load(args)
    for f in proj.functions():
        print(f"{f.key:>10}  {f.name:<28} addr={f.addr:#x} size={f.size}")


def cmd_disasm(args):
    proj = _load(args)
    for f in _pick_funcs(proj, args.func):
        print(f"; ---- {f.name} ({f.key}) ----")
        for row in proj.disassembly(f.key):
            b = f" {row['bytes']}" if row["bytes"] else ""
            print(f"  {row['addr']}:{b:<22} {row['text']}")
        print()


def cmd_decompile(args):
    proj = _load(args)
    for f in _pick_funcs(proj, args.func):
        print(proj.pseudocode(f.key))
        print()


def cmd_strings(args):
    proj = _load(args)
    for s in proj.strings():
        print(f"{s['addr']:>10}  {s['value']}")


def cmd_serve(args):
    from .web.app import create_app
    app = create_app(Project.from_path(args.file))
    print(f"Insight web UI on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


# -- game-target commands ---------------------------------------------------
def cmd_detect(args):
    from .game.detect import detect_path
    from .game import engines
    from .frontends import registry
    dets = detect_path(args.file)
    if not dets:
        print("no engine detected")
        return
    for d in dets:
        eng = engines.get(d.engine_id)
        name = eng.name if eng else d.engine_id
        var = f" [{d.variant}]" if d.variant else ""
        print(f"{d.confidence*100:5.0f}%  {name}{var}")
        for ev in d.evidence:
            print(f"          · {ev}")
        fe = registry.for_engine(d.engine_id)
        if eng:
            print(f"          runtime: {eng.runtime}")
        if fe:
            print(f"          decompiler: {fe.strategy} ({fe.status}) — {fe.detail}")


def cmd_tools(args):
    from .game.detect import detect_path
    from .game import unpack
    dets = detect_path(args.file)
    if not dets:
        print("no engine detected")
        return
    eid = dets[0].engine_id
    print(f"recommended open-source tools for {eid}:")
    for t in unpack.tool_status(eid):
        mark = ""
        if t["python"]:
            mark = "  [installed]" if t["installed"] else "  [pip install]"
        print(f"  {t['name']:<28} {t['purpose']:<8} {t['url']}{mark}")


def cmd_discover(args):
    from .game.target import GameTarget
    rep = GameTarget(args.file).analyze(do_ingest=True, do_discovery=True)
    if rep.best:
        print(f"engine: {rep.best.engine_id} ({rep.best.confidence*100:.0f}%)")
    if rep.ingestion:
        print(f"ingested: {len(rep.ingestion.assets)} assets, "
              f"{len(rep.ingestion.scripts)} scripts via {rep.ingestion.handled_by or 'n/a'}")
    disc = rep.discovery
    if not disc or not disc.findings:
        print("no notable content discovered")
        return
    print(f"discoveries: {disc.summary()}")
    for f in disc.findings[:args.limit]:
        print(f"  [{f.category:<11}] {f.matched:<16} ({f.source})  {f.text[:70]}")


def cmd_procs(args):
    from .live.memscan import list_processes
    for p in list_processes():
        print(f"{p.pid:>8}  {p.name}")


def cmd_memscan(args):
    from .live.memscan import LiveSession
    if not args.authorize:
        print("error: pass --authorize to confirm you may inspect this process",
              file=sys.stderr)
        sys.exit(1)
    with LiveSession(args.pid, authorized=True) as s:
        if args.string is not None:
            hits = s.scan_string(args.string, limit=args.limit)
        elif args.int is not None:
            hits = s.scan_int(args.int, size=args.size, limit=args.limit)
        else:
            print(f"{len(s.regions())} mapped regions")
            return
        print(f"{len(hits)} hit(s):")
        for h in hits:
            print(f"  {h:#x}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="insight",
                                description="Interactive binary analysis & decompilation")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_file(sp):
        sp.add_argument("file")

    sp = sub.add_parser("info", help="summarise a file"); add_file(sp)
    sp.set_defaults(handler=cmd_info)
    sp = sub.add_parser("list", help="list functions"); add_file(sp)
    sp.set_defaults(handler=cmd_list)
    sp = sub.add_parser("disasm", help="show disassembly"); add_file(sp)
    sp.add_argument("--func", help="function key or name")
    sp.set_defaults(handler=cmd_disasm)
    sp = sub.add_parser("decompile", help="show pseudocode"); add_file(sp)
    sp.add_argument("--func", help="function key or name")
    sp.set_defaults(handler=cmd_decompile)
    sp = sub.add_parser("strings", help="dump strings"); add_file(sp)
    sp.set_defaults(handler=cmd_strings)
    sp = sub.add_parser("serve", help="launch web UI"); add_file(sp)
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8000)
    sp.set_defaults(handler=cmd_serve)

    sp = sub.add_parser("detect", help="identify the game engine"); add_file(sp)
    sp.set_defaults(handler=cmd_detect)
    sp = sub.add_parser("tools", help="recommended open-source tools"); add_file(sp)
    sp.set_defaults(handler=cmd_tools)
    sp = sub.add_parser("discover", help="find dev rooms / test maps / unused content")
    add_file(sp)
    sp.add_argument("--limit", type=int, default=40)
    sp.set_defaults(handler=cmd_discover)
    sp = sub.add_parser("procs", help="list running processes")
    sp.set_defaults(handler=cmd_procs)
    sp = sub.add_parser("memscan", help="scan a live process's memory")
    sp.add_argument("pid", type=int)
    sp.add_argument("--string", help="scan for a string value")
    sp.add_argument("--int", type=int, help="scan for an integer value")
    sp.add_argument("--size", type=int, default=4, choices=[1, 2, 4, 8])
    sp.add_argument("--limit", type=int, default=100)
    sp.add_argument("--authorize", action="store_true",
                    help="confirm you are permitted to inspect this process")
    sp.set_defaults(handler=cmd_memscan)

    args = p.parse_args(argv)
    args.handler(args)


if __name__ == "__main__":
    main()
