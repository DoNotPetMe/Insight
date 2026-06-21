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

    args = p.parse_args(argv)
    args.handler(args)


if __name__ == "__main__":
    main()
