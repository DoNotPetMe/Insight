"""Build a demonstration GameScript module.

Run directly to (re)generate ``samples/demo.gsv`` — a compiled script blob that
looks like something a game engine might ship.  Insight can disassemble and
decompile it back into readable pseudocode.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from insight.gamescript.module import GSModule
from insight.gamescript.assembler import make_function


def build_module() -> GSModule:
    mod = GSModule()

    # index 0 -- clamp(x, lo, hi): a helper called by other scripts
    def clamp(e):
        # if (x < lo) return lo
        e.load(0).load(1).lt().jz("c1")
        e.load(1).ret()
        e.label("c1")
        # if (x > hi) return hi
        e.load(0).load(2).gt().jz("c2")
        e.load(2).ret()
        e.label("c2")
        e.load(0).ret()
    make_function(mod, "clamp", nargs=3, nlocals=3, build_fn=clamp)

    # index 1 -- update_enemy(self, dt): if/else with engine calls + a CALL
    def update_enemy(e):
        # hp = getHealth(self)
        e.load(0).syscall("getHealth", 1).store(2)
        # if (hp < 20) { flee } else { chase }
        e.load(2).push_int(20).lt().jz("else")
        e.load(0).push_str("flee").syscall("playAnim", 2).pop()
        # setSpeed(self, clamp(getSpeed(self) * 2, 1, 10))
        e.load(0)
        e.load(0).syscall("getSpeed", 1).push_int(2).mul()
        e.push_int(1).push_int(10).call(0, 3)        # clamp(...)
        e.syscall("setSpeed", 2).pop()
        e.jmp("end")
        e.label("else")
        # target = findPlayer(); moveToward(self, target, dt)
        e.syscall("findPlayer", 0).store(3)
        e.load(0).load(3).load(1).syscall("moveToward", 3).pop()
        e.label("end")
        e.load(2).ret()
    make_function(mod, "update_enemy", nargs=2, nlocals=4, build_fn=update_enemy)

    # index 2 -- count_down(n): a simple while loop
    def count_down(e):
        e.label("loop")
        e.load(0).push_int(0).gt().jz("done")
        e.push_str("tick").syscall("log", 1).pop()
        e.load(0).push_int(1).sub().store(0)
        e.jmp("loop")
        e.label("done")
        e.load(0).ret()
    make_function(mod, "count_down", nargs=1, nlocals=1, build_fn=count_down)

    # index 3 -- sum_to(n): accumulating loop with two induction variables
    def sum_to(e):
        e.push_int(0).store(1)      # total = 0
        e.push_int(1).store(2)      # i = 1
        e.label("loop")
        e.load(2).load(0).le().jz("done")   # while (i <= n)
        e.load(1).load(2).add().store(1)    # total = total + i
        e.load(2).push_int(1).add().store(2)  # i = i + 1
        e.jmp("loop")
        e.label("done")
        e.load(1).ret()
    make_function(mod, "sum_to", nargs=1, nlocals=3, build_fn=sum_to)

    return mod


def main():
    mod = build_module()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.gsv")
    with open(out, "wb") as f:
        f.write(mod.to_bytes())
    print(f"wrote {out} ({len(mod.to_bytes())} bytes, "
          f"{len(mod.functions)} functions)")


if __name__ == "__main__":
    main()
