"""A small C-like AST shared by Insight's decompiler back ends.

Expression and statement nodes know how to render themselves to pseudocode.
Operator precedence is tracked so the emitter only parenthesises when needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------
class Expr:
    precedence: int = 100

    def render(self, parent_prec: int = 0) -> str:  # pragma: no cover - base
        raise NotImplementedError


def _wrap(expr: "Expr", parent_prec: int) -> str:
    text = expr.render(expr.precedence)
    if expr.precedence < parent_prec:
        return f"({text})"
    return text


@dataclass
class Literal(Expr):
    value: object
    precedence: int = 100

    def render(self, parent_prec: int = 0) -> str:
        v = self.value
        if isinstance(v, str):
            return v          # already-formatted (e.g. quoted string, "null")
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, float):
            return f"{v:g}"
        return str(v)


@dataclass
class Name(Expr):
    ident: str
    precedence: int = 100

    def render(self, parent_prec: int = 0) -> str:
        return self.ident


@dataclass
class Unary(Expr):
    opsym: str
    operand: Expr
    precedence: int = 13

    def render(self, parent_prec: int = 0) -> str:
        return f"{self.opsym}{_wrap(self.operand, self.precedence + 1)}"


@dataclass
class Binary(Expr):
    opsym: str
    left: Expr
    right: Expr
    precedence: int = 11

    def render(self, parent_prec: int = 0) -> str:
        l = _wrap(self.left, self.precedence)
        r = _wrap(self.right, self.precedence + 1)
        return f"{l} {self.opsym} {r}"


@dataclass
class Call(Expr):
    func: str
    args: list[Expr] = field(default_factory=list)
    is_host: bool = False     # host/engine API ("syscall") vs script function
    precedence: int = 90

    def render(self, parent_prec: int = 0) -> str:
        inner = ", ".join(a.render(0) for a in self.args)
        return f"{self.func}({inner})"


@dataclass
class Raw(Expr):
    """An opaque expression rendered verbatim (used for fallbacks)."""
    text: str
    precedence: int = 100

    def render(self, parent_prec: int = 0) -> str:
        return self.text


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------
class Stmt:
    def render(self, indent: int = 0) -> list[str]:  # pragma: no cover - base
        raise NotImplementedError


def _pad(indent: int) -> str:
    return "    " * indent


@dataclass
class Assign(Stmt):
    target: str
    value: Expr
    declare: bool = False      # emit a `local`/`var` keyword on first use

    def render(self, indent: int = 0) -> list[str]:
        kw = "local " if self.declare else ""
        return [f"{_pad(indent)}{kw}{self.target} = {self.value.render(0)};"]


@dataclass
class ExprStmt(Stmt):
    expr: Expr

    def render(self, indent: int = 0) -> list[str]:
        return [f"{_pad(indent)}{self.expr.render(0)};"]


@dataclass
class Return(Stmt):
    value: Expr | None = None

    def render(self, indent: int = 0) -> list[str]:
        if self.value is None:
            return [f"{_pad(indent)}return;"]
        return [f"{_pad(indent)}return {self.value.render(0)};"]


@dataclass
class If(Stmt):
    cond: Expr
    then: list[Stmt] = field(default_factory=list)
    orelse: list[Stmt] = field(default_factory=list)

    def render(self, indent: int = 0) -> list[str]:
        pad = _pad(indent)
        lines = [f"{pad}if ({self.cond.render(0)}) {{"]
        for s in self.then:
            lines += s.render(indent + 1)
        if self.orelse:
            lines.append(f"{pad}}} else {{")
            for s in self.orelse:
                lines += s.render(indent + 1)
        lines.append(f"{pad}}}")
        return lines


@dataclass
class While(Stmt):
    cond: Expr
    body: list[Stmt] = field(default_factory=list)

    def render(self, indent: int = 0) -> list[str]:
        pad = _pad(indent)
        lines = [f"{pad}while ({self.cond.render(0)}) {{"]
        for s in self.body:
            lines += s.render(indent + 1)
        lines.append(f"{pad}}}")
        return lines


@dataclass
class Break(Stmt):
    def render(self, indent: int = 0) -> list[str]:
        return [f"{_pad(indent)}break;"]


@dataclass
class Continue(Stmt):
    def render(self, indent: int = 0) -> list[str]:
        return [f"{_pad(indent)}continue;"]


@dataclass
class Goto(Stmt):
    label: str

    def render(self, indent: int = 0) -> list[str]:
        return [f"{_pad(indent)}goto {self.label};"]


@dataclass
class Label(Stmt):
    name: str

    def render(self, indent: int = 0) -> list[str]:
        # labels sit one level out for readability
        pad = _pad(max(indent - 1, 0))
        return [f"{pad}{self.name}:"]


@dataclass
class Comment(Stmt):
    text: str

    def render(self, indent: int = 0) -> list[str]:
        return [f"{_pad(indent)}// {self.text}"]


@dataclass
class Function:
    name: str
    params: list[str]
    body: list[Stmt] = field(default_factory=list)
    locals_decl: list[str] = field(default_factory=list)

    def render(self) -> str:
        header = f"function {self.name}({', '.join(self.params)}) {{"
        lines = [header]
        if self.locals_decl:
            decl = ", ".join(self.locals_decl)
            lines.append(f"{_pad(1)}local {decl};")
        for s in self.body:
            lines += s.render(1)
        lines.append("}")
        return "\n".join(lines)
